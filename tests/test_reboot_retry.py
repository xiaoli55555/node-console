"""No real reboots: exercise the authenticated agent/command/rotation lifecycle."""
import time
import unittest
import test_failover as fixture
import server


class RebootRetry(unittest.TestCase):
    def setUp(self):
        self.f=fixture.PrimaryFailover(methodName='runTest');self.f.setUp();self.addCleanup(self.f.tearDown)
        f=self.f
        response=f.save(failover_server_id=None,failover_binding_ids=[]);self.assertEqual(response.status_code,200,response.json)
        with server.connect() as db:
            db.execute("UPDATE detection_plans SET response_mode='reboot',action_connection_id=NULL WHERE server_id=?",(f.sid('B'),))
            db.execute("UPDATE vps_rotations SET active_server_id=?,phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_started=?,drain_grace_s=120,low_samples=0,emergency=0 WHERE id=?",(f.sid('A'),f.sid('B'),f.clock[0]-121,f.rid))
    def start(self):
        f=self.f
        f.advance(15,('A','B'));f.tick();f.advance(15,('A','B'));f.tick()
        self.assertEqual(f.row()['phase'],'waiting_ip')
        return f.row()['reboot_command_id']
    def report_B(self,uptime=1000):
        f=self.f
        return f.admin.post('/api/agent/report',json={'public_ips':[f.ips[f.sid('B')]],'egress_ips':[f.ips[f.sid('B')]],'egress_checked':f.clock[0],'uptime':uptime,'tcp':25,'connections_sampled':f.clock[0],'capabilities':['reboot']},headers={'Authorization':'Bearer '+f.nodes['B']['token']})
    def finish(self,cid,new_ip=None):
        f=self.f
        command=self.report_B().json['command'];self.assertEqual(command,{'id':cid,'action':'reboot'})
        ack=f.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers={'Authorization':'Bearer '+f.nodes['B']['token']});self.assertEqual(ack.status_code,200)
        f.clock[0]+=70;f.refresh('A')
        if new_ip:f.ips[f.sid('B')]=new_ip
        response=self.report_B(uptime=10);self.assertEqual(response.status_code,200,response.json)
        with server.connect() as db:self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(cid,)).fetchone()[0],'completed')
        f.refresh('B')
    def test_reboots_again_after_same_IP_then_stops_after_changed_IP_and_resumes_B(self):
        f=self.f;cid=self.start();ids=[cid]
        for attempt in (1,2):
            self.assertEqual(f.row()['action_attempts'],attempt)
            self.finish(cid);f.tick()
            self.assertEqual(f.row()['phase'],'draining');self.assertIn('继续重启',f.row()['status'])
            f.advance(15,('A','B'));f.tick()
            with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],attempt)
            f.advance(15,('A','B'));f.tick();cid=f.row()['reboot_command_id'];ids.append(cid)
            self.assertEqual(f.row()['phase'],'waiting_ip')
        self.finish(cid,new_ip='8.8.4.4');f.tick()
        self.assertEqual(f.row()['phase'],'waiting_probe')
        f.advance(15,('A','B'));f.tick()
        self.assertEqual(f.row()['phase'],'active');self.assertEqual(f.row()['active_server_id'],f.sid('B'))
        self.assertEqual(f.value('mobile'),'8.8.4.4');self.assertEqual(f.row()['next_switch_at'],f.clock[0]+7200)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],3)
            self.assertFalse(db.execute('SELECT 1 FROM commands WHERE server_id=?',(f.sid('A'),)).fetchone())
        self.assertEqual(len(set(ids)),3);f.change.assert_not_called()
    def test_pending_or_unknown_command_does_not_overlap_reboots(self):
        f=self.f
        for status in ('queued','issued','accepted','unconfirmed'):
            with self.subTest(status=status),server.connect() as db:
                db.execute('DELETE FROM commands')
                uid=f.admin.get('/api/me').json['id']
                cid=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot',?,?,?)",(f.sid('B'),uid,status,f.clock[0]-70,f.clock[0]-70)).lastrowid
                db.execute("UPDATE vps_rotations SET phase='waiting_ip',reboot_command_id=?,action_started=? WHERE id=?",(cid,f.clock[0]-70,f.rid))
            f.tick()
            self.assertEqual(f.row()['phase'],'waiting_ip')
            with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],1)
    def test_normal_retry_respects_new_TCP_samples_and_still_healthy_A(self):
        f=self.f;cid=self.start();self.finish(cid);f.tick()
        for _ in range(2):
            f.advance(15,('A','B'))
            with server.connect() as db:
                import json
                metrics=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('B'),)).fetchone()[0]);metrics['tcp']=80
                db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(metrics),f.sid('B')))
            f.tick()
        self.assertEqual(f.row()['phase'],'draining');self.assertEqual(f.row()['low_samples'],0)
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],1)
    def test_recovered_fixed_A_is_verified_instead_of_rebooted_again(self):
        f=self.f
        with server.connect() as db:
            db.execute("UPDATE detection_plans SET response_mode='reboot',action_connection_id=NULL WHERE server_id=?",(f.sid('A'),))
            uid=f.admin.get('/api/me').json['id']
            cid=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot','completed',?,?)",(f.sid('A'),uid,f.clock[0]-70,f.clock[0]-10)).lastrowid
            db.execute("UPDATE vps_rotations SET active_server_id=?,drain_server_id=?,phase='waiting_ip',old_ip='8.8.8.8',reboot_command_id=?,action_started=? WHERE id=?",(f.sid('B'),f.sid('A'),cid,f.clock[0]-70,f.rid))
            db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1' WHERE id=?",(f.bindings['mobile'],))
        f.records[f.bindings['mobile']]['Value']='1.1.1.1';f.tick()
        self.assertEqual(f.row()['phase'],'waiting_probe');self.assertIn('不继续重启主机',f.row()['status'])
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],1)
    def test_legacy_completed_command_is_adopted_after_upgrade(self):
        f=self.f;cid=self.start();self.finish(cid)
        with server.connect() as db:db.execute('UPDATE vps_rotations SET reboot_command_id=NULL WHERE id=?',(f.rid,))
        f.tick();self.assertEqual(f.row()['phase'],'draining')
