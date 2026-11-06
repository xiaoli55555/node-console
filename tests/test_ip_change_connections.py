"""A fresh low connection count is mandatory even for emergency actions."""
import json
import unittest
import test_rotation_emergency as fixture
import server
import rotation
from server_failover import before_action


class ConnectionGate(unittest.TestCase):
    def setUp(self):
        fixture.OriginalEmergencyProbe.setUp(self)
        self.f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}

    def sample(self,count,age=0):
        f=self.f
        with server.connect() as db:
            node=db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('A'),)).fetchone()
            metrics=json.loads(node['metrics']);metrics.update(tcp=count,connections_sampled=f.clock[0]-age)
            db.execute('UPDATE servers SET metrics=?,seen=? WHERE id=?',(json.dumps(metrics),f.clock[0],f.sid('A')))
            db.execute('UPDATE vps_rotations SET connection_threshold=80,emergency=1 WHERE id=?',(f.rid,))

    def test_strict_limit_and_invalid_samples(self):
        for count,age,blocked in [(79,0,False),(80,0,True),(81,0,True),(0,46,True),(None,0,True),(-1,0,True),(False,0,True)]:
            with self.subTest(count=count,age=age):
                self.sample(count,age)
                with server.connect() as db:
                    reason=rotation.ip_change_connection_guard(db,self.f.sid('A'),self.f.clock[0])
                    self.assertEqual(bool(reason),blocked)

    def test_emergency_and_retry_use_common_action_guard(self):
        self.sample(80)
        with server.connect() as db:
            self.assertIn('必须低于',before_action(db,self.f.sid('A'),self.f.clock[0],server.CIPHER))
            db.execute("UPDATE vps_rotations SET phase='waiting_ip' WHERE id=?",(self.f.rid,))
            self.assertIn('必须低于',before_action(db,self.f.sid('A'),self.f.clock[0],server.CIPHER))

    def test_queued_command_waits_for_current_low_report(self):
        f=self.f
        with server.connect() as db:
            uid=db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()[0]
            cid=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot','queued',?,?)",(f.sid('A'),uid,f.clock[0],f.clock[0])).lastrowid
        def report(count):
            return f.admin.post('/api/agent/report',json={'public_ips':['8.8.8.8'],'tcp':count,'connections_sampled':f.clock[0],'capabilities':['reboot']},headers={'Authorization':'Bearer '+f.nodes['A']['token']})
        self.assertIsNone(report(80).json['command'])
        with server.connect() as db:self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(cid,)).fetchone()[0],'queued')
        self.assertEqual(report(79).json['command']['id'],cid)

    def test_force_threshold_cannot_bypass_normal_limit(self):
        self.sample(90)
        with server.connect() as db:
            db.execute('UPDATE vps_rotations SET force_drain_threshold=100 WHERE id=?',(self.f.rid,))
            self.assertIn('阈值 80',rotation.ip_change_connection_guard(db,self.f.sid('A'),self.f.clock[0]))

    def start_repair_below_limit(self):
        f=self.f
        f.health[f.sid('A')]=False;f.refresh('A');f.tick()
        f.advance(2,online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1')
        f.advance(2,online=('A','B'));f.offline_probe()
        self.sample(80);f.tick()
        f.change.assert_not_called()
        self.assertIn('必须低于',f.row()['status'])
        self.sample(79);f.tick()
        self.assertEqual(f.change.call_count,1)

    def test_emergency_repair_waits_then_executes_below_limit(self):
        self.start_repair_below_limit()

    def test_provider_no_ip_change_retry_checks_connections_again(self):
        self.start_repair_below_limit()
        f=self.f
        f.advance(61,online=('B',))
        self.sample(80);f.tick()
        self.assertEqual(f.change.call_count,1)
        self.assertIn('必须低于',f.row()['status'])
        self.sample(79);f.tick()
        self.assertEqual(f.change.call_count,2)
        self.assertEqual(f.change.call_args.args[1],f.sid('A'))
