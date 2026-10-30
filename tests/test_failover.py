"""Fault injection uses the real Flask API, SQLite state and DNS CAS checks."""
import json
import time
import unittest
from unittest.mock import patch, MagicMock
import test_panel as support
import server
import rotation
import failover
from ip_dns import IntegrationError


class PrimaryFailover(unittest.TestCase):
    post=support.PanelTest.post
    def setUp(self):
        support.PanelTest.setUp(self)
        self.clock=[int(time.time())];self.health={};self.nodes={};self.ips={}
        self.patches=[patch('time.time',side_effect=lambda:self.clock[0])]
        self.patches[0].start()
        for name,ip in [('A','8.8.8.8'),('B','1.1.1.1'),('C','9.9.9.9')]:
            node=self.post('/api/servers',{'name':name}).json
            self.nodes[name]=node;sid=node['id'];self.ips[sid]=ip;self.health[sid]=True
            with server.connect() as db:
                db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,443,1)',(sid,))
                source=db.execute("INSERT INTO detection_sources(name,kind,secret,enabled) VALUES(?,'boce',?,1)",('selected '+name,server.CIPHER.encrypt(b'test-source').decode())).lastrowid
                action=None
                if name!='C':action=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES(?,'change_ip','{}',?)",('action '+name,server.CIPHER.encrypt(b'test-action').decode())).lastrowid
                db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,daily_limit,next_at,response_mode,action_connection_id,failure_threshold) VALUES(?,?,?,120,1,1000,? ,?,?,2)",(sid,source,'["13"]',self.clock[0]+120,'none' if name=='C' else 'change_api',action))
            self.refresh(name)
        self.records={};self.bindings={}
        with server.connect() as db:
            cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('DNS','alidns','{}',?)",(server.CIPHER.encrypt(b'test-dns').decode(),)).lastrowid
            for line in ('mobile','telecom','unicom'):
                bid=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic,verify_new_ip) VALUES(?,?,'example.com',?,'edge',?,'8.8.8.8',443,1,1)",(self.sid('A'),cid,line,line)).lastrowid
                self.bindings[line]=bid
                self.records[bid]={'RecordId':line,'RR':'edge','Line':line,'Type':'A','Value':'8.8.8.8','TTL':60,'Status':'ENABLE'}
        def get(c,b):return dict(self.records[b['id']])
        def update(c,b,r,ip):self.records[b['id']]['Value']=ip
        self.patches += [patch('rotation.load_connection',return_value={'kind':'alidns'}),patch('rotation.get_dns_record',side_effect=get),patch('rotation.update_dns_record',side_effect=update),patch('failover.load_connection',return_value={'kind':'alidns'}),patch('failover.get_dns_record',side_effect=get),patch('failover.update_dns_record',side_effect=update),patch('rotation.boce_dns_gate',side_effect=lambda db,sid,*args,**kw:None if self.health.get(sid) else 'selected nodes unreachable'),patch('rotation.socket.create_connection',return_value=MagicMock()),patch('rotation.invoke_change_ip_api',return_value='accepted')]
        self.mocks=[p.start() for p in self.patches[1:]]
        self.change=self.mocks[-1];self.write=self.mocks[5]
        self.payload={'other_server_id':self.sid('B'),'binding_id':self.bindings['mobile'],'interval_s':7200,'takeover_s':600,'lead_s':0,'mode':'fixed_primary','mobile_only_ack':True,'enabled':True,'connection_threshold':80,'failover_server_id':self.sid('C'),'failover_binding_ids':list(self.bindings.values()),'failover_recovery_s':30}
        result=self.save();self.assertEqual(result.status_code,200,result.json)
        self.rid=result.json['rotation']['id']
    def tearDown(self):
        with server.connect() as db:
            db.execute('DELETE FROM vps_failover_leases')
            db.execute('UPDATE vps_rotations SET failover_server_id=NULL')
        for p in reversed(self.patches):p.stop()
    def sid(self,name):return self.nodes[name]['id']
    def save(self,**changes):
        return self.admin.put(f'/api/admin/servers/{self.sid("A")}/rotation',json=dict(self.payload,**changes),headers={'X-CSRF-Token':self.tokens['admin']})
    def refresh(self,name,ip=None):
        sid=self.sid(name)
        if ip:self.ips[sid]=ip
        result=self.admin.post('/api/agent/report',json={'public_ips':[self.ips[sid]],'egress_ips':[self.ips[sid]],'egress_checked':self.clock[0],'tcp':25,'tcp_by_port':{'443':25},'connections_sampled':self.clock[0],'capabilities':['reboot'],'uptime':1000,'rx_bytes':0,'tx_bytes':0},headers={'Authorization':'Bearer '+self.nodes[name]['token']})
        self.assertEqual(result.status_code,200,result.json)
        with server.connect() as db:
            source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(sid,)).fetchone()[0]
            db.execute('INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details,scheduled) VALUES(?,?,?,443,?,\'completed\',?,?,?,1)',(sid,source,self.ips[sid],'["13"]',self.clock[0],self.clock[0],json.dumps([{'node_id':'13','state':'reachable' if self.health.get(sid) else 'unreachable'}])))
    def advance(self,seconds=15,online=('B','C')):
        self.clock[0]+=seconds
        for name in online:self.refresh(name)
    def down(self,name='A'):
        with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(self.clock[0]-30,self.sid(name)))
    def tick(self):rotation.tick(server.connect,server.CIPHER)
    def row(self):
        with server.connect() as db:return dict(db.execute('SELECT * FROM vps_rotations WHERE id=?',(self.rid,)).fetchone())
    def value(self,line):return self.records[self.bindings[line]]['Value']
    def test_A_offline_C_takes_all_A_records_without_IP_actions(self):
        self.down();self.tick()
        for line in self.bindings:self.assertEqual(self.value(line),'9.9.9.9')
        self.change.assert_not_called()
        self.assertIn('全部解析',self.row()['failover_status'])
    def test_A_outage_while_mobile_on_healthy_B_does_not_steal_mobile(self):
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(self.clock[0],self.rid))
        self.tick();self.assertEqual(self.value('mobile'),'1.1.1.1')
        self.down();self.tick()
        self.assertEqual(self.value('mobile'),'1.1.1.1')
        for line in ('telecom','unicom'):self.assertEqual(self.value(line),'9.9.9.9')
    def test_B_offline_during_A_outage_C_can_also_take_mobile(self):
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(self.clock[0],self.rid))
        self.tick();self.down();self.tick();self.down('B');self.tick()
        self.assertEqual(self.value('mobile'),'9.9.9.9');self.change.assert_not_called()
    def test_C_failed_or_stale_never_receives_records(self):
        self.health[self.sid('C')]=False;self.down();self.tick()
        self.assertEqual(self.value('telecom'),'8.8.8.8');self.assertEqual(self.value('mobile'),'8.8.8.8')
        self.assertIn('不可接替',self.row()['failover_status'])
    def test_A_returns_new_IP_restore_waits_for_stability_then_uses_new_IP(self):
        self.down();self.tick()
        self.advance(15,('A','B','C'));self.refresh('A','8.8.4.4');self.tick()
        self.assertEqual(self.value('telecom'),'9.9.9.9')
        self.advance(15,('A','B','C'));self.tick();self.assertEqual(self.value('telecom'),'9.9.9.9')
        self.advance(15,('A','B','C'));self.tick()
        for line in self.bindings:self.assertEqual(self.value(line),'8.8.4.4')
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_failover_leases').fetchone()[0],0)
    def test_A_heartbeat_returns_but_selected_probes_fail_C_remains(self):
        self.down();self.tick();self.advance(15,('B','C'));self.health[self.sid('A')]=False;self.refresh('A');self.tick()
        self.assertEqual(self.value('telecom'),'9.9.9.9');self.assertIsNone(self.row()['failover_healthy_since'])
    def test_A_flapping_resets_recovery_stability_window(self):
        self.down();self.tick();self.advance(15,('A','B','C'));self.tick()
        self.assertIsNotNone(self.row()['failover_healthy_since'])
        self.down();self.tick();self.assertIsNone(self.row()['failover_healthy_since'])
        self.advance(15,('A','B','C'));self.tick();self.assertEqual(self.value('mobile'),'9.9.9.9')
    def test_C_fails_after_A_verified_restores_without_extra_stability_delay(self):
        self.down();self.tick();self.advance(15,('A','B','C'));self.health[self.sid('C')]=False;self.tick()
        self.assertEqual(self.value('telecom'),'8.8.8.8')
    def test_dns_write_applied_then_timeout_reconciles_without_duplicate(self):
        def update(c,b,r,ip):
            self.records[b['id']]['Value']=ip
            raise IntegrationError('timeout after apply')
        self.down()
        with patch('failover.update_dns_record',side_effect=update) as api:
            self.tick();self.assertEqual(api.call_count,1)
        self.tick()
        for line in self.bindings:self.assertEqual(self.value(line),'9.9.9.9')
        self.change.assert_not_called()
    def test_DNS_unknown_blocks_retries_and_records_remain_leased(self):
        self.down()
        with patch('failover.update_dns_record',side_effect=IntegrationError('timeout')) as api:
            self.tick();self.tick();self.assertEqual(api.call_count,1)
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_failover_leases WHERE intent IS NOT NULL').fetchone()[0],1)
        self.change.assert_not_called()
    def test_C_busy_with_reboot_does_not_receive_traffic(self):
        uid=self.admin.get('/api/me').json['id']
        with server.connect() as db:db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot','accepted',?,?)",(self.sid('C'),uid,self.clock[0],self.clock[0]))
        self.down();self.tick();self.assertEqual(self.value('telecom'),'8.8.8.8')
    def test_no_automatic_IP_change_on_reserved_C(self):
        import detectors
        with server.connect() as db:
            self.assertTrue(failover.reserved(db,self.sid('C')))
            p=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()
            db.execute("UPDATE detection_plans SET response_mode='reboot',action_enabled=1,failure_threshold=2 WHERE server_id=?",(self.sid('C'),))
            for _ in range(3):
                rid=db.execute('INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details,scheduled) VALUES(?,?,?,443,?,\'pending\',?,?,?,1)',(self.sid('C'),p['source_id'],'9.9.9.9',p['nodes'],self.clock[0],self.clock[0],'[]')).lastrowid
                run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
                detectors.finish(db,run,'complete',[{'node_id':'13','state':'unreachable'}])
            self.assertFalse(db.execute('SELECT 1 FROM commands WHERE server_id=?',(self.sid('C'),)).fetchone())
    def test_invalid_C_selection_and_foreign_records_reject_transactionally(self):
        for bad in (self.sid('A'),self.sid('B'),True,'3',999999):
            with self.subTest(backup=bad):self.assertNotEqual(self.save(failover_server_id=bad).status_code,200)
        self.assertEqual(self.row()['failover_server_id'],self.sid('C'))
        self.assertNotEqual(self.save(failover_binding_ids=[999999]).status_code,200)
    def test_active_failover_cannot_be_removed_reassigned_or_deleted(self):
        self.down();self.tick()
        self.assertEqual(self.save(failover_server_id=None).status_code,409)
        self.assertEqual(self.admin.delete(f'/api/servers/{self.sid("C")}',headers={'X-CSRF-Token':self.tokens['admin']}).status_code,409)
        uid=self.alice.get('/api/me').json['id']
        self.assertEqual(self.admin.patch(f'/api/servers/{self.sid("A")}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,409)
    def test_pause_allows_safe_restore_of_existing_leases(self):
        self.down();self.tick();result=self.save(enabled=False);self.assertEqual(result.status_code,200,result.json)
        self.advance(15,('A','B','C'));self.tick();self.advance(30,('A','B','C'));self.tick()
        self.assertEqual(self.value('telecom'),'8.8.8.8');self.assertEqual(self.row()['enabled'],0)
    def test_legacy_alternating_mode_also_supports_primary_failover(self):
        self.assertEqual(self.save(enabled=False).status_code,200)
        result=self.save(mode='alternating');self.assertEqual(result.status_code,200,result.json)
        self.down();self.tick();self.assertEqual(self.value('telecom'),'9.9.9.9');self.change.assert_not_called()
    def test_failover_during_A_reboot_restores_new_IP_without_state_deadlock(self):
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET active_server_id=?,phase='waiting_ip',drain_server_id=?,old_ip='8.8.8.8',action_started=? WHERE id=?",(self.sid('B'),self.sid('A'),self.clock[0],self.rid))
            db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1' WHERE id=?",(self.bindings['mobile'],))
        self.records[self.bindings['mobile']]['Value']='1.1.1.1'
        self.down();self.tick();self.assertEqual(self.value('telecom'),'9.9.9.9')
        self.advance(15,('A','B','C'));self.refresh('A','8.8.4.4');self.tick()
        self.advance(30,('A','B','C'));self.tick()
        self.assertEqual(self.value('telecom'),'8.8.4.4');self.assertEqual(self.value('mobile'),'1.1.1.1')
        self.tick();self.assertEqual(self.row()['phase'],'waiting_probe')
    def test_C_heartbeat_stale_despite_old_success_does_not_receive_traffic(self):
        self.down('C');self.down();self.tick()
        self.assertEqual(self.value('telecom'),'8.8.8.8');self.write.assert_not_called()
    def test_C_business_port_failure_blocks_transfer_even_when_nodes_pass(self):
        self.down()
        def connect(target,**kwargs):
            if target[0]=='9.9.9.9':raise OSError('business port down')
            return MagicMock()
        with patch('rotation.socket.create_connection',side_effect=connect):self.tick()
        self.assertEqual(self.value('mobile'),'8.8.8.8');self.write.assert_not_called()
    def test_B_change_inflight_survives_A_outage_and_restore(self):
        with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=? WHERE id=?",(self.sid('B'),self.clock[0],self.rid))
        self.down();self.tick();self.assertEqual(self.value('mobile'),'9.9.9.9')
        self.assertEqual(self.row()['phase'],'waiting_ip');self.change.assert_not_called()
        self.advance(15,('A','B','C'));self.tick();self.advance(30,('A','B','C'));self.tick()
        self.assertEqual(self.value('mobile'),'8.8.8.8');self.assertEqual(self.row()['phase'],'waiting_ip')
        self.assertEqual(self.row()['drain_server_id'],self.sid('B'));self.change.assert_not_called()
    def test_C_API_actions_are_cancelled_while_reserved(self):
        import detectors
        with server.connect() as db:
            action=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('C action','change_ip','{}',?)",(server.CIPHER.encrypt(b'test-action').decode(),)).lastrowid
            db.execute("UPDATE detection_plans SET response_mode='change_api',action_enabled=1,action_connection_id=? WHERE server_id=?",(action,self.sid('C')))
            source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0]
            run=db.execute('INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details,scheduled,action_status) VALUES(?,?,?,443,?,\'completed\',?,?,?,1,\'queued\')',(self.sid('C'),source,'9.9.9.9','["13"]',self.clock[0],self.clock[0],'[]')).lastrowid
        with patch('detectors.invoke_change_ip_api') as change:detectors.execute_change_ip_actions(server.connect,server.CIPHER);change.assert_not_called()
        with server.connect() as db:self.assertEqual(db.execute('SELECT action_status FROM detection_runs WHERE id=?',(run,)).fetchone()[0],'cancelled')
    def test_client_cannot_select_another_customers_failover_server(self):
        uid=self.alice.get('/api/me').json['id']
        with server.connect() as db:
            db.execute('UPDATE vps_rotations SET owner_id=? WHERE id=?',(uid,self.rid))
            for name in ('A','B'):
                sid=self.sid(name)
                db.execute('UPDATE servers SET owner_id=? WHERE id=?',(uid,sid))
                db.execute('UPDATE detection_plans SET owner_id=? WHERE server_id=?',(uid,sid))
                db.execute('UPDATE detection_sources SET owner_id=?,server_id=? WHERE id=(SELECT source_id FROM detection_plans WHERE server_id=?)',(uid,sid,sid))
                db.execute('UPDATE ip_connections SET owner_id=?,server_id=? WHERE id=(SELECT action_connection_id FROM detection_plans WHERE server_id=?)',(uid,sid,sid))
            db.execute('UPDATE ip_connections SET owner_id=?,server_id=? WHERE id IN (SELECT connection_id FROM dns_bindings WHERE server_id=?)',(uid,self.sid('A'),self.sid('A')))
        result=self.alice.put(f'/api/client/servers/{self.sid("A")}/rotation',json=self.payload,headers={'X-CSRF-Token':self.tokens['alice']})
        self.assertEqual(result.status_code,409,result.json)
        self.assertIn('不属于',result.json.get('error',''))

    def test_new_A_binding_is_also_transferred_but_unrelated_B_binding_is_not(self):
        with server.connect() as db:
            connection=db.execute('SELECT connection_id FROM dns_bindings WHERE id=?',(self.bindings['telecom'],)).fetchone()[0]
            for line,host in [('extra_A','A'),('unrelated_B','B')]:
                bid=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic) VALUES(?,?,'example.com',?,'extra',?,'8.8.8.8',443,0)",(self.sid(host),connection,line,line)).lastrowid
                self.bindings[line]=bid
                self.records[bid]={'RecordId':line,'RR':'extra','Line':line,'Type':'A','Value':'8.8.8.8','TTL':60,'Status':'ENABLE'}
        self.down();self.tick()
        self.assertEqual(self.value('extra_A'),'9.9.9.9')
        self.assertEqual(self.value('unrelated_B'),'8.8.8.8')
    def test_partial_A_record_selection_is_rejected(self):
        result=self.save(failover_binding_ids=[self.bindings['telecom']])
        self.assertEqual(result.status_code,409,result.json)
        self.assertIn('全部',result.json['error'])
    def test_brief_heartbeat_gap_under_threshold_does_not_trigger_C(self):
        with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(self.clock[0]-14,self.sid('A')))
        self.tick();self.write.assert_not_called();self.assertEqual(self.value('mobile'),'8.8.8.8')
    def test_ordinary_A_sync_is_blocked_while_C_owns_record(self):
        self.down();self.tick()
        result=self.post(f'/api/ip-dns/bindings/{self.bindings["telecom"]}/check',{'apply':True})
        self.assertNotEqual(result.status_code,200,result.json)
        self.assertEqual(self.value('telecom'),'9.9.9.9')
    def test_external_DNS_edit_is_not_overwritten(self):
        self.records[self.bindings['telecom']]['Value']='4.4.4.4'
        self.down();self.tick()
        self.assertEqual(self.value('telecom'),'4.4.4.4');self.change.assert_not_called()
    def test_A_bindings_can_use_multiple_business_ports_if_C_serves_them(self):
        with server.connect() as db:db.execute('UPDATE dns_bindings SET port=8443 WHERE id=?',(self.bindings['telecom'],))
        self.assertEqual(self.save().status_code,200)
        self.down();self.tick()
        self.assertEqual(self.value('telecom'),'9.9.9.9')

    def test_C_protects_A_even_when_B_scheduled_rotation_is_paused(self):
        result=self.save(enabled=False);self.assertEqual(result.status_code,200,result.json)
        self.down();self.tick()
        for line in self.bindings:self.assertEqual(self.value(line),'9.9.9.9')
        self.assertEqual(self.row()['enabled'],0);self.change.assert_not_called()

    def test_A_independent_API_verification_does_not_deadlock_DNS_restore(self):
        self.assertEqual(self.save(enabled=False).status_code,200)
        self.down();self.tick()
        with server.connect() as db:
            source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(self.sid('A'),)).fetchone()[0]
            db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details,scheduled,action_status,action_candidate,action_attempts,action_attempted) VALUES(?,?,?,443,?,'completed',?,?,?,1,'verifying',?,1,?)",(self.sid('A'),source,'8.8.8.8','["13"]',self.clock[0],self.clock[0],'[]','8.8.4.4',self.clock[0]))
        self.advance(15,('A','B','C'));self.refresh('A','8.8.4.4');self.tick()
        self.advance(30,('A','B','C'));self.tick()
        for line in self.bindings:self.assertEqual(self.value(line),'8.8.4.4')
        self.change.assert_not_called()
