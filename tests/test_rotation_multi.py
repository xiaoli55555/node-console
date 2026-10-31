"""Multi-record plans and independent fixed plans on a shared primary."""
import unittest
from unittest.mock import patch
import test_failover as fixture
import server
import rotation
import rotation_groups
from ip_dns import IntegrationError


class MultiPlan(unittest.TestCase):
    post=fixture.PrimaryFailover.post
    sid=fixture.PrimaryFailover.sid
    refresh=fixture.PrimaryFailover.refresh
    advance=fixture.PrimaryFailover.advance
    down=fixture.PrimaryFailover.down
    save=fixture.PrimaryFailover.save
    row=fixture.PrimaryFailover.row
    value=fixture.PrimaryFailover.value

    def setUp(self):
        fixture.PrimaryFailover.setUp(self)
        self.assertEqual(self.save(failover_server_id=None).status_code,200)
        with server.connect() as db:
            action=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('C action','change_ip','{}',?)",(server.CIPHER.encrypt(b'action').decode(),)).lastrowid
            db.execute("UPDATE detection_plans SET response_mode='change_api',action_connection_id=?,automatic=1 WHERE server_id=?",(action,self.sid('C')))
        self.refresh('C')
        self.kind_patch=patch('rotation.load_connection',side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]})
        self.kind_patch.start()

    def tearDown(self):
        self.kind_patch.stop()
        fixture.PrimaryFailover.tearDown(self)

    def put(self,other=None,bindings=None,**extra):
        d=dict(self.payload,failover_server_id=None,other_server_id=other or self.sid('B'))
        if bindings:d.update(binding_ids=bindings,binding_id=bindings[0])
        d.update(extra)
        return self.admin.put(f'/api/admin/servers/{self.sid("A")}/rotation',json=d,headers={'X-CSRF-Token':self.tokens['admin']})

    def second(self):
        result=self.put(self.sid('C'),[self.bindings['telecom']])
        self.assertEqual(result.status_code,200,result.json)
        return result.json['rotation']['id']

    def drop_first(self):
        result=self.put(enabled=False,rotation_id=self.rid)
        self.assertEqual(result.status_code,200,result.json)
        result=self.admin.delete(f'/api/admin/servers/{self.sid("A")}/rotation?rotation_id={self.rid}',headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(result.status_code,200,result.json)

    def multi(self):
        self.drop_first()
        result=self.put(bindings=[self.bindings['mobile'],self.bindings['telecom']])
        self.assertEqual(result.status_code,200,result.json)
        self.rid=result.json['rotation']['id']
        return result.json['rotation']

    def tick(self):rotation.tick(server.connect,server.CIPHER)

    def test_fixed_primary_can_be_shared_by_two_independent_plans(self):
        second=self.second()
        result=self.admin.get('/api/admin/rotations').json
        self.assertEqual(len(result['rotations']),2)
        self.assertEqual({r['id'] for r in result['rotations']},{self.rid,second})
        self.assertEqual({r['primary_server_id'] for r in result['rotations']},{self.sid('A')})
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(self.clock[0],second))
        self.tick()
        self.assertEqual(self.value('telecom'),'9.9.9.9')
        self.assertEqual(self.value('mobile'),'8.8.8.8')
        self.change.assert_not_called()

    def test_alternating_plan_cannot_share_primary_with_fixed_plan(self):
        result=self.put(self.sid('C'),[self.bindings['telecom']],mode='alternating')
        self.assertEqual(result.status_code,409,result.json)
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_rotations').fetchone()[0],1)

    def test_multiselect_is_one_visible_plan_and_moves_every_record(self):
        r=self.multi();self.assertEqual(len(r['binding_ids']),2)
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=?',(self.clock[0],))
        self.tick()
        self.assertEqual(self.value('mobile'),'1.1.1.1');self.assertEqual(self.value('telecom'),'1.1.1.1')
        self.assertEqual(self.value('unicom'),'8.8.8.8')
        result=self.admin.get('/api/admin/rotations').json
        self.assertEqual(len(result['rotations']),1);self.assertEqual(len(result['rotations'][0]['member_ids']),2)
        self.change.assert_not_called()

    def test_record_group_changes_B_IP_once_after_all_routes_drain(self):
        self.multi()
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=?',(self.clock[0],))
        self.tick()
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=?',(self.clock[0],))
        self.tick()
        with server.connect() as db:db.execute('UPDATE vps_rotations SET drain_grace_s=0')
        self.advance(15,('A','B','C'));self.tick()
        self.advance(15,('A','B','C'));self.tick();self.tick()
        self.assertEqual(self.change.call_count,1)
        self.refresh('B','1.0.0.1');self.tick();self.tick()
        self.assertEqual(self.value('mobile'),'1.0.0.1');self.assertEqual(self.value('telecom'),'1.0.0.1')
        self.assertEqual(self.change.call_count,1)
        self.assertEqual(self.ips[self.sid('A')],'8.8.8.8')

    def test_bad_second_record_rolls_back_entire_group_creation(self):
        self.drop_first();self.records[self.bindings['telecom']]['Value']='4.2.2.2'
        with server.connect() as db:db.execute('UPDATE dns_bindings SET automatic=1 WHERE id=?',(self.bindings['mobile'],))
        result=self.put(bindings=[self.bindings['mobile'],self.bindings['telecom']])
        self.assertEqual(result.status_code,409,result.json)
        with server.connect() as db:
            self.assertFalse(db.execute('SELECT 1 FROM vps_rotations').fetchone())
            self.assertTrue(db.execute('SELECT automatic FROM dns_bindings WHERE id=?',(self.bindings['mobile'],)).fetchone()[0])
        self.change.assert_not_called()

    def test_group_pause_and_delete_does_not_stop_other_plan_or_A_actions(self):
        second=self.second()
        with server.connect() as db:
            db.execute('UPDATE detection_plans SET action_enabled=1 WHERE server_id=?',(self.sid('A'),))
            uid=db.execute("SELECT id FROM users WHERE role='admin'").fetchone()[0]
            cid=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot','queued',?,?)",(self.sid('A'),uid,self.clock[0],self.clock[0])).lastrowid
        self.drop_first()
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(cid,)).fetchone()[0],'queued')
            self.assertTrue(db.execute('SELECT action_enabled FROM detection_plans WHERE server_id=?',(self.sid('A'),)).fetchone()[0])
            self.assertTrue(db.execute('SELECT enabled FROM vps_rotations WHERE id=?',(second,)).fetchone()[0])

    def test_ambiguous_delete_requires_plan_id(self):
        self.second()
        result=self.admin.delete(f'/api/admin/servers/{self.sid("A")}/rotation',headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(result.status_code,409)
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_rotations').fetchone()[0],2)

    def test_shared_primary_fault_results_in_one_A_IP_action(self):
        self.second();self.health[self.sid('A')]=False
        self.refresh('A');self.clock[0]+=1;self.refresh('A')
        self.tick();self.tick()
        self.assertEqual(self.value('mobile'),'1.1.1.1');self.assertEqual(self.value('telecom'),'9.9.9.9')
        self.assertEqual(self.change.call_count,1)
        self.assertEqual(self.change.call_args.args[1],self.sid('A'))
        self.health[self.sid('A')]=True;self.refresh('A','8.8.4.4');self.tick();self.tick()
        self.assertEqual(self.change.call_count,1)

    def test_one_record_TTL_cannot_be_ignored_by_group_action(self):
        r=self.multi()
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET active_server_id=?,phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_started=?,drain_grace_s=0,low_samples=2",(self.sid('A'),self.sid('B'),self.clock[0]))
            db.execute('UPDATE vps_rotations SET drain_grace_s=120 WHERE id<>?',(r['id'],))
            root=db.execute('SELECT * FROM vps_rotations WHERE id=?',(r['id'],)).fetchone()
            with self.assertRaisesRegex(IntegrationError,'TTL'):rotation_groups.action_guard(db,root,self.sid('B'),self.clock[0]+30)
            rotation_groups.action_guard(db,root,self.sid('B'),self.clock[0]+121)

    def test_bulk_picker_validates_every_record_without_DNS_writes(self):
        with server.connect() as db:cid=db.execute('SELECT connection_id FROM dns_bindings LIMIT 1').fetchone()[0]
        provider_rows=list(self.records.values())
        def get_record(conn,b):return next(r for r in provider_rows if r['RecordId']==b['record_id'])
        with patch('rotation_dns.records',return_value=(provider_rows,False)),patch('rotation_dns.dns.get_dns_record',side_effect=get_record),patch('rotation_dns.dns.update_dns_record') as writer:
            result=self.post(f'/api/admin/servers/{self.sid("A")}/rotation/dns-binding',{'connection_id':cid,'domain':'example.com','record_ids':['telecom','unicom']})
            self.assertEqual(result.status_code,200,result.json)
            self.assertEqual(len(result.json['bindings']),2)
            writer.assert_not_called()

    def test_bulk_picker_bad_record_does_not_create_partial_binding(self):
        with server.connect() as db:
            cid=db.execute('SELECT connection_id FROM dns_bindings LIMIT 1').fetchone()[0]
            count=db.execute('SELECT COUNT(*) FROM dns_bindings').fetchone()[0]
        provider_rows=[dict(self.records[self.bindings['unicom']],RecordId='new-good',RR='new-edge'),dict(self.records[self.bindings['telecom']],RecordId='new-bad',RR='bad-edge',Value='1.1.1.1')]
        with patch('rotation_dns.records',return_value=(provider_rows,False)),patch('rotation_dns.dns.get_dns_record',side_effect=lambda c,b:next(r for r in provider_rows if r['RecordId']==b['record_id'])):
            result=self.post(f'/api/admin/servers/{self.sid("A")}/rotation/dns-binding',{'connection_id':cid,'domain':'example.com','record_ids':['new-good','new-bad']})
            self.assertEqual(result.status_code,409,result.json)
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM dns_bindings').fetchone()[0],count)

    def test_C_preserves_healthy_B_records_for_all_shared_primary_plans(self):
        self.second()
        node=self.post('/api/servers',{'name':'D standby'}).json
        self.nodes['D']=node;self.ips[node['id']]='9.9.9.10';self.health[node['id']]=True
        response=self.admin.post('/api/agent/report',json={'public_ips':['9.9.9.10'],'tcp':0,'connections_sampled':self.clock[0],'capabilities':['reboot'],'uptime':1000},headers={'Authorization':'Bearer '+node['token']})
        self.assertEqual(response.status_code,200,response.json)
        selected=self.put(rotation_id=self.rid,failover_server_id=node['id'])
        self.assertEqual(selected.status_code,200,selected.json)
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=?',(self.clock[0],))
        self.tick()
        self.assertEqual(self.value('mobile'),'1.1.1.1');self.assertEqual(self.value('telecom'),'9.9.9.9')
        self.clock[0]+=31;self.refresh('B');self.refresh('C')
        self.admin.post('/api/agent/report',json={'public_ips':['9.9.9.10'],'tcp':0,'connections_sampled':self.clock[0],'capabilities':['reboot'],'uptime':1000},headers={'Authorization':'Bearer '+node['token']})
        self.tick();self.refresh('D');self.tick()
        self.assertEqual(self.value('mobile'),'1.1.1.1');self.assertEqual(self.value('telecom'),'9.9.9.9');self.assertEqual(self.value('unicom'),'9.9.9.10')
        self.assertTrue(all(r['primary_failover_active'] for r in self.admin.get('/api/admin/rotations').json['rotations']))
        self.refresh('A','8.8.4.4');self.tick()
        self.clock[0]+=30
        for name in ('A','B','C','D'):self.refresh(name)
        self.tick()
        self.assertEqual(self.value('unicom'),'8.8.4.4')
        self.assertEqual(self.value('mobile'),'1.1.1.1');self.assertEqual(self.value('telecom'),'9.9.9.9')
        self.change.assert_not_called()

    def test_late_lower_id_repair_does_not_overtake_an_inflight_A_action(self):
        second=self.second();self.health[self.sid('A')]=False
        self.refresh('A');self.clock[0]+=1;self.refresh('A')
        with server.connect() as db:
            db.execute('UPDATE vps_rotations SET active_server_id=other_server_id,next_switch_at=?',(self.clock[0]+7200,))
            db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='8.8.8.8',action_started=?,action_attempts=1 WHERE id=?",(self.sid('A'),self.clock[0],second))
            db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1' WHERE id=?",(self.bindings['mobile'],))
            db.execute("UPDATE dns_bindings SET expected_ip='9.9.9.9' WHERE id=?",(self.bindings['telecom'],))
        self.records[self.bindings['mobile']]['Value']='1.1.1.1';self.records[self.bindings['telecom']]['Value']='9.9.9.9'
        self.tick();self.tick()
        self.change.assert_not_called()
        self.assertIn('计划 #'+str(second),self.row()['status'])

    def test_new_plan_is_rejected_while_shared_A_IP_action_is_inflight(self):
        with server.connect() as db:db.execute("UPDATE vps_rotations SET active_server_id=other_server_id,phase='waiting_ip',drain_server_id=?,old_ip='8.8.8.8',action_started=? WHERE id=?",(self.sid('A'),self.clock[0],self.rid))
        response=self.put(self.sid('C'),[self.bindings['telecom']])
        self.assertEqual(response.status_code,409,response.json)
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_rotations').fetchone()[0],1)

    def test_delete_owner_transfers_inflight_shared_A_action_without_resending(self):
        second=self.second()
        with server.connect() as db:
            db.execute('UPDATE vps_rotations SET active_server_id=other_server_id')
            db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='8.8.8.8',action_started=?,action_attempts=1,emergency=1,fault_recovery=1 WHERE id=?",(self.sid('A'),self.clock[0],self.rid))
            db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1' WHERE id=?",(self.bindings['mobile'],))
            db.execute("UPDATE dns_bindings SET expected_ip='9.9.9.9' WHERE id=?",(self.bindings['telecom'],))
        self.records[self.bindings['mobile']]['Value']='1.1.1.1';self.records[self.bindings['telecom']]['Value']='9.9.9.9'
        self.drop_first()
        with server.connect() as db:
            survivor=db.execute('SELECT * FROM vps_rotations WHERE id=?',(second,)).fetchone()
            self.assertEqual(survivor['phase'],'waiting_ip');self.assertEqual(survivor['action_started'],self.clock[0]);self.assertEqual(survivor['drain_server_id'],self.sid('A'))
        self.tick();self.change.assert_not_called()

    def test_direct_DNS_admin_controls_cannot_remove_or_reassign_a_group_member(self):
        self.multi();bid=self.bindings['telecom']
        result=self.admin.delete(f'/api/ip-dns/bindings/{bid}',headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(result.status_code,409,result.json)
        with server.connect() as db:
            b=dict(db.execute('SELECT * FROM dns_bindings WHERE id=?',(bid,)).fetchone())
        result=self.post('/api/ip-dns/bindings',{'id':bid,'server_id':self.sid('A'),'connection_id':b['connection_id'],'domain':b['domain'],'record_id':b['record_id'],'rr':b['rr'],'line':b['line'],'expected_ip':b['expected_ip'],'port':443,'automatic':False})
        self.assertEqual(result.status_code,400,result.json)
        self.assertIn('轮换',result.json['error'])
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_rotations').fetchone()[0],2)
            self.assertTrue(db.execute('SELECT 1 FROM dns_bindings WHERE id=?',(bid,)).fetchone())
