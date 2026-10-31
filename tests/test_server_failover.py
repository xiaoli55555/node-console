"""Exercise per-server protection against real SQLite and authenticated routes."""
import unittest
from unittest.mock import patch
import test_failover as fixture
import server
import server_failover as sf
import failover
import detectors
import rotation
from ip_dns import IntegrationError


class ServerFailover(unittest.TestCase):
    post=fixture.PrimaryFailover.post
    row=fixture.PrimaryFailover.row
    save=fixture.PrimaryFailover.save
    sid=fixture.PrimaryFailover.sid
    refresh=fixture.PrimaryFailover.refresh
    advance=fixture.PrimaryFailover.advance
    down=fixture.PrimaryFailover.down
    value=fixture.PrimaryFailover.value

    def setUp(self):
        fixture.PrimaryFailover.setUp(self)
        with server.connect() as db:
            failover.stop_probe(db,self.rid,remove=True)
            db.execute('DELETE FROM vps_rotations')
        self.extra=[patch('server_failover.load_connection',return_value={'kind':'alidns'}),patch('server_failover.get_dns_record',side_effect=lambda c,b:dict(self.records[b['id']])),patch('server_failover.update_dns_record',side_effect=lambda c,b,r,ip:self.records[b['id']].update(Value=ip))]
        for p in self.extra:p.start()
        result=self.config()
        self.assertEqual(result.status_code,200,result.json)

    def tearDown(self):
        with server.connect() as db:
            db.execute('DELETE FROM server_failover_leases')
            db.execute('DELETE FROM server_failovers')
        for p in reversed(self.extra):p.stop()
        fixture.PrimaryFailover.tearDown(self)

    def config(self,**changes):
        return self.admin.put(f'/api/servers/{self.sid("A")}/failover',json=dict({'backup_id':self.sid('C'),'recovery_s':30,'offline_s':30},**changes),headers={'X-CSRF-Token':self.tokens['admin']})

    def state(self):
        with server.connect() as db:return dict(db.execute('SELECT * FROM server_failovers WHERE server_id=?',(self.sid('A'),)).fetchone())

    def tick(self,verify=True):
        sf.tick(server.connect,server.CIPHER)
        if verify and self.state()['active']:
            self.refresh('C')
            sf.tick(server.connect,server.CIPHER)

    def request(self):
        with server.connect() as db:return sf.before_action(db,self.sid('A'),self.clock[0],server.CIPHER)

    def test_idle_standby_never_probes_and_does_not_change_DNS(self):
        self.tick()
        with server.connect() as db:
            self.assertTrue(failover.probe_blocked(db,self.sid('C')))
            self.assertFalse(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0])
        self.assertFalse(self.state()['active'])
        self.assertEqual(self.value('mobile'),'8.8.8.8')

    def test_offline_takes_all_records_only_after_inherited_probe(self):
        self.clock[0]+=31;self.refresh('B');self.refresh('C')
        sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('telecom'),'8.8.8.8')
        self.refresh('C');sf.tick(server.connect,server.CIPHER)
        for line in self.bindings:self.assertEqual(self.value(line),'9.9.9.9')
        with server.connect() as db:
            self.assertEqual(failover.budget_primary(db,self.sid('C')),self.sid('A'))
            self.assertTrue(failover.guarded(db,self.bindings['mobile']))
        self.change.assert_not_called()

    def test_reboot_waits_for_takeover_then_new_IP_restores_after_stability(self):
        with server.connect() as db:
            message=detectors.queue_reboot(db,self.sid('A'),self.clock[0])
            self.assertIn('等待',message)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
        self.tick()
        with server.connect() as db:
            self.assertTrue(detectors.queue_reboot(db,self.sid('A'),self.clock[0]).startswith('已排队'))
            db.execute("UPDATE commands SET status='completed'")
        self.refresh('A','8.8.4.4');sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('mobile'),'9.9.9.9')
        self.advance(15,('A','C'));sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('mobile'),'9.9.9.9')
        self.advance(15,('A','C'));sf.tick(server.connect,server.CIPHER)
        for line in self.bindings:self.assertEqual(self.value(line),'8.8.4.4')
        self.assertFalse(self.state()['active'])
        with server.connect() as db:self.assertTrue(failover.probe_blocked(db,self.sid('C')))

    def test_bad_or_unknown_standby_blocks_actions_and_DNS(self):
        self.request();self.health[self.sid('C')]=False;self.tick()
        self.assertIn('不可接替',self.request())
        self.assertEqual(self.value('mobile'),'8.8.8.8')
        with server.connect() as db:
            db.execute("UPDATE detection_runs SET details='[]' WHERE server_id=?",(self.sid('C'),))
            self.assertIsNotNone(sf.before_action(db,self.sid('A'),self.clock[0],server.CIPHER))
            self.assertFalse(db.execute('SELECT 1 FROM commands').fetchone())

    def test_live_takeover_cannot_be_removed_and_backup_cannot_be_shared(self):
        self.request();self.tick()
        self.assertEqual(self.config(backup_id=None).status_code,409)
        response=self.admin.put(f'/api/servers/{self.sid("B")}/failover',json={'backup_id':self.sid('C')},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(response.status_code,409)
        self.assertEqual(self.admin.delete(f'/api/servers/{self.sid("C")}',headers={'X-CSRF-Token':self.tokens['admin']}).status_code,409)

    def test_DNS_write_uncertainty_is_reconciled_without_duplicate_write(self):
        self.request();sf.tick(server.connect,server.CIPHER);self.refresh('C')
        original=sf.update_dns_record
        def uncertain(c,b,r,ip):
            original(c,b,r,ip)
            raise IntegrationError('provider read timed out')
        with patch('server_failover.update_dns_record',side_effect=uncertain) as writer:
            sf.tick(server.connect,server.CIPHER)
            self.assertEqual(writer.call_count,1)
        with server.connect() as db:self.assertTrue(db.execute('SELECT 1 FROM server_failover_leases WHERE target_ip IS NOT NULL').fetchone())
        sf.tick(server.connect,server.CIPHER)
        for line in self.bindings:self.assertEqual(self.value(line),'9.9.9.9')
        with server.connect() as db:self.assertFalse(db.execute('SELECT 1 FROM server_failover_leases WHERE target_ip IS NOT NULL').fetchone())

    def test_external_DNS_edit_is_not_overwritten(self):
        self.request();self.records[self.bindings['telecom']]['Value']='4.2.2.2';self.tick()
        self.assertEqual(self.value('telecom'),'4.2.2.2')
        self.assertIsNotNone(self.request())

    def test_unhealthy_primary_after_IP_change_keeps_backup(self):
        self.request();self.tick();self.health[self.sid('A')]=False;self.refresh('A','8.8.4.4')
        sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('mobile'),'9.9.9.9')
        self.assertIsNone(self.state()['healthy_since'])

    def test_rotation_record_is_left_to_AB_but_extra_records_are_protected(self):
        with server.connect() as db:
            # A rotation can coexist with per-server protection; its selected
            # record must never be leased or written by this engine.
            bid=self.bindings['mobile']
            db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,next_switch_at,updated) VALUES(?,?,?,?,?,?,?)",(self.admin_id if hasattr(self,'admin_id') else db.execute("SELECT id FROM users WHERE role='admin'").fetchone()[0],self.sid('A'),self.sid('B'),bid,self.sid('B'),self.clock[0]+100,self.clock[0]))
            db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1' WHERE id=?",(bid,))
            self.records[bid]['Value']='1.1.1.1'
        self.request();self.tick()
        self.assertEqual(self.value('mobile'),'1.1.1.1')
        for line in ('telecom','unicom'):self.assertEqual(self.value(line),'9.9.9.9')
        with server.connect() as db:self.assertFalse(db.execute('SELECT 1 FROM server_failover_leases WHERE binding_id=?',(self.bindings['mobile'],)).fetchone())

    def test_API_job_waits_for_takeover_and_finishes_after_DNS_restore(self):
        with server.connect() as db:
            p=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(self.sid('A'),)).fetchone()
            rid=db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details,scheduled,action_status) VALUES(?,?,?,443,?,'completed',?,?,'[]',1,'queued')",(self.sid('A'),p['source_id'],'8.8.8.8',p['nodes'],self.clock[0],self.clock[0])).lastrowid
        with patch('detectors.invoke_change_ip_api',return_value='accepted') as action,patch('detectors.load_connection',return_value={'kind':'change_ip','secret':'test'}):
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            action.assert_not_called()
            self.tick()
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            self.assertEqual(action.call_count,1)
            self.assertEqual(self.value('mobile'),'9.9.9.9')
            self.refresh('A','8.8.4.4')
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            sf.tick(server.connect,server.CIPHER)
            self.advance(30,('A','C'));sf.tick(server.connect,server.CIPHER)
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            self.assertEqual(action.call_count,1)
        with server.connect() as db:self.assertEqual(db.execute('SELECT action_status FROM detection_runs WHERE id=?',(rid,)).fetchone()[0],'completed')

    def test_backup_IP_change_blocks_admission_until_DNS_is_updated(self):
        self.request();self.tick();self.refresh('C','9.9.9.10')
        self.assertIsNotNone(self.request())
        # Even with valid fresh probes, leases pointing to the former address
        # do not authorize a destructive primary action.
        self.assertEqual(self.value('mobile'),'9.9.9.9')

    def test_customer_cannot_configure_another_customers_server(self):
        response=self.alice.put(f'/api/servers/{self.sid("A")}/failover',json={'backup_id':self.sid('C')},headers={'X-CSRF-Token':self.tokens['alice']})
        self.assertEqual(response.status_code,404)

    def test_cannot_turn_a_reserved_backup_into_a_rotation_member(self):
        with server.connect() as db:self.assertTrue(failover.reserved(db,self.sid('C')))
        response=self.save(failover_server_id=None,other_server_id=self.sid('C'))
        self.assertEqual(response.status_code,409)

    def test_serving_backup_keeps_its_own_plan_and_delays_its_normal_IP_change(self):
        # B is an automatic changer, so it can be a warm standby without having
        # its own selected nodes/source or automatic actions overwritten.
        self.assertEqual(self.config(backup_id=self.sid('B')).status_code,200)
        with server.connect() as db:
            original=dict(db.execute('SELECT * FROM detection_plans WHERE server_id=?',(self.sid('B'),)).fetchone())
            self.assertFalse(failover.reserved(db,self.sid('B')))
        self.request();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('mobile'),'1.1.1.1')
        with server.connect() as db:
            current=dict(db.execute('SELECT * FROM detection_plans WHERE server_id=?',(self.sid('B'),)).fetchone())
            self.assertEqual(current,original)
            self.assertIn('正接替',sf.before_action(db,self.sid('B'),self.clock[0],server.CIPHER))
        self.assertFalse(self.state()['cold'])

    def test_fault_on_serving_backup_does_not_publish_it(self):
        self.assertEqual(self.config(backup_id=self.sid('B')).status_code,200)
        self.health[self.sid('B')]=False;self.refresh('B')
        self.request();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('mobile'),'8.8.8.8')
        self.assertIsNotNone(self.request())

    def test_B_can_use_serving_A_while_existing_A_has_cold_C(self):
        # Return to the original A/B/C topology and add B -> A protection.
        self.assertEqual(self.config(backup_id=None).status_code,200)
        self.assertEqual(self.save().status_code,200)
        response=self.admin.put(f'/api/servers/{self.sid("B")}/failover',json={'backup_id':self.sid('A')},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(response.status_code,200,response.json)
        with server.connect() as db:
            self.assertFalse(db.execute('SELECT cold FROM server_failovers WHERE server_id=?',(self.sid('B'),)).fetchone()[0])
            self.assertTrue(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('A'),)).fetchone()[0])
        self.assertEqual(self.save(enabled=False).status_code,200)

    def test_existing_A_C_also_protects_other_records_before_A_API_repair(self):
        self.assertEqual(self.config(backup_id=None).status_code,200)
        saved=self.save();self.assertEqual(saved.status_code,200,saved.json)
        self.rid=saved.json['rotation']['id']
        self.health[self.sid('A')]=False
        self.refresh('A');self.clock[0]+=1;self.refresh('A')
        with patch('rotation.load_connection',side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}):
            fixture.PrimaryFailover.tick(self)
            self.change.assert_not_called()
            fixture.PrimaryFailover.tick(self)
        self.assertEqual(self.value('mobile'),'1.1.1.1')
        for line in ('telecom','unicom'):self.assertEqual(self.value(line),'9.9.9.9')
        self.assertEqual(self.change.call_count,1,self.row())

    def test_generated_HKT_API_cannot_bypass_pre_change_takeover(self):
        import json
        import hkt_dhcp
        with server.connect() as db:
            node=db.execute('SELECT metrics FROM servers WHERE id=?',(self.sid('A'),)).fetchone()
            metrics=json.loads(node['metrics']);metrics['capabilities'].append('hkt_dhcp')
            db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(metrics),self.sid('A')))
        result=self.post(f'/api/admin/servers/{self.sid("A")}/hkt-dhcp/api')
        self.assertEqual(result.status_code,200,result.json)
        with self.assertRaisesRegex(IntegrationError,'等待'):hkt_dhcp.queue(self.sid('A'))
        with server.connect() as db:self.assertFalse(db.execute('SELECT 1 FROM commands').fetchone())
        self.tick()
        job=hkt_dhcp.queue(self.sid('A'))
        with server.connect() as db:self.assertEqual(db.execute('SELECT action FROM commands WHERE id=?',(job,)).fetchone()[0],'hkt_dhcp')
        self.assertEqual(self.value('mobile'),'9.9.9.9')

    def test_pausing_unsent_action_allows_same_IP_to_restore(self):
        self.request();self.tick()
        with server.connect() as db:db.execute('UPDATE detection_plans SET action_enabled=0 WHERE server_id=?',(self.sid('A'),))
        sf.tick(server.connect,server.CIPHER)
        self.advance(30,('A','C'));sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('mobile'),'8.8.8.8')
        self.assertIsNone(self.state()['requested_at'])
