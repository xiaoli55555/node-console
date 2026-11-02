"""A drained rotating VPS must change IP before re-entry, including fault handoff."""
import unittest
from unittest.mock import patch
import test_rotation_emergency as emergency_fixture
import rotation
import server
from ip_dns import IntegrationError

class ReentryGate(unittest.TestCase):
    setUp=emergency_fixture.OriginalEmergencyProbe.setUp
    def test_emergency_cannot_republish_draining_machine_with_old_ip(self):
        f=self.f
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip=?,drain_started=?,drain_grace_s=0,low_samples=2 WHERE id=?",(f.sid('B'),'1.1.1.1',f.clock[0],f.rid))
        for attempt in range(2):
            try:rotation._dns_switch(server.connect,server.CIPHER,f.rid,f.clock[0],emergency=True)
            except IntegrationError:pass
            f.advance(2,online=('A','B'))
        self.assertEqual(f.value('mobile'),'8.8.8.8')
        self.assertEqual(f.row()['drain_server_id'],f.sid('B'))
    def test_ip_rollback_during_recheck_does_not_complete_rotation(self):
        f=self.f
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='waiting_probe',drain_server_id=?,old_ip='1.1.1.1',new_ip='8.8.4.4',action_started=? WHERE id=?",(f.sid('B'),f.clock[0]-10,f.rid))
        f.tick();f.advance(15,online=('A','B'));f.tick()
        self.assertNotEqual(f.row()['phase'],'active')
        self.assertEqual(f.value('mobile'),'8.8.8.8')
    def test_normal_deadline_during_drain_does_not_switch(self):
        f=self.f
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='1.1.1.1',next_switch_at=? WHERE id=?",(f.sid('B'),f.clock[0]-1,f.rid))
        rotation._dns_switch(server.connect,server.CIPHER,f.rid,f.clock[0])
        self.assertEqual(f.value('mobile'),'8.8.8.8')

    def test_carrier_failure_does_not_prevent_drain_change_recheck_then_handoff(self):
        f=self.f
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        f.health[f.sid('A')]=False;f.refresh('A')
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_started=?,drain_grace_s=0,low_samples=2 WHERE id=?",(f.sid('B'),f.clock[0]-30,f.rid))
        f.tick()
        self.assertEqual(f.row()['phase'],'waiting_ip');self.assertEqual(f.change.call_count,1)
        self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.advance(15,online=('A','B'));f.refresh('B',ip='8.8.4.4');f.tick()
        self.assertEqual(f.row()['phase'],'waiting_probe');self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.advance(15,online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'8.8.4.4')
        self.assertEqual(f.row()['drain_server_id'],f.sid('A'))
    def test_same_ip_after_completed_attempt_stays_out_even_past_deadline(self):
        f=self.f
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,next_switch_at=? WHERE id=?",(f.sid('B'),f.clock[0]-70,f.clock[0]-1,f.rid))
        f.tick()
        self.assertEqual(f.row()['phase'],'draining')
        rotation._dns_switch(server.connect,server.CIPHER,f.rid,f.clock[0])
        self.assertEqual(f.value('mobile'),'8.8.8.8')

    def ready_standby(self,deadline):
        f=self.f
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='waiting_probe',drain_server_id=?,old_ip='1.1.1.1',new_ip='8.8.4.4',action_started=?,next_switch_at=? WHERE id=?",(f.sid('B'),f.clock[0]-30,deadline,f.rid))
        f.refresh('B',ip='8.8.4.4')

    def test_overdue_repair_switches_in_the_verification_pass(self):
        f=self.f;deadline=f.clock[0]-3600;self.ready_standby(deadline)
        f.tick()
        self.assertEqual(f.value('mobile'),'8.8.4.4')
        self.assertEqual(f.row()['next_switch_at'],f.clock[0]+f.row()['interval_s']-f.row()['lead_s'])

    def test_early_repair_keeps_original_future_deadline(self):
        f=self.f;deadline=f.clock[0]+3600;self.ready_standby(deadline)
        f.tick();f.tick()
        self.assertEqual(f.row()['next_switch_at'],deadline)
        self.assertEqual(f.value('mobile'),'8.8.8.8')

    def test_overdue_failed_business_port_cannot_handoff_or_reset_deadline(self):
        f=self.f;deadline=f.clock[0]-3600;self.ready_standby(deadline)
        with patch('rotation.socket.create_connection',side_effect=OSError('port down')):f.tick()
        self.assertEqual(f.row()['phase'],'waiting_probe')
        self.assertEqual(f.row()['next_switch_at'],deadline)
        self.assertEqual(f.value('mobile'),'8.8.8.8')
    def make_ip_old(self,name):
        f=self.f
        with server.connect() as db:
            latest=db.execute('SELECT MAX(id) FROM ip_events WHERE server_id=?',(f.sid(name),)).fetchone()[0]
            age=f.row()['interval_s']//2+60
            db.execute('UPDATE ip_events SET observed=? WHERE server_id=?',(f.clock[0]-age-1,f.sid(name)))
            db.execute('UPDATE ip_events SET observed=? WHERE id=?',(f.clock[0]-age,latest))

    def test_early_ready_standby_refreshes_once_five_minutes_before_handoff(self):
        f=self.f;deadline=f.clock[0]+600;self.ready_standby(deadline)
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        f.tick();self.assertEqual(f.row()['standby_ready_server'],f.sid('B'));self.make_ip_old('B')
        f.advance(299,online=('A','B'));f.tick();self.assertEqual(f.row()['phase'],'active')
        f.advance(1,online=('A','B'));f.tick()
        self.assertEqual(f.row()['phase'],'draining');self.assertEqual(f.row()['emergency'],0)
        self.assertEqual(f.row()['preload_refresh_deadline'],deadline)
        self.assertEqual(f.row()['next_switch_at'],deadline);self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.tick();self.assertEqual(f.row()['low_samples'],1);f.change.assert_not_called()
        f.advance(15,online=('A','B'));f.tick();self.assertEqual(f.row()['phase'],'waiting_ip')
        self.assertEqual(f.change.call_count,1)
        f.advance(15,online=('A','B'));f.refresh('B',ip='1.0.0.1');f.tick()
        f.advance(15,online=('A','B'));f.tick();self.assertEqual(f.row()['phase'],'active')
        f.tick();f.tick();self.assertEqual(f.change.call_count,1)
        self.assertEqual(f.value('mobile'),'8.8.8.8');self.assertEqual(f.row()['next_switch_at'],deadline)
        f.advance(deadline-f.clock[0],online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'1.0.0.1')
        self.assertIsNone(f.row()['preload_refresh_deadline'])

    def test_recently_recovered_standby_does_not_refresh_again_in_final_window(self):
        f=self.f;deadline=f.clock[0]+200;self.ready_standby(deadline)
        f.tick();f.tick();f.tick()
        self.assertEqual(f.row()['phase'],'active');f.change.assert_not_called()
        self.assertEqual(f.row()['next_switch_at'],deadline)

    def test_preload_refresh_still_waits_for_connection_threshold(self):
        import json
        f=self.f;deadline=f.clock[0]+600;self.ready_standby(deadline);f.tick();self.make_ip_old('B')
        f.advance(300,online=('A','B'));f.tick()
        with server.connect() as db:
            row=db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('B'),)).fetchone()
            metrics=json.loads(row['metrics']);metrics['tcp']=1000
            db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(metrics),f.sid('B')))
        f.tick();f.tick()
        self.assertEqual(f.row()['phase'],'draining');self.assertEqual(f.row()['low_samples'],0)
        f.change.assert_not_called();self.assertEqual(f.value('mobile'),'8.8.8.8')
    def insert_pending_probe(self,name):
        f=self.f
        with server.connect() as db:
            db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details,scheduled) SELECT server_id,source_id,ip,port,nodes,'pending',?,?,'[]',1 FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1",(f.clock[0],f.clock[0],f.sid(name)))

    def test_pending_probe_does_not_hide_confirmed_carrier_failure(self):
        f=self.f;f.health[f.sid('A')]=False;f.refresh('A');self.insert_pending_probe('A')
        f.tick();self.assertIsNotNone(f.row()['emergency_probe_after'])
        f.advance(2,online=('A','B'));self.insert_pending_probe('A');f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1')

    def test_carrier_fault_cancels_unissued_optional_refresh_then_repairs_carrier(self):
        f=self.f;deadline=f.clock[0]+600;self.ready_standby(deadline)
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        f.tick()
        # An optional refresh prepared before the young-IP policy took effect.
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='8.8.4.4',drain_started=?,drain_grace_s=0,preload_base_attempt=action_attempts,drain_base_attempt=action_attempts,preload_refresh_deadline=next_switch_at WHERE id=?",(f.sid('B'),f.clock[0],f.rid))
        self.assertEqual(f.row()['phase'],'draining');f.change.assert_not_called()
        f.health[f.sid('A')]=False;f.refresh('A');f.tick()
        self.assertEqual(f.row()['phase'],'active');f.change.assert_not_called()
        self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.advance(2,online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'8.8.4.4')
        self.assertEqual(f.row()['drain_server_id'],f.sid('A'))
        f.tick();self.assertEqual(f.change.call_count,1)
        self.assertEqual(f.row()['phase'],'waiting_ip')
        self.assertEqual(f.row()['emergency'],1)

    def test_issued_optional_refresh_finishes_before_fault_handoff(self):
        f=self.f;deadline=f.clock[0]+600;self.ready_standby(deadline)
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        f.tick();self.make_ip_old('B');f.advance(300,online=('A','B'));f.tick();f.tick()
        f.advance(15,online=('A','B'));f.tick()
        self.assertEqual(f.row()['phase'],'waiting_ip');self.assertEqual(f.change.call_count,1)
        f.health[f.sid('A')]=False;f.refresh('A');f.tick()
        self.assertEqual(f.row()['phase'],'waiting_ip');self.assertLessEqual(f.row()['next_switch_at'],f.clock[0])
        self.assertEqual(f.value('mobile'),'8.8.8.8');self.assertEqual(f.change.call_count,1)
        f.advance(15,online=('A','B'));f.refresh('B',ip='1.0.0.1');f.tick()
        f.advance(15,online=('A','B'));f.tick();f.tick()
        self.assertEqual(f.value('mobile'),'1.0.0.1')
        self.assertLess(f.clock[0],deadline)

    def test_unknown_completed_probe_does_not_reuse_an_older_failure(self):
        f=self.f;f.health[f.sid('A')]=False;f.refresh('A');self.insert_pending_probe('A')
        with server.connect() as db:
            db.execute("UPDATE detection_runs SET status='unknown' WHERE server_id=? AND status='pending'",(f.sid('A'),))
            self.assertFalse(rotation._failed_ip(db,f.sid('A'),f.clock[0]))
    def test_paused_schedule_does_not_starve_inflight_fault_recovery(self):
        f=self.f
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET enabled=0,phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,fault_recovery=1 WHERE id=?",(f.sid('B'),f.clock[0]-30,f.rid))
        f.health[f.sid('A')]=False;f.refresh('A');f.refresh('B',ip='8.8.4.4');f.tick()
        self.assertEqual(f.row()['phase'],'waiting_probe')
        self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.advance(15,online=('A','B'));f.tick();f.tick()
        self.assertEqual(f.value('mobile'),'8.8.4.4');self.assertEqual(f.row()['enabled'],0)
    def test_three_rounds_of_faults_across_rotation_phases(self):
        scenarios=[
            'test_pending_probe_does_not_hide_confirmed_carrier_failure',
            'test_carrier_fault_cancels_unissued_optional_refresh_then_repairs_carrier',
            'test_issued_optional_refresh_finishes_before_fault_handoff',
            'test_carrier_failure_does_not_prevent_drain_change_recheck_then_handoff',
            'test_paused_schedule_does_not_starve_inflight_fault_recovery',
            'test_overdue_failed_business_port_cannot_handoff_or_reset_deadline',
            'test_same_ip_after_completed_attempt_stays_out_even_past_deadline',
        ]
        for cycle in range(3):
            for scenario in scenarios:
                with self.subTest(cycle=cycle,scenario=scenario):
                    case=ReentryGate(methodName=scenario)
                    case.setUp()
                    try:getattr(case,scenario)()
                    finally:case.doCleanups()

    def test_independent_confirmation_then_fault_handoff_repair_and_return(self):
        import detectors
        import detection_recheck
        f=self.f
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        f.health[f.sid('A')]=False;f.refresh('A')
        with server.connect() as db:
            db.execute("UPDATE detection_plans SET confirm_node='19' WHERE server_id=?",(f.sid('A'),))
            parent=db.execute('SELECT * FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1',(f.sid('A'),)).fetchone()
            db.execute("UPDATE detection_runs SET status='pending' WHERE id=?",(parent['id'],))
            parent=db.execute('SELECT * FROM detection_runs WHERE id=?',(parent['id'],)).fetchone()
            detectors.finish(db,parent,'首轮不通',[{'node_id':'13','state':'unreachable'}])
        f.tick();self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()
        with patch('detectors.boce',return_value={'data':{'id':'cross-point'}}):detection_recheck.tick(server.connect,server.CIPHER)
        with server.connect() as db:db.execute('UPDATE detection_rechecks SET poll_at=0')
        with patch('detectors.boce',return_value={'done':True,'list':[{'node_id':19,'packets_transmitted':1,'packets_received':0,'error_code':0}]}):detection_recheck.tick(server.connect,server.CIPHER)
        f.tick();f.advance(2,online=('B',));f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1');self.assertEqual(f.change.call_count,1)
        self.assertEqual(f.row()['enabled'],1)
        f.health[f.sid('A')]=True;f.refresh('A',ip='1.0.0.1');f.tick()
        with server.connect() as db:self.assertLessEqual(db.execute('SELECT next_at FROM detection_plans WHERE server_id=?',(f.sid('A'),)).fetchone()[0],f.clock[0])
        f.advance(2,online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'1.0.0.1');self.assertEqual(f.row()['enabled'],1)
