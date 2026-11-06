"""Urgent fault progression and opt-in one-hour connection reclamation."""
import json
import unittest
from unittest.mock import patch

import test_fixed_primary as fixed_fixture
import test_rotation_emergency as real_fixture
import rotation
import rotation_groups
import detectors
import dns_worker
import server


class ForcedDrain(unittest.TestCase):
    setUp=fixed_fixture.FixedPrimary.setUp
    tearDown=fixed_fixture.FixedPrimary.tearDown
    connect=fixed_fixture.FixedPrimary.connect
    row=fixed_fixture.FixedPrimary.row
    switch=fixed_fixture.FixedPrimary.switch
    refresh=fixed_fixture.FixedPrimary.refresh

    def prepare(self,threshold=200,mode='fixed_primary'):
        self.record['content']='8.8.8.8'
        with self.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='active',mode='fixed_primary',active_server_id=1,drain_server_id=NULL,force_drain_samples=NULL,low_samples=0,last_sample_at=NULL,action_started=NULL")
        self.switch(1000);self.switch(1600)
        with self.connect() as db:
            db.execute('UPDATE vps_rotations SET mode=?,force_drain_threshold=?,next_switch_at=10000',(mode,threshold))
        self.count=150

    def step(self,now):
        self.refresh(now)
        rotation._run_rotation(self.connect,None,1,now)

    def test_full_hour_and_two_new_samples_required_in_both_modes(self):
        for mode in ('fixed_primary','alternating'):
            with self.subTest(mode=mode):
                self.prepare(mode=mode);self.change.reset_mock()
                self.step(5199);self.step(5200);self.step(5200)
                self.change.assert_not_called()
                self.step(5215)
                self.change.assert_not_called()
                self.assertEqual(self.row()['phase'],'draining')

    def test_disabled_threshold_does_not_relax_normal_gate(self):
        self.prepare(threshold=0)
        for now in (5200,5215,5230):self.step(now)
        self.change.assert_not_called();self.assertEqual(self.row()['phase'],'draining')

    def test_threshold_is_strict_and_high_sample_resets_confirmation(self):
        self.prepare()
        self.step(5200);self.count=200;self.step(5215)
        self.count=150;self.step(5230);self.change.assert_not_called()
        self.step(5245);self.change.assert_not_called()

    def test_missing_and_stale_samples_break_forced_confirmation(self):
        self.prepare();self.step(5200)
        with patch('rotation._fresh_ip',return_value=('1.1.1.1',443,{'tcp':0,'connections_sampled':5000})):
            self.step(5215)
        self.step(5230);self.change.assert_not_called()
        self.step(5245);self.change.assert_not_called()

    def test_new_drain_and_changed_threshold_cannot_reuse_confirmation(self):
        self.prepare();self.step(5200)
        with self.connect() as db:db.execute('UPDATE vps_rotations SET force_drain_threshold=180')
        self.step(5215);self.change.assert_not_called()
        with self.connect() as db:db.execute('UPDATE vps_rotations SET drain_started=1620')
        self.step(5230);self.change.assert_not_called()
        self.step(5245);self.change.assert_not_called()

    def test_unhealthy_carrier_and_pending_action_still_block_force(self):
        self.prepare();self.step(5200)
        with patch('rotation._fixed_ready',side_effect=rotation.IntegrationError('carrier unavailable')):
            self.step(5215)
        self.change.assert_not_called()
        with patch('rotation._pending_action',return_value=True):self.step(5230)
        self.change.assert_not_called()
        self.step(5245);self.change.assert_not_called()

    def test_long_ttl_cannot_be_bypassed_after_one_hour(self):
        self.prepare()
        with self.connect() as db:db.execute('UPDATE vps_rotations SET drain_grace_s=4000')
        self.step(5200);self.step(5215);self.change.assert_not_called()
        self.step(5600);self.step(5615);self.change.assert_not_called()

    def test_shared_record_with_unfinished_drain_blocks_forced_action(self):
        self.prepare();self.step(5200)
        with self.connect() as db:
            db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,phase,next_switch_at,updated,drain_server_id,drain_started,drain_grace_s,low_samples,mode) VALUES(1,1,2,2,1,1,'draining',5200,5200,2,1600,0,0,'fixed_primary')")
        self.step(5215);self.change.assert_not_called()
        self.assertIn('关联记录',self.row()['status'])
        with self.connect() as db:db.execute('UPDATE vps_rotations SET low_samples=2 WHERE id<>1')
        self.step(5230);self.change.assert_not_called()


class FastRecovery(unittest.TestCase):
    setUp=real_fixture.OriginalEmergencyProbe.setUp

    def prepare(self,mode='alternating'):
        f=self.f;f.health[f.sid('A')]=False;f.refresh('A')
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET mode=?,phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,action_attempts=1 WHERE id=?",(mode,f.sid('B'),f.clock[0],f.rid))
        return f

    def test_force_threshold_api_preserves_setting_when_toggled_and_validates(self):
        f=self.f
        self.assertEqual(f.save(force_drain_threshold=200).status_code,200)
        self.assertEqual(f.row()['force_drain_threshold'],200)
        self.assertEqual(f.save(enabled=False).status_code,200)
        self.assertEqual(f.row()['force_drain_threshold'],200)
        for bad in (-1,True,1.5,'200',10001):
            self.assertEqual(f.save(enabled=False,force_drain_threshold=bad).status_code,400)
        self.assertEqual(f.save(enabled=False,force_drain_threshold=0).status_code,200)
        self.assertEqual(f.row()['force_drain_threshold'],0)

    def test_forced_drain_cannot_override_current_connection_threshold(self):
        f=self.f
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_started=?,drain_grace_s=0,force_drain_threshold=200 WHERE id=?",(f.sid('B'),f.clock[0]-3601,f.rid))
        for step in range(2):
            if step:f.advance(15,online=('A','B'))
            with server.connect() as db:
                m=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('B'),)).fetchone()[0]);m['tcp']=150
                db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(m),f.sid('B')))
            f.tick()
        f.change.assert_not_called()
        self.assertIn('必须低于',f.row()['status'])

    def test_incident_forces_new_round_but_not_repeated_paid_rounds(self):
        f=self.prepare()
        ids,sids=rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        self.assertEqual(ids,[f.rid]);self.assertEqual(set(sids),{f.sid('A'),f.sid('B')})
        with server.connect() as db:
            self.assertTrue(all(x[0]<=f.clock[0] for x in db.execute('SELECT next_at FROM detection_plans WHERE server_id IN (?,?)',(f.sid('A'),f.sid('B')))))
        f.refresh('A');f.refresh('B')
        with server.connect() as db:db.execute('UPDATE detection_plans SET next_at=?',(f.clock[0]+600,))
        ids,sids=rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        self.assertEqual(ids,[f.rid]);self.assertEqual(sids,[])
        with server.connect() as db:self.assertEqual(db.execute('SELECT next_at FROM detection_plans WHERE server_id=?',(f.sid('B'),)).fetchone()[0],f.clock[0]+600)
        f.refresh('B',ip='8.8.4.4')
        # An agent IP change with no result for that IP must not reuse old data.
        with server.connect() as db:db.execute("DELETE FROM detection_runs WHERE server_id=? AND ip='8.8.4.4'",(f.sid('B'),))
        _,sids=rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        self.assertIn(f.sid('B'),sids)

    def test_pending_primary_and_independent_polls_are_due_now(self):
        f=self.prepare();rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        with server.connect() as db:
            rid=db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,poll_at) SELECT server_id,source_id,ip,port,nodes,'pending',?,?,? FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1",(f.clock[0],f.clock[0],f.clock[0]+30,f.sid('B'))).lastrowid
            db.execute("INSERT INTO detection_rechecks(parent_id,node,state,created,poll_at) VALUES(?,'19','pending',?,?)",(rid,f.clock[0],f.clock[0]+30))
        rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT poll_at FROM detection_runs WHERE id=?',(rid,)).fetchone()[0],f.clock[0])
            self.assertEqual(db.execute('SELECT poll_at FROM detection_rechecks WHERE parent_id=?',(rid,)).fetchone()[0],f.clock[0])

    def test_same_worker_pass_observes_new_ip_verifies_and_hands_off(self):
        f=self.prepare();f.tick()
        rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        f.refresh('B',ip='8.8.4.4')
        with patch('dns_worker.detection_tick'):
            dns_worker.rotation_detection_cycle()
        self.assertEqual(f.value('mobile'),'8.8.4.4')
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))
        f.change.assert_not_called()

    def test_healthy_carrier_and_disabled_detection_do_not_get_extra_probes(self):
        f=self.prepare();f.health[f.sid('A')]=True;f.refresh('A')
        self.assertEqual(rotation.expedite_recovery_probes(server.connect,server.CIPHER),([],[]))
        f.health[f.sid('A')]=False;f.refresh('A')
        with server.connect() as db:db.execute('UPDATE detection_plans SET automatic=0')
        _,sids=rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        self.assertEqual(sids,[])

    def test_scoped_detector_keeps_unrelated_schedules_and_actions_untouched(self):
        f=self.f
        with server.connect() as db:db.execute('UPDATE detection_plans SET next_at=0')
        with patch('detectors.start_run') as submit,patch('detectors.execute_change_ip_actions') as actions:
            detectors.tick(server.connect,server.CIPHER,server_ids=[f.sid('B')])
        self.assertEqual([x.args[2] for x in submit.call_args_list],[f.sid('B')]);actions.assert_not_called()

    def test_real_detector_pipeline_submits_polls_and_hands_off_without_sleep(self):
        self.run_detector_pipeline('alternating')

    def test_fixed_mode_real_detector_pipeline_also_hands_off_immediately(self):
        self.run_detector_pipeline('fixed_primary')

    def run_detector_pipeline(self,mode):
        f=self.prepare(mode);f.refresh('A');f.tick()
        rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        f.refresh('B',ip='8.8.4.4')
        with server.connect() as db:
            db.execute("DELETE FROM detection_runs WHERE server_id=? AND ip='8.8.4.4'",(f.sid('B'),))
        hosts={}
        def provider(secret,path,body=None):
            if body:
                remote='task-'+str(len(hosts));hosts[remote]=body['host']
                return {'data':{'id':remote}}
            host=hosts[path.rsplit('/',1)[-1]]
            return {'done':True,'list':[{'node_id':13,'packets_transmitted':1,'packets_received':int(host.startswith('8.8.4.4:') or host=='www.baidu.com:80'),'error_code':0}]}
        with patch('rotation.boce_dns_gate',side_effect=detectors.boce_dns_gate),patch('detectors.boce',side_effect=provider) as remote,patch('dns_worker.time.sleep') as sleep:
            dns_worker.rotation_detection_cycle()
        self.assertEqual(f.value('mobile'),'8.8.4.4')
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))
        self.assertIn('www.baidu.com:80',hosts.values());self.assertGreaterEqual(remote.call_count,4);self.assertLessEqual(remote.call_count,8)
        sleep.assert_not_called();f.change.assert_not_called()

    def test_pending_confirmation_does_not_clear_an_existing_urgent_incident(self):
        f=self.prepare();rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        with patch('rotation._failed_ip',return_value=False),patch('rotation.boce_dns_gate',return_value='等待独立复测'):
            ids,_=rotation.expedite_recovery_probes(server.connect,server.CIPHER)
            self.assertEqual(ids,[f.rid]);self.assertIsNotNone(f.row()['urgent_probe_floors'])
        with patch('rotation._failed_ip',return_value=False),patch('rotation.boce_dns_gate',return_value=None):
            self.assertEqual(rotation.expedite_recovery_probes(server.connect,server.CIPHER),([],[]))
            self.assertIsNone(f.row()['urgent_probe_floors'])

    def test_normal_drain_is_not_mislabelled_forced_when_both_thresholds_pass(self):
        from rotation_insights import record_progress
        f=self.f;before=dict(f.row());start=f.clock[0]-3601
        after=dict(before,phase='waiting_ip',drain_server_id=f.sid('B'),old_ip='1.1.1.1',action_started=f.clock[0],action_attempts=1,drain_started=start,low_samples=2,force_drain_threshold=200,force_drain_samples=json.dumps({'started':start,'threshold':200,'count':2,'stamp':f.clock[0]}))
        with server.connect() as db:
            record_progress(db,before,after,f.clock[0])
            self.assertEqual(db.execute('SELECT reason FROM rotation_recovery_timings WHERE rotation_id=?',(f.rid,)).fetchone()[0],'scheduled_rotation')

    def test_forced_preload_is_counted_as_forced_reclamation(self):
        from rotation_insights import record_progress
        f=self.f;before=dict(f.row());start=f.clock[0]-3601
        after=dict(before,phase='waiting_ip',drain_server_id=f.sid('B'),old_ip='1.1.1.1',action_started=f.clock[0],action_attempts=1,drain_started=start,low_samples=0,preload_refresh_deadline=before['next_switch_at'],force_drain_threshold=200,force_drain_samples=json.dumps({'started':start,'threshold':200,'count':2,'stamp':f.clock[0]}))
        with server.connect() as db:
            record_progress(db,before,after,f.clock[0])
            self.assertEqual(db.execute('SELECT reason FROM rotation_recovery_timings WHERE rotation_id=?',(f.rid,)).fetchone()[0],'forced_drain')

    def test_urgent_detection_still_obeys_daily_budget(self):
        f=self.prepare()
        _,sids=rotation.expedite_recovery_probes(server.connect,server.CIPHER)
        with server.connect() as db:db.execute('UPDATE detection_plans SET daily_limit=0')
        with patch('detectors.boce') as remote:
            detectors.tick(server.connect,server.CIPHER,server_ids=sids)
        remote.assert_not_called();self.assertEqual(f.value('mobile'),'8.8.8.8')
