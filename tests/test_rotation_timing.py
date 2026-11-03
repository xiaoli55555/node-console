"""Carrier duration follows confirmed DNS changes, not phase changes or uptime."""
import unittest
import test_rotation_emergency as fixture
import test_failover as failover_fixture
import server
import rotation


class CarrierTiming(unittest.TestCase):
    setUp=fixture.OriginalEmergencyProbe.setUp

    def timing(self):
        with server.connect() as db:return rotation._rotation_json(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(self.f.rid,)).fetchone())['timing']

    def test_confirmed_handoff_records_duration_and_actual_overrun(self):
        f=self.f;start=f.clock[0]
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(start+30,f.rid))
        f.advance(35,online=('A','B'));f.tick()
        t=self.timing();self.assertEqual(t['current']['server_id'],f.sid('B'))
        self.assertEqual(t['current']['started'],start+35)
        old=t['history'][1];self.assertEqual(old['server_id'],f.sid('A'))
        self.assertEqual(old['elapsed_s'],35);self.assertEqual(old['overdue_s'],5)
        self.assertEqual(old['deadline'],start+30)
        f.advance(15,online=('A','B'));f.tick();f.tick()
        t=self.timing();self.assertEqual(t['current']['elapsed_s'],15);self.assertEqual(len(t['history']),2)

    def test_manual_new_ip_starts_a_new_observed_carrier_period(self):
        f=self.f;start=f.clock[0];f.advance(20,online=('A','B'))
        f.refresh('A',ip='1.0.0.1');f.records[f.bindings['mobile']]['Value']='1.0.0.1'
        rotation._sync_external_dns(server.connect,server.CIPHER,f.rid,f.clock[0],force=True)
        t=self.timing();self.assertEqual(t['current']['ip'],'1.0.0.1')
        self.assertEqual(t['current']['reason'],'carrier_ip_observed')
        self.assertEqual(t['history'][1]['elapsed_s'],20);self.assertEqual(t['history'][1]['finished'],start+20)

    def test_pause_and_config_save_do_not_restart_carrier_duration(self):
        f=self.f;start=f.clock[0];f.advance(15,online=('A','B'))
        self.assertEqual(f.save(enabled=False).status_code,200)
        f.advance(15,online=('A','B'));f.tick()
        t=self.timing();self.assertEqual(t['current']['started'],start)
        self.assertEqual(t['current']['elapsed_s'],30);self.assertIsNone(t['switch_deadline'])
        self.assertEqual(len(t['history']),1)

    def test_upgrade_baseline_is_censored_and_survives_repeated_ticks(self):
        f=self.f
        with server.connect() as db:db.execute('DELETE FROM rotation_carrier_periods WHERE rotation_id=?',(f.rid,))
        f.advance(10,online=('A','B'));f.tick();first=self.timing()['current']
        self.assertEqual(first['started'],f.clock[0]);self.assertEqual(first['censored'],1)
        f.advance(15,online=('A','B'));f.tick()
        t=self.timing();self.assertEqual(t['current']['elapsed_s'],15);self.assertEqual(len(t['history']),1)

    def test_running_config_saves_preserve_deadline_in_every_phase(self):
        f=self.f;start=f.clock[0];deadline=f.row()['next_switch_at']
        for phase in ('active','draining','waiting_ip','waiting_probe'):
            with self.subTest(phase=phase):
                with server.connect() as db:
                    db.execute('UPDATE vps_rotations SET phase=?,drain_server_id=? WHERE id=?',
                               (phase,None if phase=='active' else f.sid('B'),f.rid))
                f.advance(15,online=('A','B'))
                result=f.save(connection_threshold=20,offline_after_s=30,force_drain_threshold=100)
                self.assertEqual(result.status_code,200,result.json)
                self.assertEqual(f.row()['next_switch_at'],deadline)
                self.assertEqual(f.row()['phase'],phase)
                self.assertEqual(self.timing()['current']['started'],start)

    def test_interval_and_lead_edits_apply_next_cycle_not_save_time(self):
        f=self.f;deadline=f.row()['next_switch_at'];f.advance(60,online=('A','B'))
        result=f.save(interval_s=10800,lead_s=660)
        self.assertEqual(result.status_code,200,result.json)
        self.assertEqual(f.row()['next_switch_at'],deadline)
        self.assertEqual(f.row()['interval_s'],10800);self.assertEqual(f.row()['lead_s'],660)
        f.advance(deadline-f.clock[0],online=('A','B'));f.tick()
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))
        self.assertEqual(f.row()['next_switch_at'],f.clock[0]+10800-660)

    def test_saving_overdue_plan_does_not_postpone_handoff(self):
        f=self.f
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(f.clock[0]-60,f.rid))
        deadline=f.row()['next_switch_at']
        result=f.save(connection_threshold=20)
        self.assertEqual(result.status_code,200,result.json)
        self.assertEqual(f.row()['next_switch_at'],deadline)
        f.tick();self.assertEqual(f.row()['active_server_id'],f.sid('B'))

    def test_explicit_resume_starts_schedule_without_resetting_carrier_history(self):
        f=self.f;start=f.clock[0]
        self.assertEqual(f.save(enabled=False).status_code,200)
        f.advance(60,online=('A','B'))
        result=f.save(interval_s=10800,lead_s=660)
        self.assertEqual(result.status_code,200,result.json)
        self.assertEqual(f.row()['next_switch_at'],f.clock[0]+10800-660)
        self.assertEqual(self.timing()['current']['started'],start)

    def test_fixed_primary_has_no_fabricated_load_deadline(self):
        f=self.f
        with server.connect() as db:db.execute("UPDATE vps_rotations SET mode='fixed_primary',next_switch_at=? WHERE id=?",(f.clock[0]-120,f.rid))
        t=self.timing();self.assertIsNone(t['switch_deadline']);self.assertIsNone(t['overdue_s'])

    def test_drain_and_action_deadlines_are_independent_of_carrier_start(self):
        f=self.f;started=self.timing()['current']['started']
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,drain_started=?,force_drain_threshold=200 WHERE id=?",(f.sid('B'),f.clock[0]-3590,f.rid))
        t=self.timing();self.assertEqual(t['drain_timeout_at'],f.clock[0]+10);self.assertEqual(t['force_threshold'],200)
        with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',action_started=? WHERE id=?",(f.clock[0]-65,f.rid))
        t=self.timing();self.assertIsNone(t['drain_timeout_at']);self.assertEqual(t['action_observe_until'],f.clock[0]-5)
        self.assertEqual(t['current']['started'],started)


class FailoverCarrierTiming(unittest.TestCase):
    setUp=failover_fixture.PrimaryFailover.setUp
    tearDown=failover_fixture.PrimaryFailover.tearDown
    post=failover_fixture.PrimaryFailover.post
    sid=failover_fixture.PrimaryFailover.sid
    save=failover_fixture.PrimaryFailover.save
    refresh=failover_fixture.PrimaryFailover.refresh
    down=failover_fixture.PrimaryFailover.down
    advance=failover_fixture.PrimaryFailover.advance
    tick=failover_fixture.PrimaryFailover.tick
    row=failover_fixture.PrimaryFailover.row
    value=failover_fixture.PrimaryFailover.value

    def test_backup_and_restore_have_their_own_periods(self):
        self.down();self.tick();self.tick()
        with server.connect() as db:
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(self.rid,)).fetchone()
            t=rotation._rotation_json(db,r)['timing']
        self.assertEqual(t['current']['server_id'],self.sid('C'))
        self.assertEqual(t['current']['reason'],'failover_takeover');self.assertIsNone(t['switch_deadline'])
        self.assertEqual(len(t['history']),2)
        self.advance(15,('A','B','C'));self.tick();self.advance(30,('A','B','C'));self.tick()
        with server.connect() as db:
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(self.rid,)).fetchone()
            t=rotation._rotation_json(db,r)['timing']
        self.assertEqual(t['current']['server_id'],self.sid('A'));self.assertEqual(t['current']['reason'],'failover_restore')
        self.assertEqual(len(t['history']),3);self.assertEqual(t['history'][1]['elapsed_s'],45)
