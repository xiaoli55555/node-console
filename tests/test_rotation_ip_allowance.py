"""IP allowance survives fault handoffs; emergencies never require credit."""
import unittest
import json
from unittest.mock import patch
import test_rotation_emergency as fixture
import test_rotation_multi as multi_fixture
import rotation
import rotation_timing
import server


class IPAllowance(unittest.TestCase):
    setUp=fixture.OriginalEmergencyProbe.setUp

    def past(self,name,seconds,ip=None):
        f=self.f
        with server.connect() as db:
            db.execute('INSERT INTO rotation_carrier_periods(rotation_id,server_id,ip,started,finished,elapsed_s,reason) VALUES(?,?,?,?,?,?,?)',
                (f.rid,f.sid(name),ip or f.ips[f.sid(name)],f.clock[0]-seconds-100,f.clock[0]-100,seconds,'fault_switch'))

    def emergency(self):
        f=self.f;f.health[f.sid('A')]=False;f.refresh('A');f.tick()
        f.advance(2,online=('A','B'));f.tick()
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))

    def test_exhausted_standby_still_takes_over_emergency(self):
        f=self.f;self.past('B',8000);self.emergency()
        self.assertLess(f.row()['next_switch_at'],f.clock[0])
        self.assertEqual(f.value('mobile'),'1.1.1.1')

    def test_exhausted_candidate_is_refreshed_before_normal_handoff(self):
        f=self.f;self.past('B',8000)
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(f.clock[0],f.rid))
        f.tick()
        self.assertEqual(f.row()['active_server_id'],f.sid('A'))
        self.assertEqual(f.row()['phase'],'draining')
        self.assertEqual(f.row()['drain_server_id'],f.sid('B'))
        self.assertEqual(f.value('mobile'),'8.8.8.8')

    def test_returning_same_ip_only_gets_remaining_time(self):
        f=self.f;self.past('A',3600);self.emergency()
        with server.connect() as db:
            used=rotation_timing.ip_usage(db,f.rid,f.sid('A'),'8.8.8.8',f.clock[0])
        f.health[f.sid('A')]=True;f.advance(15,online=('A','B'))
        with patch('rotation._heartbeat_confirmed',return_value=False):f.tick()
        self.assertEqual(f.row()['active_server_id'],f.sid('A'))
        self.assertEqual(f.row()['next_switch_at'],f.clock[0]+7200-used)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT reason FROM rotation_carrier_periods WHERE rotation_id=? AND finished IS NULL',(f.rid,)).fetchone()[0],'fault_restore')

    def test_exhausted_original_does_not_bounce_back_after_recovery(self):
        f=self.f;self.past('A',8000);self.emergency()
        f.health[f.sid('A')]=True;f.advance(15,online=('A','B'))
        with patch('rotation._heartbeat_confirmed',return_value=False):f.tick()
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))
        self.assertEqual(f.row()['drain_server_id'],f.sid('A'))
        self.assertEqual(f.row()['repair_check_required'],0)
        self.assertEqual(f.row()['drain_grace_s'],120)
        # Leaving emergency recovery must restore the normal TTL gate.
        f.advance(15,online=('A','B'));f.tick()
        f.advance(15,online=('A','B'));f.tick()
        f.change.assert_not_called()

    def test_ttl_read_failure_waits_safely_then_resumes_without_pausing(self):
        f=self.f;self.past('A',8000);self.emergency()
        f.health[f.sid('A')]=True;f.advance(15,online=('A','B'))
        for _ in range(3):
            with patch('rotation._heartbeat_confirmed',return_value=False),patch('rotation.get_dns_record',side_effect=rotation.IntegrationError('DNS API timeout')):
                f.tick()
            self.assertTrue(f.row()['enabled']);self.assertEqual(f.row()['repair_check_required'],1)
            self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()
        with patch('rotation._heartbeat_confirmed',return_value=False):f.tick()
        self.assertEqual(f.row()['repair_check_required'],0)
        self.assertEqual(f.row()['drain_grace_s'],120)
        self.assertTrue(f.row()['enabled'])

    def test_new_ip_does_not_inherit_old_ip_usage(self):
        f=self.f;self.past('B',8000);f.refresh('B',ip='1.0.0.1')
        with server.connect() as db:
            self.assertEqual(rotation_timing.ip_usage(db,f.rid,f.sid('B'),'1.0.0.1',f.clock[0]),0)
        self.emergency()
        self.assertEqual(f.row()['next_switch_at'],f.clock[0]+7200)

    def test_failed_probe_never_starts_candidate_clock(self):
        f=self.f;f.health[f.sid('B')]=False;f.refresh('B')
        f.health[f.sid('A')]=False;f.refresh('A');f.tick()
        f.advance(2,online=('A','B'));f.tick()
        with server.connect() as db:
            self.assertFalse(db.execute('SELECT 1 FROM rotation_carrier_periods WHERE rotation_id=? AND server_id=?',(f.rid,f.sid('B'))).fetchone())

    def test_ip_ledger_survives_more_than_ninety_days(self):
        f=self.f;self.past('B',8000)
        with server.connect() as db:
            rotation_timing.change(db,f.rid,f.sid('B'),'1.0.0.1',f.clock[0]+100*86400,'scheduled_switch')
            self.assertEqual(rotation_timing.ip_usage(db,f.rid,f.sid('B'),'1.1.1.1',f.clock[0]+100*86400),8000)

    def test_twelve_full_cycles_keep_switching_and_refreshing_ips(self):
        f=self.f
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        for cycle in range(12):
            before=f.row()['active_server_id']
            f.advance(max(1,f.row()['next_switch_at']-f.clock[0]),online=('A','B'));f.tick()
            self.assertNotEqual(f.row()['active_server_id'],before,(cycle,f.row()['status']))
            self.assertTrue(f.row()['enabled'])
            old='A' if before==f.sid('A') else 'B'
            # Advance through real TTL and two independent low-TCP samples.
            f.advance(max(15,f.row()['drain_grace_s']),online=('A','B'));f.tick()
            f.advance(15,online=('A','B'));f.tick()
            self.assertEqual(f.row()['phase'],'waiting_ip',(cycle,f.row()['status']))
            f.advance(15,online=('A','B'));f.refresh(old,ip='8.8.4.'+str(cycle+10));f.tick()
            f.advance(15,online=('A','B'));f.tick()
            self.assertEqual(f.row()['phase'],'active',(cycle,f.row()['status']))
            self.assertGreater(f.row()['next_switch_at'],f.clock[0])
            active=f.row()['active_server_id']
            self.assertEqual(f.value('mobile'),f.ips[active])

    def test_normal_handoff_respects_ttl_and_two_strict_low_samples(self):
        f=self.f
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        f.advance(f.row()['next_switch_at']-f.clock[0],online=('A','B'));f.tick()
        f.advance(f.row()['drain_grace_s']-1,online=('A','B'));f.tick()
        f.change.assert_not_called()
        for tcp in (1000,80,1000,79):
            f.advance(15,online=('A','B'))
            with server.connect() as db:
                m=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('A'),)).fetchone()[0]);m['tcp']=tcp
                db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(m),f.sid('A')))
            f.tick();f.change.assert_not_called()
            self.assertEqual(f.value('mobile'),'1.1.1.1')
        f.advance(15,online=('A','B'));f.tick()
        f.change.assert_called_once()
        self.assertEqual(f.row()['phase'],'waiting_ip')

    def test_normal_due_cannot_reuse_unfinished_draining_ip(self):
        f=self.f
        f.advance(f.row()['next_switch_at']-f.clock[0],online=('A','B'));f.tick()
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(f.clock[0],f.rid))
        for _ in range(5):
            with server.connect() as db:
                m=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('A'),)).fetchone()[0]);m['tcp']=1000
                db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(m),f.sid('A')))
            f.tick()
            self.assertEqual(f.value('mobile'),'1.1.1.1')
            f.change.assert_not_called()

    def test_twenty_fault_recovery_rounds_keep_plan_live_and_credit(self):
        f=self.f
        for cycle in range(20):
            f.health[f.sid('A')]=False
            for attempt in range(6):
                f.advance(5,online=('A','B'));f.tick()
                if f.row()['active_server_id']==f.sid('B'):break
            self.assertEqual(f.row()['active_server_id'],f.sid('B'),(cycle,f.row()['status']))
            with server.connect() as db:
                used=rotation_timing.ip_usage(db,f.rid,f.sid('A'),'8.8.8.8',f.clock[0])
            f.health[f.sid('A')]=True;f.advance(5,online=('A','B'))
            with patch('rotation._heartbeat_confirmed',return_value=False):f.tick()
            self.assertEqual(f.row()['active_server_id'],f.sid('A'),(cycle,f.row()['status']))
            self.assertEqual(f.row()['next_switch_at'],f.clock[0]+7200-used)
            self.assertTrue(f.row()['enabled']);self.assertIsNone(f.row()['dns_intent'])
            f.change.assert_not_called()


class GroupAllowance(unittest.TestCase):
    setUp=multi_fixture.MultiPlan.setUp
    tearDown=multi_fixture.MultiPlan.tearDown
    post=multi_fixture.MultiPlan.post
    sid=multi_fixture.MultiPlan.sid
    save=multi_fixture.MultiPlan.save
    refresh=multi_fixture.MultiPlan.refresh
    put=multi_fixture.MultiPlan.put
    drop_first=multi_fixture.MultiPlan.drop_first
    multi=multi_fixture.MultiPlan.multi
    row=multi_fixture.MultiPlan.row
    value=multi_fixture.MultiPlan.value
    tick=multi_fixture.MultiPlan.tick
    advance=multi_fixture.MultiPlan.advance

    def test_group_recovery_uses_one_remaining_allowance(self):
        self.multi()
        with server.connect() as db:db.execute("UPDATE vps_rotations SET mode='alternating'")
        self.health[self.sid('A')]=False;self.refresh('A');self.tick()
        self.advance(2,online=('A','B'));self.tick()
        self.advance(2,online=('A','B'));self.tick()
        self.assertEqual(self.row()['active_server_id'],self.sid('B'))
        with server.connect() as db:
            used=rotation_timing.ip_usage(db,self.rid,self.sid('A'),'8.8.8.8',self.clock[0])
        self.health[self.sid('A')]=True;self.advance(15,online=('A','B'))
        with patch('rotation._heartbeat_confirmed',return_value=False):self.tick()
        with server.connect() as db:
            rows=db.execute('SELECT * FROM vps_rotations').fetchall()
            self.assertTrue(all(r['active_server_id']==self.sid('A') for r in rows))
            self.assertTrue(all(r['next_switch_at']==self.clock[0]+7200-used for r in rows))

    def test_partial_dns_write_does_not_start_candidate_allowance(self):
        plan=self.multi()
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET mode='alternating',next_switch_at=?",(self.clock[0],))
        original=rotation.update_dns_record
        def partial(*args):
            if args[1]['id']==self.bindings['telecom']:raise rotation.IntegrationError('provider unavailable')
            return original(*args)
        with patch('rotation.update_dns_record',side_effect=partial):self.tick()
        with server.connect() as db:
            self.assertFalse(db.execute('SELECT 1 FROM rotation_carrier_periods WHERE server_id=?',(self.sid('B'),)).fetchone())
            self.assertTrue(all(r['dns_intent'] for r in db.execute('SELECT * FROM vps_rotations')))
        self.advance(15,online=('A','B'));self.tick()
        with server.connect() as db:
            rows=db.execute('SELECT * FROM vps_rotations').fetchall()
            self.assertTrue(all(r['active_server_id']==self.sid('B') for r in rows))
            self.assertEqual(len({r['next_switch_at'] for r in rows}),1)
            self.assertTrue(all(r['next_switch_at']==self.clock[0]+7200 for r in rows))
