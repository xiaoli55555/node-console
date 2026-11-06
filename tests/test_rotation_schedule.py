import json
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import rotation_schedule as schedule
import rotation
import rotation_groups
import test_rotation_fast_recovery as fixture
import test_failover
from ip_dns import IntegrationError


def at(hour, minute=0, day=3):
    return int(datetime(2026,11,day,hour,minute,tzinfo=timezone(timedelta(hours=8))).timestamp())


class ScheduleValidation(unittest.TestCase):
    def row(self):
        return {'drain_schedule':json.dumps(dict(schedule.DEFAULT,enabled=True)),'connection_threshold':10}

    def test_exact_boundaries_and_midnight(self):
        r=self.row()
        for hour,minute,limit in [(0,0,80),(2,59,80),(3,0,20),(9,59,20),(10,0,40),(19,59,40),(20,0,80),(23,59,80)]:
            self.assertEqual(schedule.effective(r,at(hour,minute))['threshold'],limit)
        self.assertNotEqual(schedule.effective(r,at(23,59))['key'],schedule.effective(r,at(0,0,4))['key'])

    def test_invalid_gap_overlap_missing_or_float_rejected(self):
        for value in [None,{},dict(schedule.DEFAULT,enabled=1),dict(schedule.DEFAULT,boundaries=[0,600,1200]),dict(schedule.DEFAULT,boundaries=[180,180,1200]),dict(schedule.DEFAULT,boundaries=[180,1200,600]),dict(schedule.DEFAULT,boundaries=[180,600,1440]),dict(schedule.DEFAULT,thresholds=[80,20,40]),dict(schedule.DEFAULT,thresholds=[80,20,40,0]),dict(schedule.DEFAULT,thresholds=[80,20,40,True]),dict(schedule.DEFAULT,thresholds=[80,20,40,1.5])]:
            with self.subTest(value=value),self.assertRaises(IntegrationError):schedule.validate(value)

    def test_corruption_falls_back_with_visible_warning(self):
        r=self.row();r['drain_schedule']='broken'
        state=schedule.effective(r,at(20));self.assertEqual(state['threshold'],10);self.assertTrue(state['warning'])
        r['drain_schedule']=json.dumps(schedule.DEFAULT)
        self.assertEqual(schedule.effective(r,at(20))['threshold'],10)


class ScheduleDraining(fixture.ForcedDrain):
    # Reuse fixture helpers, but not inherited test cases.
    def prepare_schedule(self):
        self.prepare(threshold=0,mode='alternating')
        with self.connect() as db:
            db.execute('UPDATE vps_rotations SET drain_started=?,next_switch_at=?,drain_schedule=?',(at(18),at(23),json.dumps(dict(schedule.DEFAULT,enabled=True))))
        self.count=30

    def test_crossing_boundary_cannot_reuse_samples(self):
        self.prepare_schedule();self.step(at(19,59));self.step(at(19,59)+15)
        self.assertEqual(self.row()['low_samples'],1)
        self.count=50;self.step(at(20))
        self.assertEqual(self.row()['low_samples'],0);self.change.assert_not_called()
        self.step(at(20)+15);self.assertEqual(self.row()['low_samples'],1)
        self.step(at(20)+15);self.change.assert_not_called()
        self.step(at(20)+30);self.change.assert_called_once()

    def test_emergency_still_requires_current_connection_limit(self):
        self.prepare_schedule();self.count=5000
        with self.connect() as db:db.execute('UPDATE vps_rotations SET emergency=1,low_samples=2')
        self.step(at(20));self.change.assert_not_called()
        self.count=79;self.step(at(20)+1);self.change.assert_called_once()

    def test_peer_cannot_authorize_action_using_previous_period_samples(self):
        self.prepare_schedule();self.step(at(19,59));self.step(at(19,59)+15)
        with self.connect() as db:
            db.execute('UPDATE vps_rotations SET low_samples=2,last_sample_at=?',(at(19,59)+15,))
            row=db.execute('SELECT * FROM vps_rotations').fetchone()
            self.assertFalse(schedule.samples_current(row,at(20)))

    def test_save_resets_samples_without_resetting_deadline(self):
        self.prepare_schedule();self.step(at(19,59));self.step(at(19,59)+15)
        before=self.row()
        with self.connect() as db:schedule.save(db,1,dict(schedule.DEFAULT,enabled=True,thresholds=[90,20,40,90]),at(19,59)+16)
        self.assertEqual(self.row()['next_switch_at'],before['next_switch_at'])
        self.assertEqual(self.row()['low_samples'],0)


class ScheduleAPI(unittest.TestCase):
    def setUp(self):
        self.f=test_failover.PrimaryFailover(methodName='runTest');self.f.setUp();self.addCleanup(self.f.tearDown)

    def test_atomic_validation_roundtrip_disable_and_legacy_preservation(self):
        f=self.f;cfg=dict(schedule.DEFAULT,enabled=True);deadline=f.row()['next_switch_at']
        response=f.save(drain_schedule=cfg);self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(response.json['rotation']['drain_schedule'],cfg)
        self.assertEqual(f.row()['next_switch_at'],deadline)
        before=f.row()
        response=f.save(connection_threshold=999,drain_schedule=dict(cfg,boundaries=[600,180,1200]))
        self.assertGreaterEqual(response.status_code,400)
        self.assertEqual(f.row(),before)
        self.assertEqual(f.save().status_code,200)
        self.assertEqual(json.loads(f.row()['drain_schedule']),cfg)
        cfg['enabled']=False
        self.assertEqual(f.save(enabled=False,drain_schedule=cfg).status_code,200)
        self.assertFalse(json.loads(f.row()['drain_schedule'])['enabled'])


class ScheduledFaultMatrix(unittest.TestCase):
    def test_all_fault_stages_with_schedule_enabled(self):
        from test_rotation_fault_matrix import RotationFaultMatrix
        original=RotationFaultMatrix.case
        def scheduled_case(matrix):
            case,f=original(matrix)
            with test_failover.server.connect() as db:
                db.execute('UPDATE vps_rotations SET drain_schedule=? WHERE id=?',(json.dumps(dict(schedule.DEFAULT,enabled=True)),f.rid))
            return case,f
        with patch.object(RotationFaultMatrix,'case',scheduled_case):
            matrix=RotationFaultMatrix(methodName='test_both_fault_types_at_eight_stages_then_repair_return_and_resume')
            matrix.test_both_fault_types_at_eight_stages_then_repair_return_and_resume()
