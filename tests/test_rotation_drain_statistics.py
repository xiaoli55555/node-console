"""Drain observations are separate from IP-change action duration."""
import unittest
from unittest.mock import patch
import test_rotation_emergency as fixture
import rotation
import server

class DrainStatistics(unittest.TestCase):
    setUp=fixture.OriginalEmergencyProbe.setUp
    def start(self,**changes):
        f=self.f
        values=dict(phase='draining',drain_server_id=f.sid('B'),drain_started=f.clock[0]-120,old_ip='1.1.1.1',drain_grace_s=0,low_samples=0,last_sample_at=None)
        values.update(changes)
        with server.connect() as db:
            db.execute('UPDATE vps_rotations SET '+','.join(k+'=?' for k in values)+' WHERE id=?',list(values.values())+[f.rid])
            rotation._drain_timing(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(f.rid,)).fetchone(),f.clock[0],start=True)
    def stats(self):
        with server.connect() as db:return rotation._drain_statistics(db,self.f.row())
    def test_two_distinct_samples_complete_before_action_guard(self):
        f=self.f;self.start()
        with patch.object(rotation,'_pending_action',return_value=True):
            f.tick();self.assertEqual(self.stats()['records'][0]['outcome'],'pending')
            f.tick();self.assertEqual(self.stats()['records'][0]['outcome'],'pending')
            f.advance(15,online=('A','B'));f.tick()
            result=self.stats();self.assertEqual(result['records'][0]['outcome'],'completed')
            self.assertEqual(result['records'][0]['elapsed_s'],135)
            self.assertEqual(result['records'][0]['tcp'],25)
            f.advance(15,online=('A','B'));f.tick()
            self.assertEqual(self.stats()['summaries'][0]['count'],1)
            self.assertEqual(self.stats()['records'][0]['elapsed_s'],135)
            f.change.assert_not_called()
    def test_emergency_skipped_and_ip_changed_unknown_excluded(self):
        f=self.f;self.start(emergency=1,low_samples=2)
        with patch.object(rotation,'_pending_action',return_value=True):f.tick()
        self.assertEqual(self.stats()['records'][0]['outcome'],'skipped')
        self.assertEqual(self.stats()['summaries'],[])
        f.advance(15,online=('A','B'));self.start(emergency=0,old_ip='8.8.4.4')
        f.tick()
        self.assertEqual(self.stats()['records'][0]['outcome'],'unobserved')
        self.assertEqual(self.stats()['summaries'],[])
    def test_ttl_wait_does_not_mark_complete(self):
        self.start(drain_grace_s=600,low_samples=2)
        self.f.tick()
        self.assertEqual(self.stats()['records'][0]['outcome'],'pending')
    def test_page_endpoint_requires_admin_and_exposes_measurements(self):
        self.start()
        with server.connect() as db:rotation._drain_timing(db,self.f.row(),self.f.clock[0])
        result=self.f.admin.get('/api/admin/rotation-drain-statistics')
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json['rotations'][0]['drain_statistics']['records'][0]['outcome'],'pending')
        self.assertNotEqual(server.app.test_client().get('/api/admin/rotation-drain-statistics').status_code,200)

    def test_repair_without_dns_handoff_does_not_fabricate_a_drain(self):
        self.start()
        with server.connect() as db:db.execute('DELETE FROM vps_rotation_drain_timings')
        self.f.tick()
        self.assertEqual(self.stats()['records'],[])
    def test_confirmed_dns_switch_starts_one_measurement(self):
        f=self.f
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(f.clock[0],f.rid))
        rotation._dns_switch(server.connect,server.CIPHER,f.rid,f.clock[0])
        record=self.stats()['records'][0]
        self.assertEqual(record['server_id'],f.sid('A'))
        self.assertEqual(record['started'],f.clock[0])
        self.assertEqual(record['outcome'],'pending')
        self.assertEqual(record['threshold'],f.row()['connection_threshold'])
        self.assertEqual(len(self.stats()['records']),1)
