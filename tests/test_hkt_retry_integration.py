"""Full rotation/SQLite/queue regression for terminal DHCP retries."""
import json
import unittest
from test_hkt_rotation_blocked import HKTBlockedRotation
import server
import hkt_dhcp

class RetryIntegration(unittest.TestCase):
    setUp = HKTBlockedRotation.setUp
    prepare = HKTBlockedRotation.prepare
    run_ticks = HKTBlockedRotation.run_ticks

    def assert_single_retry(self):
        self.run_ticks(5)
        with server.connect() as db:
            jobs=db.execute("SELECT status FROM commands WHERE server_id=? ORDER BY id",(self.f.sid('B'),)).fetchall()
        self.assertEqual(len(jobs),2)
        self.assertEqual(jobs[-1]['status'],'queued')
        self.assertEqual(self.f.row()['action_attempts'],1)
        self.assertEqual(self.f.change.call_count,1)
        self.assertEqual(self.f.value('mobile'),'8.8.8.8')

    def test_expired_retries(self):
        self.prepare('expired');self.assert_single_retry()

    def test_failed_retries(self):
        self.prepare('failed');self.assert_single_retry()

    def test_emergency_failed_retries(self):
        self.prepare('failed',emergency=True);self.assert_single_retry()

    def test_unconfirmed_never_overlaps(self):
        self.prepare('unconfirmed');self.run_ticks(10)
        self.f.change.assert_not_called()
        self.assertEqual(self.f.row()['action_attempts'],0)

    def test_queue_reuses_pending_job(self):
        self.prepare('expired')
        first=hkt_dhcp.queue(self.f.sid('B'),managed=True)
        for _ in range(100):
            self.assertEqual(hkt_dhcp.queue(self.f.sid('B'),managed=True),first)
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commands WHERE server_id=?",(self.f.sid('B'),)).fetchone()[0],2)

    def test_multiple_terminal_failures_can_retry(self):
        self.prepare('expired')
        for status in ['failed','expired']*10:
            job=hkt_dhcp.queue(self.f.sid('B'),managed=True)
            with server.connect() as db:
                db.execute('UPDATE commands SET status=? WHERE id=?',(status,job))
        final=hkt_dhcp.queue(self.f.sid('B'),managed=True)
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commands WHERE server_id=? AND status='queued'",(self.f.sid('B'),)).fetchone()[0],1)
            self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(final,)).fetchone()[0],'queued')

    def test_carrier_still_cannot_change(self):
        self.prepare('expired')
        with server.connect() as db:
            db.execute('UPDATE vps_rotations SET active_server_id=? WHERE id=?',(self.f.sid('B'),self.f.rid))
        with self.assertRaises(Exception) as caught:
            hkt_dhcp.queue(self.f.sid('B'),managed=True)
        self.assertIn('承载',str(caught.exception))
