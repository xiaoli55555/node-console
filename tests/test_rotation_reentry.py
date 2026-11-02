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
        self.assertEqual(f.row()['phase'],'active')
        f.tick();self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.advance(2,online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'8.8.4.4')
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

    def test_overdue_repair_keeps_deadline_and_switches_next_pass(self):
        f=self.f;deadline=f.clock[0]-3600;self.ready_standby(deadline)
        f.tick()
        self.assertEqual(f.row()['phase'],'active')
        self.assertEqual(f.row()['next_switch_at'],deadline)
        self.assertEqual(f.value('mobile'),'8.8.8.8')
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
