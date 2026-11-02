"""Read-only adoption of manual DNS changes never cancels an issued IP action."""
import unittest
from unittest.mock import patch
import test_rotation_reentry as fixture
import rotation
import server
from ip_dns import IntegrationError

class ManualDNS(unittest.TestCase):
 setUp=fixture.ReentryGate.setUp
 def sync(self):return rotation._sync_external_dns(server.connect,server.CIPHER,self.f.rid,self.f.clock[0],force=True)
 def change_dns(self,ip):self.f.records[self.f.bindings['mobile']]['Value']=ip
 def test_owned_healthy_standby_is_adopted_without_writing_dns(self):
  f=self.f;self.change_dns('1.1.1.1')
  with patch('rotation.update_dns_record') as write:self.assertTrue(self.sync());write.assert_not_called()
  r=f.row();self.assertEqual(r['active_server_id'],f.sid('B'));self.assertEqual(r['drain_server_id'],f.sid('A'))
  self.assertEqual(r['enabled'],1);self.assertEqual(r['next_switch_at'],f.clock[0]+r['interval_s']-r['lead_s'])
  f.change.assert_not_called()
 def test_manual_new_ip_on_same_carrier_restarts_clock(self):
  f=self.f;f.refresh('A',ip='1.0.0.1');self.change_dns('1.0.0.1')
  self.assertTrue(self.sync());self.assertEqual(f.row()['active_server_id'],f.sid('A'));self.assertEqual(f.row()['phase'],'active')
  with server.connect() as db:self.assertEqual(db.execute('SELECT expected_ip FROM dns_bindings WHERE id=?',(f.bindings['mobile'],)).fetchone()[0],'1.0.0.1')
 def test_unknown_ip_and_unhealthy_target_do_not_reset_plan(self):
  f=self.f;self.change_dns('9.9.9.9')
  with self.assertRaises(IntegrationError):self.sync()
  self.assertEqual(f.row()['active_server_id'],f.sid('A'));self.assertEqual(f.row()['external_dns_pending'],1)
  self.change_dns('1.1.1.1');f.health[f.sid('B')]=False;f.refresh('B')
  with self.assertRaises(IntegrationError):self.sync()
  self.assertEqual(f.row()['active_server_id'],f.sid('A'));f.change.assert_not_called()
 def test_explicit_pause_is_preserved(self):
  f=self.f
  with server.connect() as db:db.execute('UPDATE vps_rotations SET enabled=0 WHERE id=?',(f.rid,))
  self.change_dns('1.1.1.1');self.sync();self.assertEqual(f.row()['enabled'],0)
 def test_issued_ip_action_is_not_erased(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,action_attempts=2 WHERE id=?",(f.sid('B'),f.clock[0],f.rid))
  self.change_dns('1.1.1.1');self.assertFalse(self.sync());self.assertEqual(f.row()['phase'],'waiting_ip');self.assertEqual(f.row()['action_attempts'],2)
 def test_pending_reboot_on_target_blocks_adoption(self):
  f=self.f;self.change_dns('1.1.1.1')
  with patch('rotation._pending_action',return_value=True):
   with self.assertRaises(IntegrationError):self.sync()
  self.assertEqual(f.row()['active_server_id'],f.sid('A'))
 def test_fixed_primary_takeover_does_not_drain_or_change_primary_ip(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET mode='fixed_primary' WHERE id=?",(f.rid,))
  self.change_dns('1.1.1.1');self.sync()
  self.assertEqual(f.row()['active_server_id'],f.sid('B'));self.assertEqual(f.row()['phase'],'active');self.assertIsNone(f.row()['drain_server_id']);f.change.assert_not_called()
 def test_unconfirmed_previous_ip_action_blocks_manual_restart(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_base_attempt=0,action_attempts=1 WHERE id=?",(f.sid('B'),f.rid))
  self.change_dns('1.1.1.1')
  with self.assertRaises(IntegrationError):self.sync()
  self.assertEqual(f.row()['action_attempts'],1);self.assertEqual(f.row()['phase'],'draining')
