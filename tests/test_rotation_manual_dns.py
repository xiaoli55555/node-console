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
  self.change_dns('1.1.1.1')
  with self.assertRaises(IntegrationError):self.sync()
  self.assertEqual(f.row()['phase'],'waiting_ip');self.assertEqual(f.row()['action_attempts'],2)
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
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_base_attempt=0,action_attempts=1,action_started=1 WHERE id=?",(f.sid('B'),f.rid))
  self.change_dns('1.1.1.1')
  with self.assertRaises(IntegrationError):self.sync()
  self.assertEqual(f.row()['action_attempts'],1);self.assertEqual(f.row()['phase'],'draining')
 def test_alternating_detects_manual_change_after_five_seconds(self):
  f=self.f
  self.assertFalse(rotation._sync_external_dns(server.connect,server.CIPHER,f.rid,f.clock[0]))
  self.change_dns('1.1.1.1');f.advance(5,online=('A','B'))
  self.assertTrue(rotation._sync_external_dns(server.connect,server.CIPHER,f.rid,f.clock[0]))
  self.assertEqual(f.row()['active_server_id'],f.sid('B'))
  self.assertEqual(f.row()['next_switch_at'],f.clock[0]+f.row()['interval_s']-f.row()['lead_s'])
 def test_manual_override_to_draining_old_ip_adopts_actual_dns(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_started=?,drain_base_attempt=0 WHERE id=?",(f.sid('B'),f.clock[0]-100,f.rid))
  self.change_dns('1.1.1.1');self.assertTrue(self.sync())
  self.assertEqual(f.row()['active_server_id'],f.sid('B'));self.assertEqual(f.row()['drain_server_id'],f.sid('A'))
  self.assertIsNone(f.row()['reused_ip']);f.change.assert_not_called()
 def test_carrier_manual_new_ip_preserves_partners_issued_action(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,action_attempts=2,fault_recovery=1 WHERE id=?",(f.sid('B'),f.clock[0]-10,f.rid))
  before=f.row();f.refresh('A',ip='1.0.0.1');self.change_dns('1.0.0.1')
  self.assertTrue(self.sync());after=f.row()
  for key in ('phase','drain_server_id','old_ip','action_started','action_attempts'):self.assertEqual(after[key],before[key],key)
  self.assertEqual(after['active_server_id'],f.sid('A'));self.assertEqual(after['external_dns_pending'],0)
  self.assertEqual(after['fault_recovery'],0)
  f.change.assert_not_called()
 def test_manual_new_ip_of_repaired_target_finishes_and_starts_other_drain(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,action_attempts=2 WHERE id=?",(f.sid('B'),f.clock[0]-10,f.rid))
  f.refresh('B',ip='8.8.4.4');self.change_dns('8.8.4.4')
  self.assertTrue(self.sync());self.assertEqual(f.row()['active_server_id'],f.sid('B'))
  self.assertEqual(f.row()['phase'],'draining');self.assertEqual(f.row()['drain_server_id'],f.sid('A'))
  self.assertEqual(f.row()['action_attempts'],2);f.change.assert_not_called()
 def test_unresolved_manual_change_blocks_actions_between_poll_intervals(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_started=?,drain_grace_s=0,low_samples=2 WHERE id=?",(f.sid('B'),f.clock[0]-100,f.rid))
  self.change_dns('9.9.9.9')
  f.tick();f.tick();f.tick()
  self.assertEqual(f.row()['external_dns_pending'],1);f.change.assert_not_called()
 def test_second_manual_edit_during_validation_is_not_adopted(self):
  f=self.f;self.change_dns('1.1.1.1');original=rotation._fixed_ready
  def concurrent(*args,**kwargs):
   result=original(*args,**kwargs);self.change_dns('9.9.9.9');return result
  with patch('rotation._fixed_ready',side_effect=concurrent):
   with self.assertRaises(IntegrationError):self.sync()
  self.assertEqual(f.row()['active_server_id'],f.sid('A'));self.assertEqual(f.row()['external_dns_pending'],1)
 def test_different_business_port_is_not_adopted_as_a_healthy_target(self):
  f=self.f;self.change_dns('1.1.1.1')
  with server.connect() as db:db.execute('UPDATE ip_monitors SET port=8443 WHERE server_id=?',(f.sid('B'),))
  f.refresh('B')
  with self.assertRaisesRegex(IntegrationError,'业务端口'):self.sync()
  self.assertEqual(f.row()['active_server_id'],f.sid('A'));f.change.assert_not_called()
