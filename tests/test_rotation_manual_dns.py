"""Periodic DNS enforcement preserves the effective carrier and its schedule."""
import unittest
from unittest.mock import patch
import test_rotation_reentry as fixture
import rotation
import server
from ip_dns import IntegrationError

class ManualDNS(unittest.TestCase):
 setUp=fixture.ReentryGate.setUp
 def sync(self,force=True):return rotation._sync_external_dns(server.connect,server.CIPHER,self.f.rid,self.f.clock[0],force=force)
 def change_dns(self,ip):self.f.records[self.f.bindings['mobile']]['Value']=ip
 def test_wrong_DNS_is_corrected_without_changing_carrier_or_deadline(self):
  f=self.f;before=f.row();self.change_dns('1.1.1.1');self.assertTrue(self.sync())
  self.assertEqual(f.value('mobile'),'8.8.8.8')
  after=f.row()
  for k in ('active_server_id','phase','next_switch_at','drain_server_id','action_attempts'):self.assertEqual(after[k],before[k],k)
  f.change.assert_not_called()
 def test_unknown_external_ip_is_corrected(self):
  self.change_dns('4.4.4.4');self.assertTrue(self.sync());self.assertEqual(self.f.value('mobile'),'8.8.8.8')
 def test_pause_does_not_read_or_write_provider(self):
  f=self.f
  with server.connect() as db:db.execute('UPDATE vps_rotations SET enabled=0 WHERE id=?',(f.rid,))
  self.change_dns('1.1.1.1')
  with patch('rotation.get_dns_record') as read,patch('rotation.update_dns_record') as write:
   self.assertFalse(self.sync());read.assert_not_called();write.assert_not_called()
 def test_poll_is_every_300_seconds(self):
  f=self.f;self.assertFalse(self.sync(False));self.change_dns('1.1.1.1')
  f.advance(299,online=('A','B'));self.assertFalse(self.sync(False));self.assertEqual(f.value('mobile'),'1.1.1.1')
  f.advance(1,online=('A','B'));self.assertTrue(self.sync(False));self.assertEqual(f.value('mobile'),'8.8.8.8')
 def test_issued_partner_action_is_preserved(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,action_attempts=2 WHERE id=?",(f.sid('B'),f.clock[0],f.rid))
  before=f.row();self.change_dns('1.1.1.1');self.sync()
  after=f.row()
  for k in ('phase','drain_server_id','old_ip','action_started','action_attempts','next_switch_at'):self.assertEqual(after[k],before[k],k)
 def test_pending_rotation_intent_is_not_overridden(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET dns_intent='{}' WHERE id=?",(f.rid,))
  with patch('rotation.update_dns_record') as write:self.assertFalse(self.sync());write.assert_not_called()
 def test_C_lease_is_used_and_pending_C_handoff_is_skipped(self):
  f=self.f;self.change_dns('1.1.1.1')
  with server.connect() as db:db.execute("INSERT INTO vps_failover_leases(binding_id,rotation_id,original_ip,current_ip,updated) VALUES(?,?,'8.8.8.8','9.9.9.9',?)",(f.bindings['mobile'],f.rid,f.clock[0]))
  self.sync();self.assertEqual(f.value('mobile'),'9.9.9.9')
  with server.connect() as db:db.execute("UPDATE vps_failover_leases SET intent='{}' WHERE rotation_id=?",(f.rid,))
  with patch('rotation.update_dns_record') as write:self.assertFalse(self.sync());write.assert_not_called()
 def test_failed_update_retries_at_next_poll(self):
  f=self.f;self.change_dns('1.1.1.1')
  with patch('rotation.update_dns_record',side_effect=IntegrationError('timeout')):
   with self.assertRaises(IntegrationError):self.sync(False)
  with self.assertRaises(IntegrationError):self.sync(False)
  f.advance(300,online=('A','B'));self.assertTrue(self.sync(False));self.assertEqual(f.row()['external_dns_pending'],0)
 def test_only_selected_binding_is_corrected(self):
  f=self.f;before={line:f.value(line) for line in f.bindings if line!='mobile'}
  self.change_dns('1.1.1.1');self.sync()
  self.assertEqual({line:f.value(line) for line in before},before)
