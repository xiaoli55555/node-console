"""Every normal alternating re-entry requires a changed and verified IP."""
import unittest
import test_rotation_reentry as fixture
import rotation
import server

class MandatoryIPRefresh(unittest.TestCase):
 setUp=fixture.ReentryGate.setUp
 ready_standby=fixture.ReentryGate.ready_standby
 def prepare(self):
  f=self.f;f.refresh('B',ip='8.8.4.4')
  f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
  with server.connect() as db:
   db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='8.8.4.4',drain_started=?,drain_grace_s=0,drain_base_attempt=action_attempts WHERE id=?",(f.sid('B'),f.clock[0]-1,f.rid))
  return f
 def test_even_a_just_changed_ip_must_change_again_after_normal_exit(self):
  f=self.prepare();f.tick()
  self.assertEqual(f.row()['phase'],'draining');f.change.assert_not_called()
  f.advance(15,online=('A','B'));f.tick()
  f.change.assert_called_once();self.assertEqual(f.row()['phase'],'waiting_ip')
  self.assertIsNone(f.row()['reused_ip']);self.assertEqual(f.value('mobile'),'8.8.8.8')
 def test_waiting_action_is_not_cancelled_for_a_recent_ip(self):
  f=self.prepare()
  with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',action_started=?,action_attempts=1 WHERE id=?",(f.clock[0],f.rid))
  f.tick();self.assertEqual(f.row()['phase'],'waiting_ip');self.assertEqual(f.row()['action_attempts'],1)
 def test_five_minute_refresh_no_longer_skips_recent_ips(self):
  f=self.f;self.ready_standby(f.clock[0]+600);f.tick()
  f.advance(300,online=('A','B'));f.tick()
  self.assertEqual(f.row()['phase'],'draining');self.assertIsNone(f.row()['reused_ip'])
 def test_legacy_reuse_marker_cannot_publish_the_old_candidate(self):
  f=self.f
  with server.connect() as db:db.execute("UPDATE vps_rotations SET reused_ip='1.1.1.1',reused_server_id=?,next_switch_at=? WHERE id=?",(f.sid('B'),f.clock[0],f.rid))
  f.tick();self.assertEqual(f.value('mobile'),'8.8.8.8');self.assertEqual(f.row()['phase'],'draining')
  self.assertIn('复用已取消',f.row()['status'])
