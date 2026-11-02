"""Young-IP reuse is based on observed IP age, never DNS tenure or a reset clock."""
import json
import unittest
import test_rotation_reentry as fixture
import rotation
import server

class YoungIPReuse(unittest.TestCase):
 setUp=fixture.ReentryGate.setUp
 ready_standby=fixture.ReentryGate.ready_standby
 def young_drain(self,age=60):
  f=self.f;f.refresh('B',ip='8.8.4.4')
  with server.connect() as db:
   latest=db.execute('SELECT MAX(id) FROM ip_events WHERE server_id=?',(f.sid('B'),)).fetchone()[0]
   db.execute('UPDATE ip_events SET observed=? WHERE server_id=?',(f.clock[0]-age-1,f.sid('B')))
   db.execute('UPDATE ip_events SET observed=? WHERE id=?',(f.clock[0]-age,latest))
   db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='8.8.4.4',drain_started=?,drain_grace_s=0,drain_base_attempt=action_attempts WHERE id=?",(f.sid('B'),f.clock[0]-1,f.rid))
   r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(f.rid,)).fetchone();rotation._drain_timing(db,r,f.clock[0],start=True)
  return f.clock[0]-age
 def test_verified_young_ip_is_reused_without_resetting_age_or_changing_ip(self):
  f=self.f;started=self.young_drain();f.tick()
  self.assertEqual(f.row()['phase'],'active');self.assertEqual(f.row()['reused_ip'],'8.8.4.4');f.change.assert_not_called()
  with server.connect() as db:
   self.assertEqual(rotation._ip_observed_since(db,f.sid('B'),'8.8.4.4'),started)
   self.assertEqual(db.execute('SELECT outcome FROM vps_rotation_drain_timings WHERE rotation_id=?',(f.rid,)).fetchone()[0],'reused')
   db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(f.clock[0],f.rid))
  f.tick();self.assertEqual(f.value('mobile'),'8.8.4.4')
  with server.connect() as db:self.assertEqual(rotation._ip_observed_since(db,f.sid('B'),'8.8.4.4'),started)
 def test_age_equal_to_half_cycle_is_not_reusable(self):
  f=self.f;self.young_drain(f.row()['interval_s']//2)
  with server.connect() as db:self.assertFalse(rotation._reusable_ip(db,f.row(),f.sid('B'),'8.8.4.4',f.clock[0]))
  f.tick();self.assertEqual(f.row()['phase'],'draining')
 def test_expired_candidate_is_not_published_after_waiting(self):
  f=self.f;self.young_drain();f.tick()
  f.advance(f.row()['interval_s']//2,online=('A','B'))
  with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(f.clock[0],f.rid))
  f.tick();self.assertEqual(f.value('mobile'),'8.8.8.8');self.assertEqual(f.row()['phase'],'draining')
 def test_an_issued_ip_action_cannot_be_cancelled_for_young_ip_reuse(self):
  f=self.f;self.young_drain()
  with server.connect() as db:db.execute('UPDATE vps_rotations SET action_attempts=action_attempts+1 WHERE id=?',(f.rid,))
  f.tick();self.assertEqual(f.row()['phase'],'draining');self.assertIsNone(f.row()['reused_ip'])
 def test_unknown_first_observation_is_not_treated_as_new_ip(self):
  f=self.f
  with server.connect() as db:
   self.assertIsNone(rotation._ip_observed_since(db,f.sid('B'),'1.1.1.1'))
   self.assertFalse(rotation._reusable_ip(db,f.row(),f.sid('B'),'1.1.1.1',f.clock[0]))
 def test_blocked_ip_is_never_reused_even_after_a_healthy_sample(self):
  f=self.f;self.young_drain()
  with server.connect() as db:
   source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(f.sid('B'),)).fetchone()[0]
   db.execute("INSERT INTO detection_incidents(server_id,source_id,source_name,ip,port,nodes,threshold,failures,first_failed,last_failed,confirmed_at,state,last_run,details,response_mode) VALUES(?,?,?,'8.8.4.4',443,'[\"13\"]',2,2,?,?,?,'recovered',1,'[]','change_api')",(f.sid('B'),source,'selected',f.clock[0]-30,f.clock[0]-15,f.clock[0]-15))
   self.assertFalse(rotation._reusable_ip(db,f.row(),f.sid('B'),'8.8.4.4',f.clock[0]))
 def test_optional_five_minute_refresh_is_skipped_for_a_young_verified_ip(self):
  f=self.f;self.ready_standby(f.clock[0]+600);f.tick()
  f.advance(300,online=('A','B'));f.tick()
  self.assertEqual(f.row()['phase'],'active');self.assertEqual(f.row()['reused_ip'],'8.8.4.4');f.change.assert_not_called()
 def test_ipv6_only_history_change_does_not_reset_ipv4_age(self):
  f=self.f;started=self.young_drain()
  with server.connect() as db:
   db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(?,?,?)',(f.sid('B'),json.dumps(['8.8.4.4','2606:4700::1111']),f.clock[0]))
   self.assertEqual(rotation._ip_observed_since(db,f.sid('B'),'8.8.4.4'),started)
