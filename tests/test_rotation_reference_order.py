"""Suspicion starts B verification; only post-cut evidence authorizes A repair."""
import json
import unittest
from unittest.mock import patch
import test_rotation_emergency as fixture
import detectors
import detection_recheck
import rotation
import server


class ReferenceOrder(unittest.TestCase):
 def setUp(self):
  fixture.OriginalEmergencyProbe.setUp(self)
  f=self.f
  f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}

 def raw_failure(self):
  f=self.f;f.health[f.sid('A')]=False;f.refresh('A')
  with server.connect() as db:
   db.execute("UPDATE detection_plans SET confirm_node='19' WHERE server_id=?",(f.sid('A'),))
   row=db.execute('SELECT * FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1',(f.sid('A'),)).fetchone()
   detectors.finish(db,row,'首轮不通',[{'node_id':'13','state':'unreachable'}])
  return row['id']

 def handoff(self):
  f=self.f;self.raw_failure();f.tick()
  self.assertIsNotNone(f.row()['emergency_probe_after']);f.change.assert_not_called()
  f.clock[0]+=2;f.refresh('B');f.tick()
  self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()
  f.tick();self.assertIsNotNone(f.row()['repair_check'])

 def diagnostic_failure(self,stale=True):
  f=self.f;f.clock[0]+=2;f.refresh('B')
  if stale:
   with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(f.clock[0]-120,f.sid('A')))
  else:
   with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(f.clock[0],f.sid('A')))
  f.offline_probe('A')
  with server.connect() as db:
   row=db.execute('SELECT * FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1',(f.sid('A'),)).fetchone()
   detectors.finish(db,row,'故障后首轮不通',[{'node_id':'13','state':'unreachable'}])
  return row['id']

 def run_guard(self,reference_reachable=True,target_reachable=False):
  f=self.f
  with patch('detectors.boce',return_value={'data':{'id':'reference'}}):detection_recheck.tick(server.connect,server.CIPHER,server_ids=[f.sid('A')])
  def reference(secret,path,body=None):
   if body:return {'data':{'id':'confirm-target'}}
   return {'done':True,'list':[{'node_id':node,'packets_transmitted':1,'packets_received':int(reference_reachable),'error_code':0} for node in (13,19)]}
  with patch('detectors.boce',side_effect=reference):detection_recheck.tick(server.connect,server.CIPHER,server_ids=[f.sid('A')])
  if reference_reachable:
   with patch('detectors.boce',return_value={'done':True,'list':[{'node_id':19,'packets_transmitted':1,'packets_received':int(target_reachable),'error_code':0}]}):detection_recheck.tick(server.connect,server.CIPHER,server_ids=[f.sid('A')])

 def test_A_pending_reference_requests_B_immediately_and_B_reuses_current_ip(self):
  f=self.f;deadline=f.row()['next_switch_at'];self.handoff()
  self.assertEqual(f.row()['old_ip'],'8.8.8.8');self.assertEqual(f.ips[f.sid('B')],'1.1.1.1')
  self.assertTrue(f.row()['repair_check_required']);f.change.assert_not_called()

 def test_stale_A_still_completes_external_confirmation_then_changes_only_A(self):
  f=self.f;self.handoff();rid=self.diagnostic_failure()
  self.run_guard()
  with server.connect() as db:
   job=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(rid,)).fetchone()
   self.assertEqual(job['state'],'confirmed');self.assertEqual(job['applied'],1)
  f.tick();f.change.assert_called_once();self.assertEqual(f.change.call_args.args[1],f.sid('A'))
  self.assertEqual(f.value('mobile'),'1.1.1.1');self.assertEqual(f.row()['phase'],'waiting_ip')

 def test_both_reference_sites_fail_never_change_A(self):
  f=self.f;self.handoff();rid=self.diagnostic_failure();self.run_guard(False)
  f.tick();f.change.assert_not_called();self.assertEqual(f.value('mobile'),'1.1.1.1')
  with server.connect() as db:self.assertEqual(db.execute('SELECT state FROM detection_rechecks WHERE parent_id=?',(rid,)).fetchone()[0],'unknown')

 def test_expired_heartbeat_without_rotation_frozen_target_still_rejects(self):
  f=self.f;rid=self.raw_failure()
  with server.connect() as db:
   db.execute('UPDATE servers SET seen=? WHERE id=?',(f.clock[0]-120,f.sid('A')))
   job=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(rid,)).fetchone()
   self.assertIsNone(detection_recheck._valid(db,job,server.CIPHER,f.clock[0]))

 def test_pre_handoff_failure_cannot_authorize_post_handoff_A_repair(self):
  f=self.f;old=self.raw_failure();f.tick();f.clock[0]+=2;f.refresh('B');f.tick();f.tick()
  with server.connect() as db:
   db.execute('UPDATE servers SET seen=? WHERE id=?',(f.clock[0]-120,f.sid('A')))
   job=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(old,)).fetchone()
   self.assertIsNone(detection_recheck._valid(db,job,server.CIPHER,f.clock[0]))
  f.tick();f.change.assert_not_called()

 def test_unreported_or_changed_frozen_address_cancels_diagnosis(self):
  f=self.f;self.handoff();rid=self.diagnostic_failure()
  with server.connect() as db:
   db.execute("UPDATE vps_rotations SET old_ip='4.2.2.2' WHERE id=?",(f.rid,))
   job=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(rid,)).fetchone()
   self.assertIsNone(detection_recheck._valid(db,job,server.CIPHER,f.clock[0]))

 def test_pending_A_reference_does_not_force_a_B_action_already_inflight(self):
  f=self.f;self.raw_failure()
  with server.connect() as db:
   db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=? WHERE id=?",(f.sid('B'),f.clock[0],f.rid))
  f.tick();self.assertIsNotNone(f.row()['emergency_probe_after'])
  self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()
  self.assertEqual(f.row()['phase'],'waiting_ip')

 def test_draining_B_can_takeover_before_A_reference_completes(self):
  f=self.f;self.raw_failure()
  with server.connect() as db:
   db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip='1.1.1.1',drain_started=?,drain_grace_s=660,low_samples=0 WHERE id=?",(f.sid('B'),f.clock[0],f.rid))
  f.tick();f.clock[0]+=2;f.refresh('B');f.tick()
  self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()

 def test_stale_confirmed_A_repairs_returns_then_B_normally_drains_and_changes(self):
  f=self.f;self.handoff();self.diagnostic_failure();self.run_guard();f.tick()
  self.assertEqual(f.change.call_count,1)
  f.health[f.sid('A')]=True
  for _ in range(4):
   f.clock[0]+=2;f.refresh('A',ip='1.0.0.1');f.refresh('B');f.tick()
  self.assertEqual(f.value('mobile'),'1.0.0.1')
  self.assertEqual(f.row()['phase'],'draining');self.assertEqual(f.row()['drain_server_id'],f.sid('B'))
  self.assertEqual(f.change.call_count,1)
  wait=f.row()['drain_grace_s']
  f.clock[0]+=wait+1;f.refresh('A');f.refresh('B');f.tick()
  self.assertEqual(f.change.call_count,1)
  f.clock[0]+=15;f.refresh('A');f.refresh('B');f.tick()
  self.assertEqual(f.change.call_count,2);self.assertEqual(f.change.call_args.args[1],f.sid('B'))
  for _ in range(3):
   f.clock[0]+=2;f.refresh('A');f.refresh('B',ip='1.0.0.2');f.tick()
  self.assertEqual(f.value('mobile'),'1.0.0.1');self.assertEqual(f.row()['phase'],'active')
  self.assertEqual(f.row()['standby_ready_server'],f.sid('B'))

 def test_source_or_port_change_cancels_stale_frozen_diagnosis(self):
  f=self.f;self.handoff();rid=self.diagnostic_failure()
  with server.connect() as db:
   db.execute('UPDATE ip_monitors SET port=8443 WHERE server_id=?',(f.sid('A'),))
   job=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(rid,)).fetchone()
   self.assertIsNone(detection_recheck._valid(db,job,server.CIPHER,f.clock[0]))

 def test_last_observed_ip_change_rejects_old_frozen_diagnosis(self):
  f=self.f;self.handoff();rid=self.diagnostic_failure()
  with server.connect() as db:
   db.execute("UPDATE ip_monitors SET current_ip='4.2.2.2' WHERE server_id=?",(f.sid('A'),))
   job=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(rid,)).fetchone()
   self.assertIsNone(detection_recheck._valid(db,job,server.CIPHER,f.clock[0]))

 def test_last_agent_address_change_rejects_old_frozen_diagnosis(self):
  f=self.f;self.handoff();rid=self.diagnostic_failure()
  with server.connect() as db:
   metrics=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('A'),)).fetchone()[0])
   metrics.update(public_ips=['4.2.2.2'],egress_ips=['4.2.2.2'])
   db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(metrics),f.sid('A')))
   job=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(rid,)).fetchone()
   self.assertIsNone(detection_recheck._valid(db,job,server.CIPHER,f.clock[0]))
