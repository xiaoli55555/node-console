"""A second independent failed point confirms exactly the original IP/port."""
import json
import time
import unittest
from unittest.mock import patch
import test_detectors as fixture
import detectors
import detection_recheck as recheck

class IndependentRecheck(unittest.TestCase):
 setUp=fixture.DetectorTest.setUp
 source=fixture.DetectorTest.source
 post=fixture.DetectorTest.post
 plan=fixture.DetectorTest.plan
 incident_run=fixture.DetectorTest.incident_run
 def setup_plan(self,**changes):
  source=self.source()['id'];self.plan(source,automatic=True,response_mode='reboot',failure_threshold=5,confirm_node='3',**changes)
  self.incident_run(source,['unreachable','unreachable'])
  with self.connect() as db:
   run=db.execute('SELECT * FROM detection_runs ORDER BY id DESC LIMIT 1').fetchone()
   self.parent=run['id']
   self.assertIsNotNone(db.execute('SELECT * FROM detection_rechecks').fetchone())
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
  return source
 def execute(self,state='unreachable'):
  with patch('detectors.boce',return_value={'data':{'id':'independent-task'}}) as remote:
   recheck.tick(self.connect,self.cipher)
   self.assertEqual(remote.call_args.args[2],{'node_ids':'3','host':'8.8.8.8:443'})
  with self.connect() as db:db.execute('UPDATE detection_rechecks SET poll_at=0')
  received=0 if state=='unreachable' else 1
  result={'done':True,'list':[{'node_id':3,'packets_transmitted':1,'packets_received':received,'error_code':0}]}
  if state=='unknown':result['list']=[]
  with patch('detectors.boce',return_value=result):recheck.tick(self.connect,self.cipher)
 def test_two_failed_points_queue_one_action_without_waiting_five_rounds(self):
  self.setup_plan();self.execute()
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT state,applied FROM detection_rechecks').fetchone()[:],('confirmed',1))
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],1)
   incident=db.execute('SELECT * FROM detection_incidents').fetchone()
   self.assertEqual(incident['failures'],2);self.assertIsNotNone(incident['confirmed_at'])
  recheck.tick(self.connect,self.cipher)
  with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],1)
 def test_reachable_or_unknown_confirmation_never_actions(self):
  for state in ['reachable','unknown']:
   with self.subTest(state=state):
    self.setUp();self.setup_plan();self.execute(state)
    with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_same_node_and_self_source_are_rejected(self):
  source=self.source()['id']
  self.assertEqual(self.post('/plans/1',{'source_id':source,'nodes':['1'],'confirm_node':'1'}).status_code,400)
 def test_changed_target_or_config_cancels_before_submission(self):
  self.setup_plan()
  with self.connect() as db:db.execute("UPDATE detection_plans SET confirm_node='4'")
  with patch('detectors.boce') as remote:recheck.tick(self.connect,self.cipher);remote.assert_not_called()
  with self.connect() as db:self.assertEqual(db.execute('SELECT state FROM detection_rechecks').fetchone()[0],'cancelled')
 def test_budget_exhaustion_and_ambiguous_post_never_act_or_retry(self):
  self.setup_plan()
  with self.connect() as db:db.execute('UPDATE detection_plans SET daily_limit=1');db.execute('UPDATE detection_runs SET cost=1')
  with patch('detectors.boce') as remote:recheck.tick(self.connect,self.cipher);remote.assert_not_called()
  with self.connect() as db:self.assertEqual(db.execute('SELECT state FROM detection_rechecks').fetchone()[0],'unknown')
 def test_pending_confirmation_blocks_rotation_failure_flag(self):
  source=self.setup_plan()
  with self.connect() as db:
   p=db.execute('SELECT * FROM detection_plans').fetchone();r=db.execute('SELECT * FROM detection_runs').fetchone()
   self.assertFalse(recheck.confirmed(db,p,r))
  self.execute()
  with self.connect() as db:
   self.assertTrue(recheck.confirmed(db,db.execute('SELECT * FROM detection_plans').fetchone(),db.execute('SELECT * FROM detection_runs').fetchone()))
 def test_submit_error_does_not_retry(self):
  from ip_dns import IntegrationError
  self.setup_plan()
  with patch('detectors.boce',side_effect=IntegrationError('network')) as remote:
   recheck.tick(self.connect,self.cipher);recheck.tick(self.connect,self.cipher)
   self.assertEqual(remote.call_count,1)
  with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_ten_rounds_of_failed_reachable_and_unknown_do_not_pause_detection(self):
  for cycle in range(10):
   with self.subTest(cycle=cycle):
    self.setUp();self.setup_plan();state=['unreachable','reachable','unknown'][cycle%3];self.execute(state)
    with self.connect() as db:
     self.assertEqual(db.execute('SELECT automatic FROM detection_plans').fetchone()[0],1)
     self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],int(state=='unreachable'))
 def test_timeout_never_queues_action(self):
  self.setup_plan()
  with patch('detectors.boce',return_value={'data':{'id':'timeout-task'}}):recheck.tick(self.connect,self.cipher)
  with self.connect() as db:db.execute('UPDATE detection_rechecks SET submitted=?,poll_at=0',(int(time.time())-121,))
  with patch('detectors.boce') as remote:recheck.tick(self.connect,self.cipher);remote.assert_not_called()
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT state FROM detection_rechecks').fetchone()[0],'unknown')
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_changed_ip_cancels_confirmation(self):
  self.setup_plan()
  with self.connect() as db:
   db.execute('UPDATE servers SET metrics=? WHERE id=1',(json.dumps({'public_ips':['1.1.1.1'],'capabilities':['reboot']}),))
   db.execute("UPDATE ip_monitors SET current_ip='1.1.1.1' WHERE server_id=1")
  with patch('detectors.boce') as remote:recheck.tick(self.connect,self.cipher);remote.assert_not_called()
  with self.connect() as db:self.assertEqual(db.execute('SELECT state FROM detection_rechecks').fetchone()[0],'cancelled')
 def test_runtime_duplicate_node_is_not_independent_evidence(self):
  source=self.source()['id'];self.plan(source,automatic=True,response_mode='reboot')
  with self.connect() as db:db.execute("UPDATE detection_plans SET confirm_node='1'")
  self.incident_run(source,['unreachable','unreachable'])
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT COUNT(*) FROM detection_rechecks').fetchone()[0],0)
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_cold_backup_inherits_confirmation_node(self):
  import test_failover as failover_fixture
  import server
  case=failover_fixture.PrimaryFailover(methodName='runTest');case.setUp()
  try:
   with server.connect() as db:db.execute("UPDATE detection_plans SET confirm_node='19' WHERE server_id=?",(case.sid('A'),))
   case.down();case.tick()
   with server.connect() as db:self.assertEqual(db.execute('SELECT confirm_node FROM detection_plans WHERE server_id=?',(case.sid('C'),)).fetchone()[0],'19')
  finally:case.tearDown()
