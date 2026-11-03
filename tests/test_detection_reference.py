"""A failed control station vetoes the target failure, never proves it healthy."""
import json
import unittest
from unittest.mock import patch
import test_detection_recheck as fixture
import detectors
import detection_recheck as recheck


class ReferenceGuard(unittest.TestCase):
 setUp=fixture.IndependentRecheck.setUp
 source=fixture.IndependentRecheck.source
 post=fixture.IndependentRecheck.post
 plan=fixture.IndependentRecheck.plan
 incident_run=fixture.IndependentRecheck.incident_run
 setup_plan=fixture.IndependentRecheck.setup_plan
 reference=fixture.IndependentRecheck.reference
 execute=fixture.IndependentRecheck.execute

 def test_baidu_unreachable_or_unknown_vetoes_failure_without_target_retest(self):
  for state in ('unreachable','unknown'):
   with self.subTest(state=state):
    self.setUp();self.setup_plan();remote=self.reference(state)
    self.assertEqual(remote.call_count,2) # Two parallel reference GETs, no target POST.
    with self.connect() as db:
     job=db.execute('SELECT * FROM detection_rechecks').fetchone()
     self.assertEqual(job['state'],'unknown');self.assertEqual(job['reference_passed'],0)
     self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
     self.assertEqual(db.execute('SELECT COUNT(*) FROM detection_incidents').fetchone()[0],0)
     self.assertEqual(db.execute('SELECT failure_streak FROM detection_plans').fetchone()[0],0)
     self.assertIn('判定已撤销',db.execute('SELECT status FROM detection_runs').fetchone()[0])
     self.assertFalse(recheck.confirmed(db,db.execute('SELECT * FROM detection_plans').fetchone(),db.execute('SELECT * FROM detection_runs').fetchone()))

 def test_baidu_success_submits_target_immediately_and_counts_all_nodes(self):
  self.setup_plan();remote=self.reference()
  self.assertEqual(remote.call_count,3)
  with self.connect() as db:
   job=db.execute('SELECT * FROM detection_rechecks').fetchone()
   self.assertEqual(job['stage'],'target');self.assertEqual(job['state'],'pending')
   self.assertEqual(job['reference_passed'],1)
   self.assertEqual(db.execute('SELECT cost FROM detection_runs').fetchone()[0],7)
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)

 def test_reference_pass_but_target_unknown_vetoes_actions(self):
  self.setup_plan();self.execute('unknown')
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
   self.assertEqual(db.execute('SELECT reference_passed,state FROM detection_rechecks').fetchone()[:],(1,'unknown'))

 def test_budget_after_control_pass_cannot_skip_target(self):
  self.setup_plan()
  with self.connect() as db:db.execute('UPDATE detection_plans SET daily_limit=6')
  self.reference()
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT state FROM detection_rechecks').fetchone()[0],'unknown')
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)

 def test_no_independent_node_uses_reference_before_original_threshold(self):
  source=self.source()['id'];self.plan(source,automatic=True,response_mode='reboot',failure_threshold=2)
  self.incident_run(source,['unreachable','unreachable'],complete_reference=False)
  with self.connect() as db:
   job=db.execute('SELECT * FROM detection_rechecks').fetchone();self.assertEqual(job['node'],'')
   self.assertEqual(db.execute('SELECT COUNT(*) FROM detection_incidents').fetchone()[0],0)
  with patch('detectors.boce',return_value={'data':{'id':'control'}}):recheck.tick(self.connect,self.cipher)
  with self.connect() as db:db.execute('UPDATE detection_rechecks SET poll_at=0')
  result={'done':True,'list':[{'node_id':n,'packets_transmitted':1,'packets_received':1,'error_code':0} for n in [1,2]]}
  with patch('detectors.boce',return_value=result):recheck.tick(self.connect,self.cipher)
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT failure_streak FROM detection_plans').fetchone()[0],1)
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
   self.assertEqual(db.execute('SELECT failures FROM detection_incidents').fetchone()[0],1)

 def test_admin_status_exposes_exact_control_target_nodes_latency_and_time(self):
  self.setup_plan();self.reference()
  overview=self.client.get('/api/detection',headers=self.headers).json
  ref=overview['runs'][0]['reference']
  self.assertEqual((ref['host'],ref['port']),('www.baidu.com',80))
  self.assertTrue(ref['passed']);self.assertIsNotNone(ref['checked'])
  self.assertEqual({x['node_id'] for x in ref['details']},{'1','2','3'})
  self.assertTrue(all(x['state']=='reachable' and x['latency_ms']==17.5 for x in ref['details']))
  status=self.client.get('/api/detection/monitor-status',headers=self.headers).json
  self.assertEqual(status['monitors'][0]['run']['reference'],ref)


class FixedReferenceTarget(unittest.TestCase):
 def test_baota_allows_only_fixed_host_port_without_relaxing_vps_validation(self):
  import baota_probe
  from ip_dns import IntegrationError
  with patch('baota_probe.nodes',return_value=[{'id':'7'}]),patch('baota_probe.call',return_value={'data':{'id':'control'}}) as call:
   self.assertEqual(baota_probe.create('secret','www.baidu.com',80,['7'],'reference',reference=True),'control')
   self.assertEqual(call.call_args.args[2]['host'],'www.baidu.com')
   self.assertEqual(call.call_args.args[2]['port'],80)
   with self.assertRaises(IntegrationError):baota_probe.create('secret','www.baidu.com',81,['7'],'reference',reference=True)
   with self.assertRaises(IntegrationError):baota_probe.create('secret','other.example',80,['7'],'reference',reference=True)
   with self.assertRaises(IntegrationError):baota_probe.create('secret','www.baidu.com',80,['7'],'ordinary')
   self.assertEqual(call.call_count,1)

 def test_aliyun_keeps_reference_domain_in_tcp_task_address(self):
  import aliyun_probe
  from ip_dns import IntegrationError
  with patch('aliyun_probe.nodes',return_value=[{'id':'304:5'}]),patch('aliyun_probe.call',return_value={'CreateResultList':[{'TaskId':'control'}]}) as call:
   self.assertEqual(aliyun_probe.create('secret','www.baidu.com',80,['304:5'],'reference',reference=True),'control')
   self.assertEqual(call.call_args.kwargs['Address'],'www.baidu.com')
   self.assertEqual(json.loads(call.call_args.kwargs['OptionsJson']),{'port':80})
   with self.assertRaises(IntegrationError):aliyun_probe.create('secret','127.0.0.1',80,['304:5'],'reference',reference=True)
   self.assertEqual(call.call_count,1)

 def test_upgrade_discards_unverified_inflight_target_tasks(self):
  import sqlite3
  db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
  db.executescript(recheck.SCHEMA)
  db.execute("INSERT INTO detection_rechecks(parent_id,node,state,remote_id,created) VALUES(1,'19','pending','old-target',1)")
  recheck.initialize(db)
  row=db.execute('SELECT * FROM detection_rechecks').fetchone()
  self.assertEqual(row['state'],'unknown');self.assertEqual(row['reference_passed'],0)
  recheck.initialize(db)
  self.assertEqual(db.execute('SELECT state FROM detection_rechecks').fetchone()[0],'unknown')
  db.close()


class ReferenceHistoryGuard(unittest.TestCase):
 def test_revoked_old_failure_cannot_join_a_new_failure_threshold(self):
  import test_rotation_emergency as rotation_fixture
  import server
  import rotation
  case=rotation_fixture.OriginalEmergencyProbe(methodName='runTest');case.setUp()
  try:
   f=case.f;f.offline_probe('A')
   with server.connect() as db:
    p=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(f.sid('A'),)).fetchone()
    runs=db.execute('SELECT * FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 2',(f.sid('A'),)).fetchall()
    for i,run in enumerate(runs):
     db.execute("INSERT INTO detection_rechecks(parent_id,node,state,stage,reference_passed,applied,created) VALUES(?,'',?,'target',?,?,?)",(run['id'],'confirmed' if i==0 else 'unknown',int(i==0),int(i==0),f.clock[0]))
    self.assertIsNone(recheck.confirmed(db,p,runs[0])) # A control pass is not independent target confirmation.
    self.assertFalse(rotation._fixed_failure(db,f.sid('A'),f.clock[0]))
    db.execute("UPDATE detection_rechecks SET state='confirmed',reference_passed=1,applied=1 WHERE parent_id=?",(runs[1]['id'],))
    self.assertTrue(rotation._fixed_failure(db,f.sid('A'),f.clock[0]))
  finally:case.doCleanups()
