"""Concurrent reference sites, per-node OR, and nonblocking late results."""
import json
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch
import test_detection_reference as fixture
import detection_recheck as recheck


class DualReference(unittest.TestCase):
 setUp=fixture.ReferenceGuard.setUp
 source=fixture.ReferenceGuard.source
 post=fixture.ReferenceGuard.post
 plan=fixture.ReferenceGuard.plan
 incident_run=fixture.ReferenceGuard.incident_run
 setup_plan=fixture.ReferenceGuard.setup_plan

 def start(self,fail_host=None,barrier=None):
  self.setup_plan()
  def create(secret,path,body):
   host=body['host'].split(':')[0]
   if barrier:barrier.wait(timeout=2)
   if host==fail_host:raise recheck.IntegrationError('provider failed')
   return {'data':{'id':host}}
  with patch('detectors.boce',side_effect=create) as call:recheck.tick(self.connect,self.cipher)
  return call

 def poll(self,qq,baidu):
  def result(secret,path,body=None):
   if body:return {'data':{'id':'target'}}
   states=qq if path.endswith('www.qq.com') else baidu
   if states is None:return {'done':False}
   if states=='error':raise recheck.IntegrationError('poll failed')
   if len(states)==2:states=list(states)+['reachable']
   return {'done':True,'list':[{'node_id':i+1,'packets_transmitted':1,'packets_received':int(state=='reachable'),'error_code':0,'round_trip_avg':12+i} for i,state in enumerate(states)]}
  with self.connect() as db:
   job=db.execute('SELECT reference_jobs FROM detection_rechecks').fetchone()
   jobs=json.loads(job[0])
   for value in jobs.values():value['poll_at']=0
   db.execute('UPDATE detection_rechecks SET reference_jobs=?',(json.dumps(jobs),))
  with patch('detectors.boce',side_effect=result) as call:recheck.tick(self.connect,self.cipher)
  return call

 def row(self):
  with self.connect() as db:return dict(db.execute('SELECT * FROM detection_rechecks').fetchone())

 def test_both_posts_start_concurrently_and_each_submitted_once(self):
  call=self.start(barrier=threading.Barrier(2))
  self.assertEqual(call.call_count,2)
  with patch('detectors.boce',return_value={'done':False}) as again:recheck.tick(self.connect,self.cipher)
  self.assertTrue(all('/create/' not in x.args[1] for x in again.call_args_list))
  self.assertEqual(set(json.loads(self.row()['reference_jobs'])),{'www.qq.com','www.baidu.com'})

 def test_one_site_failed_other_passes_both_nodes(self):
  self.start();call=self.poll(['unreachable']*2,['reachable']*2)
  self.assertEqual(self.row()['stage'],'target');self.assertEqual(self.row()['reference_passed'],1)
  self.assertEqual(sum(x.args[1]=='task/create/tcping' for x in call.call_args_list),1)

 def test_each_node_may_use_different_passing_site(self):
  self.start();self.poll(['reachable','unreachable'],['unreachable','reachable'])
  self.assertEqual(self.row()['reference_passed'],1)

 def test_both_fail_veto_without_target_post(self):
  self.start();call=self.poll(['unreachable']*2,'error')
  self.assertEqual(self.row()['state'],'unknown');self.assertEqual(self.row()['reference_passed'],0)
  self.assertTrue(all(x.args[1]!='task/create/tcping' for x in call.call_args_list))
  with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)

 def test_one_bad_node_cannot_borrow_other_nodes_success(self):
  self.start();self.poll(['reachable','unreachable'],['reachable','unreachable'])
  self.assertEqual(self.row()['state'],'unknown')

 def test_slow_station_does_not_delay_target_and_late_failure_cannot_reverse_pass(self):
  self.start();self.poll(['reachable']*2,None)
  self.assertEqual(self.row()['stage'],'target')
  with self.connect() as db:
   db.execute("UPDATE detection_rechecks SET state='confirmed',applied=1")
  self.poll(['reachable']*2,['unreachable']*2)
  self.assertEqual(self.row()['state'],'confirmed');self.assertEqual(self.row()['reference_passed'],1)
  with self.connect() as db:
   view=recheck.snapshot(db,self.row()['parent_id'])
   self.assertEqual(len(view['stations']),2)
   self.assertTrue(all(x['state']=='completed' for x in view['stations']))

 def test_one_submit_error_does_not_cancel_other_station(self):
  self.start(fail_host='www.qq.com');self.poll(None,['reachable']*2)
  self.assertEqual(self.row()['reference_passed'],1)

 def test_insufficient_combined_budget_posts_neither_station(self):
  self.setup_plan()
  with self.connect() as db:db.execute('UPDATE detection_plans SET daily_limit=3')
  with patch('detectors.boce') as call:recheck.tick(self.connect,self.cipher);call.assert_not_called()
  self.assertEqual(self.row()['state'],'unknown')

 def test_reference_get_does_not_hold_database_writer_lock(self):
  self.start()
  with self.connect() as db:path=db.execute('PRAGMA database_list').fetchone()[2]
  unlocked=[];mutex=threading.Lock()
  def probe(*args):
   with mutex:
    other=sqlite3.connect(path,timeout=0)
    try:other.execute('BEGIN IMMEDIATE');other.rollback();unlocked.append(True)
    finally:other.close()
   return {'done':False}
  with patch('detectors.boce',side_effect=probe):recheck.tick(self.connect,self.cipher)
  self.assertEqual(unlocked,[True,True])

 def test_independent_confirmation_node_must_pass_its_own_reference(self):
  self.start();self.poll(['reachable','reachable','unreachable'],['reachable','reachable','unreachable'])
  self.assertEqual(self.row()['state'],'unknown');self.assertEqual(self.row()['reference_passed'],0)
