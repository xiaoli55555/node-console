import json
import time
import unittest
import test_detectors as fixture
import detectors
import detection_recheck as recheck
import dual_detection as dual

class ProbeGroups(unittest.TestCase):
 setUp=fixture.DetectorTest.setUp
 post=fixture.DetectorTest.post
 source=fixture.DetectorTest.source
 plan=fixture.DetectorTest.plan
 def child(self,source,name='上海'):
  response=self.post('/sources/'+str(source['id'])+'/probe-nodes',{'name':name})
  self.assertEqual(response.status_code,200,response.json)
  return response.json
 def probe(self,identity,path,data=None):
  return self.client.post('/api/probe/'+path,json=data or {},headers={'Authorization':'Bearer '+identity['probe_token']})
 def result(self,identity,job,value):
  return self.probe(identity,'results/'+str(job['id']),{'ip':job['ip'],'port':job['port'],'reachable':value,'latency_ms':2 if value else None})
 def commands(self):
  with self.connect() as db:return db.execute('SELECT COUNT(*) FROM commands').fetchone()[0]
 def start(self):
  with self.connect() as db:db.execute('UPDATE detection_plans SET next_at=0')
  return detectors.start_run(self.connect,self.cipher,1,scheduled=True)
 def configure(self,source,children,**options):
  self.plan(source['id'],nodes=children,automatic=True,response_mode='reboot',failure_threshold=2,**options)
 def test_group_lists_independent_nodes_and_credentials_do_not_leak(self):
  source=self.source('self');child=self.child(source)
  self.assertNotEqual(source['probe_token'],child['probe_token'])
  self.assertEqual(self.probe(child,'jobs').status_code,200)
  response=self.post('/sources/'+str(source['id'])+'/nodes')
  nodes=response.json['nodes'];self.assertEqual({n['id'] for n in nodes},{'self',child['node_id']})
  self.assertFalse(nodes[0]['online']);self.assertTrue(nodes[1]['online'])
  self.assertNotIn(child['probe_token'],response.get_data(as_text=True))
  self.assertNotIn(source['probe_token'],response.get_data(as_text=True))
  self.assertEqual(self.post('/sources/'+str(source['id'])+'/test').status_code,200)
 def test_two_group_nodes_issue_together_and_both_fail_follow_threshold(self):
  source=self.source('self');child=self.child(source)
  self.configure(source,['self',child['node_id']])
  for n in range(2):
   rid=self.start();a=self.probe(source,'jobs').json['job'];b=self.probe(child,'jobs').json['job']
   self.assertEqual(a['id'],rid);self.assertEqual(a,b)
   self.assertEqual(self.result(child,b,False).status_code,200);self.assertEqual(self.commands(),0)
   self.assertEqual(self.result(source,a,False).status_code,200)
   with self.connect() as db:
    run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
    self.assertEqual({x['node_id'] for x in json.loads(run['details'])},{'self',child['node_id']})
   self.assertEqual(self.commands(),n)
  self.assertEqual(self.result(child,b,False).status_code,409);self.assertEqual(self.commands(),1)
 def test_any_group_node_reachable_vetoes_failure(self):
  source=self.source('self');child=self.child(source);self.configure(source,['self',child['node_id']])
  for a_value,b_value in [(False,True),(True,False),(True,True)]:
   rid=self.start();a=self.probe(source,'jobs').json['job'];b=self.probe(child,'jobs').json['job']
   self.result(source,a,a_value);self.result(child,b,b_value);self.assertEqual(self.commands(),0)
   with self.connect() as db:
    self.assertEqual(db.execute('SELECT failure_streak FROM detection_plans').fetchone()[0],0)
    self.assertFalse(dual.gate(db,db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone(),'unreachable'))
 def test_selected_peer_only_and_other_keys_cannot_claim_or_report(self):
  source=self.source('self');child=self.child(source);other=self.source('self')
  self.configure(source,[child['node_id']]);rid=self.start()
  self.assertIsNone(self.probe(source,'jobs').json['job']);self.assertIsNone(self.probe(other,'jobs').json['job'])
  job=self.probe(child,'jobs').json['job'];self.assertEqual(job['id'],rid)
  self.assertEqual(self.result(source,job,False).status_code,409)
  self.assertEqual(self.result(other,job,False).status_code,409)
  self.assertEqual(self.result(child,job,True).status_code,200)
 def test_offline_missing_peer_is_unknown_and_never_actions(self):
  source=self.source('self');child=self.child(source);self.configure(source,['self',child['node_id']])
  rid=self.start();job=self.probe(source,'jobs').json['job'];self.result(source,job,False)
  with self.connect() as db:db.execute('UPDATE detection_runs SET created=? WHERE id=?',(int(time.time())-121,rid))
  detectors.tick(self.connect,self.cipher)
  self.assertEqual(self.commands(),0)
  with self.connect() as db:
   run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone();self.assertFalse(dual.gate(db,run,'unreachable'))
   snapshot=recheck.snapshot(db,rid)['probe_group'];self.assertFalse(snapshot['complete']);self.assertFalse(snapshot['pending'])
 def test_confirmation_can_use_another_node_in_the_same_group(self):
  source=self.source('self');child=self.child(source)
  self.configure(source,['self'],confirm_node=child['node_id'])
  rid=self.start();job=self.probe(source,'jobs').json['job'];self.result(source,job,False)
  recheck.tick(self.connect,self.cipher)
  self.assertIsNone(self.probe(source,'jobs').json['job'])
  confirm=self.probe(child,'jobs').json['job'];self.assertEqual(confirm['id'],-rid)
  self.assertEqual(self.result(child,confirm,False).status_code,200);self.assertEqual(self.commands(),1)
 def test_second_source_can_itself_have_multiple_nodes(self):
  first=self.source('self');second=self.source('self');child=self.child(second)
  self.configure(first,['self'],dual_source_id=second['id'],dual_nodes=['self',child['node_id']])
  rid=self.start();a=self.probe(first,'jobs').json['job'];b=self.probe(second,'jobs').json['job'];c=self.probe(child,'jobs').json['job']
  self.assertEqual(b['id'],-(dual.SELF_OFFSET+rid));self.assertEqual(b,c)
  self.result(first,a,False);self.result(second,b,False);self.result(child,c,True)
  with self.connect() as db:self.assertEqual(dual.snapshot(db,rid)['decision'],'unknown')
  self.assertEqual(self.commands(),0)
 def test_node_deletion_pause_and_cross_group_edits_are_scoped(self):
  source=self.source('self');child=self.child(source);other=self.source('self')
  self.configure(source,['self',child['node_id']])
  path='/api/detection/sources/'+str(source['id'])+'/probe-nodes/'+str(child['id'])
  self.assertEqual(self.client.delete(path,headers=self.headers).status_code,400)
  self.assertEqual(self.post('/sources/'+str(other['id'])+'/probe-nodes',{'id':child['id'],'name':'bad'}).status_code,404)
  self.assertEqual(self.post('/sources/'+str(source['id'])+'/probe-nodes',{'id':child['id'],'name':'上海','enabled':False}).status_code,200)
  self.assertEqual(self.probe(child,'jobs').status_code,401)
  self.assertEqual(self.post('/plans/1',{'source_id':source['id'],'nodes':[child['node_id']]}).status_code,400)
 def test_selecting_no_nodes_in_a_multi_node_group_is_rejected(self):
  source=self.source('self');self.child(source)
  self.assertEqual(self.post('/plans/1',{'source_id':source['id'],'nodes':[]}).status_code,400)


class GroupConfigurationChanges(unittest.TestCase):
 setUp=ProbeGroups.setUp
 post=ProbeGroups.post
 source=ProbeGroups.source
 plan=ProbeGroups.plan
 child=ProbeGroups.child
 configure=ProbeGroups.configure
 probe=ProbeGroups.probe
 result=ProbeGroups.result
 start=ProbeGroups.start
 commands=ProbeGroups.commands
 def test_old_round_is_cancelled_when_same_group_plan_is_saved_again(self):
  source=self.source('self');child=self.child(source);self.configure(source,['self',child['node_id']])
  rid=self.start();first=self.probe(source,'jobs').json['job'];second=self.probe(child,'jobs').json['job']
  self.result(source,first,False);self.configure(source,['self',child['node_id']])
  self.assertEqual(self.result(child,second,False).status_code,409)
  self.assertGreater(self.start(),rid);self.assertEqual(self.commands(),0)
 def test_pause_then_resume_does_not_reuse_an_inflight_node_task(self):
  source=self.source('self');child=self.child(source);self.configure(source,['self',child['node_id']])
  self.start();first=self.probe(source,'jobs').json['job'];second=self.probe(child,'jobs').json['job'];self.result(source,first,False)
  for enabled in (False,True):self.assertEqual(self.post('/sources/'+str(source['id'])+'/probe-nodes',{'id':child['id'],'name':'上海','enabled':enabled}).status_code,200)
  self.assertEqual(self.result(child,second,False).status_code,409);self.assertEqual(self.commands(),0)
 def test_node_from_another_group_is_not_an_allowed_selection(self):
  source=self.source('self');other=self.source('self');child=self.child(other)
  self.assertEqual(self.post('/plans/1',{'source_id':source['id'],'nodes':[child['node_id']]}).status_code,400)
 def test_positive_result_for_old_ip_cannot_authorize_group_failure(self):
  source=self.source('self');child=self.child(source);self.configure(source,['self',child['node_id']])
  self.start();first=self.probe(source,'jobs').json['job'];second=self.probe(child,'jobs').json['job'];self.result(source,first,False)
  with self.connect() as db:db.execute('UPDATE servers SET metrics=?',(json.dumps({'public_ips':['1.1.1.1'],'capabilities':['reboot']}),))
  self.assertEqual(self.result(child,second,False).status_code,409);self.assertEqual(self.commands(),0)


class PauseDuringConfirmation(unittest.TestCase):
 setUp=ProbeGroups.setUp
 post=ProbeGroups.post
 source=ProbeGroups.source
 plan=ProbeGroups.plan
 child=ProbeGroups.child
 configure=ProbeGroups.configure
 probe=ProbeGroups.probe
 result=ProbeGroups.result
 start=ProbeGroups.start
 commands=ProbeGroups.commands
 def test_pausing_first_node_cancels_its_inflight_confirmation(self):
  source=self.source('self');child=self.child(source)
  self.configure(source,[child['node_id']],confirm_node='self')
  rid=self.start();job=self.probe(child,'jobs').json['job'];self.result(child,job,False)
  recheck.tick(self.connect,self.cipher);confirm=self.probe(source,'jobs').json['job'];self.assertEqual(confirm['id'],-rid)
  for enabled in (False,True):self.post('/sources/'+str(source['id'])+'/probe-nodes',{'id':child['id'],'name':'上海','enabled':enabled})
  self.assertEqual(self.result(source,confirm,False).status_code,409);self.assertEqual(self.commands(),0)

if __name__=='__main__':unittest.main()
