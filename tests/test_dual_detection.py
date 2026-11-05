import json
import time
import unittest
from unittest.mock import patch
import test_detectors as fixture
import detectors
import dual_detection as dual
from ip_dns import boce_dns_gate, IntegrationError

class DualDetection(unittest.TestCase):
 setUp=fixture.DetectorTest.setUp
 post=fixture.DetectorTest.post
 source=fixture.DetectorTest.source
 plan=fixture.DetectorTest.plan
 def configure(self,kind='self',automatic=True,response='reboot'):
  self.a=self.source('self');self.b=self.source(kind)
  self.plan(self.a['id'],nodes=['self'],dual_source_id=self.b['id'],dual_nodes=['self'] if kind=='self' else ['3'],automatic=automatic,response_mode=response,failure_threshold=2)
 def probe(self,source,path,data=None):
  return self.client.post('/api/probe/'+path,json=data or {},headers={'Authorization':'Bearer '+source['probe_token']})
 def start(self,scheduled=True):
  with self.connect() as db:db.execute('UPDATE detection_plans SET next_at=0')
  rid=detectors.start_run(self.connect,self.cipher,1,scheduled=scheduled)
  a=self.probe(self.a,'jobs').json['job']
  self.assertEqual(a,{'id':rid,'ip':'8.8.8.8','port':443})
  b=self.probe(self.b,'jobs').json['job'] if self.b.get('probe_token') else None
  if b:self.assertEqual(b,{'id':-(dual.SELF_OFFSET+rid),'ip':'8.8.8.8','port':443})
  return rid,a,b
 def result(self,source,job,reachable):
  data={'ip':job['ip'],'port':job['port'],'reachable':reachable,'latency_ms':4 if reachable else None}
  return self.probe(source,'results/'+str(job['id']),data)
 def commands(self):
  with self.connect() as db:return db.execute('SELECT COUNT(*) FROM commands').fetchone()[0]
 def decision(self,rid):
  with self.connect() as db:return dual.snapshot(db,rid)['decision']
 def test_both_sources_issued_before_either_result_and_only_both_fail_trigger(self):
  self.configure()
  for round_number in range(2):
   rid,a,b=self.start()
   self.assertEqual(self.result(self.b,b,False).status_code,200)
   self.assertEqual(self.decision(rid),'pending');self.assertEqual(self.commands(),0)
   self.assertEqual(self.result(self.a,a,False).status_code,200)
   self.assertEqual(self.decision(rid),'unreachable')
   self.assertEqual(self.commands(),round_number)
  self.assertEqual(self.result(self.b,b,False).status_code,409)
  self.assertEqual(self.commands(),1)
 def test_any_reachable_vetoes_failure_in_either_order(self):
  for first,second in [(True,False),(False,True),(True,True)]:
   self.setUp();self.configure();rid,a,b=self.start()
   self.result(self.a,a,first);self.result(self.b,b,second)
   self.assertEqual(self.commands(),0)
   with self.connect() as db:
    run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
    self.assertEqual(json.loads(run['details'])[0]['state'],'reachable' if first else 'unreachable')
    self.assertFalse(dual.gate(db,run,'unreachable'))
    self.assertEqual(dual.gate(db,run,'reachable'),first and second)
 def test_one_timeout_never_actions_and_pending_blocks_duplicate(self):
  self.configure();rid,a,b=self.start();self.result(self.a,a,False)
  with self.assertRaisesRegex(IntegrationError,'已有检测任务'):detectors.start_run(self.connect,self.cipher,1,True)
  with self.connect() as db:db.execute('UPDATE detection_runs SET created=? WHERE id=?',(int(time.time())-121,rid))
  dual.tick(self.connect,self.cipher)
  self.assertEqual(self.decision(rid),'unknown');self.assertEqual(self.commands(),0)
 def test_ip_change_or_source_disable_discards_old_round(self):
  for reason in ('ip','disabled'):
   self.setUp();self.configure();rid,a,b=self.start();self.result(self.a,a,False)
   with self.connect() as db:
    if reason=='ip':db.execute('UPDATE servers SET metrics=?',(json.dumps({'public_ips':['1.1.1.1'],'capabilities':['reboot']}),))
    else:db.execute('UPDATE detection_sources SET enabled=0 WHERE id=?',(self.b['id'],))
   response=self.result(self.b,b,False)
   self.assertIn(response.status_code,(401,409));dual.tick(self.connect,self.cipher)
   self.assertEqual(self.commands(),0)
   with self.connect() as db:self.assertEqual(dual.snapshot(db,rid)['state'],'cancelled')
 def test_wrong_source_or_target_cannot_finish_second_result(self):
  self.configure();rid,a,b=self.start()
  self.assertEqual(self.result(self.a,b,False).status_code,409)
  b['ip']='1.1.1.1';self.assertEqual(self.result(self.b,b,False).status_code,409)
  self.assertEqual(self.decision(rid),'pending');self.assertEqual(self.commands(),0)
 def test_dns_waits_for_both_sources_and_manual_never_actions(self):
  self.configure(automatic=False,response='none');rid,a,b=self.start(scheduled=False)
  self.result(self.a,a,True)
  with self.connect() as db:self.assertIsNotNone(boce_dns_gate(db,1,'8.8.8.8'))
  self.result(self.b,b,True)
  with self.connect() as db:self.assertIsNone(boce_dns_gate(db,1,'8.8.8.8'))
  self.assertEqual(self.commands(),0)
 def test_external_second_source_runs_without_waiting_for_primary_failure(self):
  self.configure(kind='boce');rid,a,_=self.start()
  with patch('detectors.boce',return_value={'data':{'id':'secondary'}}) as call:dual.tick(self.connect,self.cipher)
  self.assertEqual(call.call_args.args[2],{'node_ids':'3','host':'8.8.8.8:443'})
  with self.connect() as db:db.execute('UPDATE detection_dual_runs SET poll_at=0')
  result={'done':True,'list':[{'node_id':3,'packets_transmitted':1,'packets_received':1,'error_code':0}]}
  with patch('detectors.boce',return_value=result):dual.tick(self.connect,self.cipher)
  self.assertEqual(self.decision(rid),'pending')
  self.result(self.a,a,False);self.assertEqual(self.decision(rid),'mixed');self.assertEqual(self.commands(),0)
  with self.connect() as db:self.assertEqual(db.execute('SELECT cost FROM detection_runs WHERE id=?',(rid,)).fetchone()[0],1)
 def test_configuration_rejects_duplicate_source_and_protects_source_deletion(self):
  self.configure()
  bad=self.post('/plans/1',{'source_id':self.a['id'],'nodes':['self'],'dual_source_id':self.a['id']})
  self.assertEqual(bad.status_code,400)
  self.assertEqual(self.client.delete('/api/detection/sources/'+str(self.b['id']),headers=self.headers).status_code,400)
  bad=self.post('/plans/1',{'source_id':self.a['id'],'nodes':['self'],'dual_source_id':999})
  self.assertEqual(bad.status_code,400)


class DualScheduling(unittest.TestCase):
 setUp=DualDetection.setUp
 post=DualDetection.post
 source=DualDetection.source
 plan=DualDetection.plan
 configure=DualDetection.configure
 probe=DualDetection.probe
 commands=DualDetection.commands
 def test_four_servers_can_receive_two_sources_before_any_results(self):
  self.configure()
  now=int(time.time())
  with self.connect() as db:
   for sid in (2,3,4):db.execute('INSERT INTO servers VALUES(?,?,?,?)',(sid,'VPS '+str(sid),json.dumps({'public_ips':['8.8.8.8'],'capabilities':['reboot']}),now))
  for sid in (2,3,4):
   response=self.post('/plans/'+str(sid),{'source_id':self.a['id'],'dual_source_id':self.b['id'],'nodes':['self'],'automatic':True})
   self.assertEqual(response.status_code,200)
  ids=[detectors.start_run(self.connect,self.cipher,sid,scheduled=True) for sid in (1,2,3,4)]
  first=[self.probe(self.a,'jobs').json['job'] for _ in ids]
  second=[self.probe(self.b,'jobs').json['job'] for _ in ids]
  self.assertEqual({j['id'] for j in first},set(ids))
  self.assertEqual({j['id'] for j in second},{-(dual.SELF_OFFSET+i) for i in ids})
  self.assertEqual(self.commands(),0)
 def test_cold_backup_inherits_both_sources(self):
  import test_failover as fixture
  import server
  case=fixture.PrimaryFailover(methodName='runTest');case.setUp()
  try:
   with server.connect() as db:
    sid=db.execute("INSERT INTO detection_sources(name,kind,secret) VALUES('上海','self','encrypted-placeholder')").lastrowid
    db.execute('UPDATE detection_plans SET dual_source_id=?,dual_nodes=? WHERE server_id=?',(sid,'["self"]',case.sid('A')))
   case.down();case.tick()
   with server.connect() as db:self.assertEqual(db.execute('SELECT dual_source_id,dual_nodes FROM detection_plans WHERE server_id=?',(case.sid('C'),)).fetchone()[:],(sid,'["self"]'))
  finally:case.tearDown()


class DualReconfiguration(unittest.TestCase):
 setUp=DualDetection.setUp
 post=DualDetection.post
 source=DualDetection.source
 plan=DualDetection.plan
 configure=DualDetection.configure
 probe=DualDetection.probe
 commands=DualDetection.commands
 start=DualDetection.start
 result=DualDetection.result
 def test_reconfiguration_cancels_old_issued_tasks_without_blocking_new_round(self):
  self.configure();rid,a,b=self.start()
  self.plan(self.a['id'],nodes=['self'],dual_source_id=self.b['id'],automatic=True)
  self.assertEqual(self.result(self.a,a,False).status_code,409)
  self.assertEqual(self.result(self.b,b,False).status_code,409)
  with self.connect() as db:db.execute('UPDATE detection_plans SET next_at=0')
  self.assertGreater(detectors.start_run(self.connect,self.cipher,1,True),rid)
  self.assertEqual(self.commands(),0)

if __name__=='__main__':unittest.main()
