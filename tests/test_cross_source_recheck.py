import json
import time
import unittest
from unittest.mock import patch
import test_detectors as fixture
import detectors
import detection_recheck as recheck

class CrossSourceRecheck(unittest.TestCase):
 setUp=fixture.DetectorTest.setUp
 post=fixture.DetectorTest.post
 source=fixture.DetectorTest.source
 plan=fixture.DetectorTest.plan
 def setup_cross(self,first='self',second='self',node='self',**extra):
  a=self.source(first);b=self.source(second)
  self.plan(a['id'],nodes=['self'] if first=='self' else ['1','2'],automatic=True,response_mode='reboot',confirm_node=node,confirm_source_id=b['id'],**extra)
  now=int(time.time());nodes=['self'] if first=='self' else ['1','2']
  with self.connect() as db:
   db.execute("UPDATE ip_monitors SET current_ip='8.8.8.8'")
   rid=db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,scheduled,created,updated) VALUES(1,?,'8.8.8.8',443,?,'pending',1,?,?)",(a['id'],json.dumps(nodes),now,now)).lastrowid
   run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
   detectors.finish(db,run,'首轮不通',[{'node_id':n,'state':'unreachable'} for n in nodes])
  return a,b,rid
 def probe(self,source,path,data=None):
  return self.client.post('/api/probe/'+path,json=data or {},headers={'Authorization':'Bearer '+source['probe_token']})
 def commands(self):
  with self.connect() as db:return db.execute('SELECT COUNT(*) FROM commands').fetchone()[0]
 def self_result(self,a,b,rid,reachable=False,**extra):
  recheck.tick(self.connect,self.cipher)
  self.assertIsNone(self.probe(a,'jobs').json['job'])
  task=self.probe(b,'jobs').json['job'];self.assertEqual(task,{'id':-rid,'ip':'8.8.8.8','port':443})
  return self.probe(b,'results/'+str(-rid),{'ip':'8.8.8.8','port':443,'reachable':reachable,'latency_ms':3 if reachable else None,**extra})
 def test_two_self_sources_confirm_once_without_fabricated_reference(self):
  a,b,rid=self.setup_cross()
  self.assertEqual(self.self_result(a,b,rid).status_code,200)
  self.assertEqual(self.commands(),1)
  self.assertEqual(self.probe(b,'results/'+str(-rid),{'ip':'8.8.8.8','port':443,'reachable':False}).status_code,409)
  with self.connect() as db:
   p=db.execute('SELECT * FROM detection_plans').fetchone();r=db.execute('SELECT * FROM detection_runs').fetchone()
   self.assertTrue(recheck.confirmed(db,p,r))
   self.assertFalse(recheck.snapshot(db,rid)['passed'])
   self.assertFalse(recheck.snapshot(db,rid)['reference_required'])
 def test_self_reachable_vetoes_and_wrong_target_rejected(self):
  a,b,rid=self.setup_cross()
  self.assertEqual(self.self_result(a,b,rid,ip='1.1.1.1').status_code,409)
  self.assertEqual(self.commands(),0)
  good=self.probe(b,'results/'+str(-rid),{'ip':'8.8.8.8','port':443,'reachable':True,'latency_ms':2})
  self.assertEqual(good.status_code,200);self.assertEqual(self.commands(),0)
 def test_changed_source_or_expired_self_result_never_actions(self):
  a,b,rid=self.setup_cross();recheck.tick(self.connect,self.cipher)
  self.probe(b,'jobs')
  with self.connect() as db:db.execute('UPDATE detection_sources SET enabled=0 WHERE id=?',(b['id'],))
  self.assertEqual(self.probe(b,'results/'+str(-rid),{'ip':'8.8.8.8','port':443,'reachable':False}).status_code,401)
  recheck.tick(self.connect,self.cipher);self.assertEqual(self.commands(),0)
  with self.connect() as db:self.assertEqual(db.execute('SELECT state FROM detection_rechecks').fetchone()[0],'cancelled')
 def controls_then_target(self,expected_nodes):
  with patch('detectors.boce',return_value={'data':{'id':'control'}}):recheck.tick(self.connect,self.cipher)
  result={'done':True,'list':[{'node_id':int(n),'packets_transmitted':1,'packets_received':1,'error_code':0} for n in expected_nodes]}
  def remote(secret,path,*args):
   if path=='task/create/tcping':return {'data':{'id':'target'}}
   return result
  with patch('detectors.boce',side_effect=remote):recheck.tick(self.connect,self.cipher)
 def test_self_to_boce_uses_confirmation_nodes_for_controls_and_target(self):
  a,b,rid=self.setup_cross('self','boce','3')
  self.controls_then_target(['3'])
  with self.connect() as db:db.execute('UPDATE detection_rechecks SET poll_at=0')
  result={'done':True,'list':[{'node_id':3,'packets_transmitted':1,'packets_received':0,'error_code':0}]}
  with patch('detectors.boce',return_value=result):recheck.tick(self.connect,self.cipher)
  self.assertEqual(self.commands(),1)
 def test_boce_to_self_controls_use_primary_nodes_only(self):
  a,b,rid=self.setup_cross('boce','self','self')
  self.controls_then_target(['1','2'])
  task=self.probe(b,'jobs').json['job'];self.assertEqual(task['id'],-rid)
  result=self.probe(b,'results/'+str(-rid),{'ip':'8.8.8.8','port':443,'reachable':False})
  self.assertEqual(result.status_code,200);self.assertEqual(self.commands(),1)
 def test_validation_deletion_and_minimum_interval(self):
  a=self.source('self');b=self.source('self')
  self.assertEqual(self.post('/plans/1',{'source_id':a['id'],'nodes':['self'],'confirm_node':'self'}).status_code,400)
  self.plan(a['id'],nodes=['self'],confirm_node='self',confirm_source_id=b['id'],interval_s=60)
  self.assertEqual(self.client.delete('/api/detection/sources/'+str(b['id']),headers=self.headers).status_code,400)
  self.assertEqual(self.post('/plans/1',{'source_id':a['id'],'nodes':['self'],'confirm_node':'self','confirm_source_id':999}).status_code,400)
  self.assertEqual(self.post('/plans/1',{'source_id':a['id'],'nodes':['self'],'interval_s':59}).status_code,400)


class CrossSourceSafety(unittest.TestCase):
 setUp=CrossSourceRecheck.setUp
 post=CrossSourceRecheck.post
 source=CrossSourceRecheck.source
 plan=CrossSourceRecheck.plan
 setup_cross=CrossSourceRecheck.setup_cross
 probe=CrossSourceRecheck.probe
 commands=CrossSourceRecheck.commands
 controls_then_target=CrossSourceRecheck.controls_then_target
 # Separate cases, without re-running the inherited integration scenarios.
 def test_external_source_credential_and_same_node_id_are_not_confused(self):
  a,b,rid=self.setup_cross('boce','boce','1')
  self.controls_then_target(['1','2'])
  with self.connect() as db:
   source=db.execute('SELECT * FROM detection_sources WHERE id=?',(b['id'],)).fetchone()
   expected=detectors.source_secret(source,self.cipher)
   db.execute('UPDATE detection_rechecks SET poll_at=0')
  def poll(secret,path,*args):
   self.assertEqual(secret,expected)
   return {'done':True,'list':[{'node_id':1,'packets_transmitted':1,'packets_received':1,'error_code':0}]}
  with patch('detectors.boce',side_effect=poll):recheck.tick(self.connect,self.cipher)
  self.assertEqual(self.commands(),0)
 def test_changed_confirm_credentials_discard_inflight_self_result(self):
  a,b,rid=self.setup_cross();recheck.tick(self.connect,self.cipher);self.probe(b,'jobs')
  with self.connect() as db:db.execute('UPDATE detection_sources SET secret=? WHERE id=?',(self.cipher.encrypt(b'new-token').decode(),b['id']))
  recheck.tick(self.connect,self.cipher)
  with self.connect() as db:self.assertEqual(db.execute('SELECT state FROM detection_rechecks').fetchone()[0],'cancelled')
  self.assertEqual(self.commands(),0)
 def test_expired_or_wrong_source_signed_job_cannot_trigger_action(self):
  a,b,rid=self.setup_cross();recheck.tick(self.connect,self.cipher);self.probe(b,'jobs')
  data={'ip':'8.8.8.8','port':443,'reachable':False}
  self.assertEqual(self.probe(a,'results/'+str(-rid),data).status_code,409)
  with self.connect() as db:db.execute('UPDATE detection_rechecks SET submitted=?',(int(time.time())-121,))
  self.assertEqual(self.probe(b,'results/'+str(-rid),data).status_code,409)
  recheck.tick(self.connect,self.cipher);self.assertEqual(self.commands(),0)


class ThirdPartyAndScheduling(unittest.TestCase):
 setUp=CrossSourceRecheck.setUp
 post=CrossSourceRecheck.post
 plan=CrossSourceRecheck.plan
 commands=CrossSourceRecheck.commands
 setup_cross=CrossSourceRecheck.setup_cross
 def source(self,kind='boce'):
  response=self.post('/sources',{'kind':kind,'name':kind,'secret':'' if kind=='self' else 'provider-token'})
  self.assertEqual(response.status_code,200)
  return response.json
 def test_self_to_baota_adapter_checks_control_sites_before_target(self):
  a,b,rid=self.setup_cross('self','baota','3')
  created=[]
  def create(secret,host,port,nodes,identity,reference=False):
   created.append((host,port,nodes,reference));return 'ref-'+host if reference else 'target'
  def poll(secret,remote,nodes):
   return [{'node_id':'3','state':'unreachable' if remote=='target' else 'reachable','latency_ms':None}]
  with patch('detectors.baota_probe.create',side_effect=create),patch('detectors.baota_probe.poll',side_effect=poll):
   recheck.tick(self.connect,self.cipher)
   recheck.tick(self.connect,self.cipher)
   with self.connect() as db:db.execute('UPDATE detection_rechecks SET poll_at=0')
   recheck.tick(self.connect,self.cipher)
  self.assertEqual({x[0] for x in created},{'www.qq.com','www.baidu.com','8.8.8.8'})
  self.assertEqual(self.commands(),1)
 def test_same_vps_cannot_overlap_a_pending_cross_recheck(self):
  self.setup_cross()
  with self.assertRaisesRegex(Exception,'独立复测进行中'):
   detectors.start_run(self.connect,self.cipher,1,scheduled=True)
 def test_unavailable_confirmation_source_does_not_drop_primary_result(self):
  a=self.source('self');b=self.source('self')
  self.plan(a['id'],nodes=['self'],automatic=True,confirm_node='self',confirm_source_id=b['id'])
  now=int(time.time())
  with self.connect() as db:
   db.execute('UPDATE detection_sources SET enabled=0 WHERE id=?',(b['id'],))
   rid=db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,scheduled,created,updated) VALUES(1,?,'8.8.8.8',443,'[\"self\"]','pending',1,?,?)",(a['id'],now,now)).lastrowid
   run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
   detectors.finish(db,run,'首轮不通',[{'node_id':'self','state':'unreachable'}])
   self.assertIn('复检来源不可用',db.execute('SELECT status FROM detection_plans').fetchone()[0])
  self.assertEqual(self.commands(),0)

if __name__=='__main__':unittest.main()
