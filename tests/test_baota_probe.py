import json
import time
import unittest
from unittest.mock import patch
import baota_probe as provider
import detectors
import test_detectors as fixtures
from ip_dns import IntegrationError,boce_dns_gate

KEY='tbt_test_private_key'
NODES={'status':0,'list':[{'id':7,'node_name':'深圳','isp_name':'移动','isp_code':3},
                         {'id':8,'node_name':'香港','isp_name':'港澳台','isp_code':8}]}
def packet(received=1):
 return {'node_id':7,'node_name':'深圳移动','error_code':0,'packets_transmitted':3,
         'packets_received':received,'round_trip_avg':12}

class ProviderTest(unittest.TestCase):
 def test_nodes_use_city_endpoint_and_filter_overseas(self):
  with patch('baota_probe.request_json',return_value=NODES) as request:
   self.assertEqual(provider.nodes(KEY),[{'id':'7','name':'深圳','isp':'移动'}])
  self.assertIn('/nodes?',request.call_args.args[0]);self.assertIn('area=city',request.call_args.args[0])
 def test_create_uses_post_separate_port_and_idempotency(self):
  with patch('baota_probe.nodes',return_value=[{'id':'7'}]),patch('baota_probe.request_json',return_value={'error_code':0,'data':{'id':'v2-task'}}) as request:
   self.assertEqual(provider.create(KEY,'8.8.8.8',59218,['7'],1),'v2-task')
  from urllib.parse import parse_qs,urlsplit
  args=request.call_args;query=parse_qs(urlsplit(args.args[0]).query)
  self.assertEqual(query['host'],['8.8.8.8']);self.assertEqual(query['port'],['59218'])
  self.assertEqual(query['node_ids'],['7']);self.assertEqual(args.kwargs['method'],'POST')
  self.assertIn('X-Idempotency-Key',args.args[1]);request.assert_called_once()
 def test_invalid_targets_and_nodes_never_submit(self):
  for ip,port,selected in [('127.0.0.1',443,['7']),('8.8.8.8',True,['7']),('8.8.8.8',443,['../7']),('8.8.8.8',443,[])]:
   with patch('baota_probe.request_json') as request,self.assertRaises(IntegrationError):provider.create(KEY,ip,port,selected,1)
   request.assert_not_called()
  with patch('baota_probe.nodes',return_value=[{'id':'8'}]),patch('baota_probe.call') as call,self.assertRaises(IntegrationError):provider.create(KEY,'8.8.8.8',443,['7'],1)
  call.assert_not_called()
 def test_api_failure_redacts_key_and_requires_explicit_success(self):
  for data in ({'error_code':403,'error':'bad '+KEY},{'done':True},{'error_code':False}):
   with patch('baota_probe.request_json',return_value=data),self.assertRaises(IntegrationError) as error:provider.call(KEY,'tasks/tcp')
   self.assertNotIn(KEY,str(error.exception))
 def test_poll_requires_matching_id_and_done(self):
  with patch('baota_probe.call',return_value={'id':'v2-task','done':False}):self.assertIsNone(provider.poll(KEY,'v2-task',['7']))
  for data in ({'id':'other','done':True,'list':[packet()]},{'id':'v2-task','done':'true','list':[packet()]}):
   with patch('baota_probe.call',return_value=data),self.assertRaises(IntegrationError):provider.poll(KEY,'v2-task',['7'])
 def test_packet_results_and_missing_offline_malformed_evidence(self):
  for row,state in [(packet(),'reachable'),(packet(0),'unreachable'),({**packet(0),'error_code':500},'unknown'),({**packet(),'packets_received':True},'unknown'),({'node_id':7,'status':'failed','error':{'code':'NODE_OFFLINE'}},'unknown')]:
   self.assertEqual(provider.summarize([row],['7'])[0]['state'],state)
  self.assertEqual(provider.summarize([],['7'])[0]['state'],'unknown')
  self.assertEqual(provider.summarize(['节点结果'],['7'])[0]['state'],'unknown')
  with self.assertRaises(IntegrationError):provider.summarize([packet(),packet()],['7'])
 def test_structured_success_and_explicit_connect_failure(self):
  for status,opened,error,state in [('succeeded',True,None,'reachable'),('failed',False,{'code':'TCP_CONNECT_FAILED'},'unreachable'),('failed',False,{'code':'TCP_TARGET_INVALID'},'unknown'),('succeeded','true',None,'unknown')]:
   row={'node_id':7,'status':status,'tcp':{'open':opened},'error':error}
   self.assertEqual(provider.summarize([row],['7'])[0]['state'],state)

class IntegrationTest(unittest.TestCase):
 setUp=fixtures.DetectorTest.setUp
 post=fixtures.DetectorTest.post
 plan=fixtures.DetectorTest.plan
 def source(self):
  r=self.post('/sources',dict(kind='baota',name='宝塔TCP',secret=KEY));self.assertEqual(r.status_code,200,r.json);return r.json['id']
 def test_lifecycle_encryption_budget_and_dns_gate(self):
  source=self.source()
  with self.connect() as db:self.assertNotIn(KEY,db.execute('SELECT secret FROM detection_sources WHERE id=?',(source,)).fetchone()[0])
  with patch('baota_probe.nodes',return_value=[{'id':'7','name':'深圳','isp':'移动'}]),patch('baota_probe.create') as create:
   self.assertEqual(self.post('/sources/'+str(source)+'/test').status_code,200)
   self.assertEqual(self.post('/sources/'+str(source)+'/nodes').status_code,200);create.assert_not_called()
  self.plan(source,nodes=['7'],port=59218)
  with patch('baota_probe.create',return_value='v2-task') as create:
   rid=detectors.start_run(self.connect,self.cipher,1)
   self.assertEqual(create.call_args.args[2:4],(59218,['7']))
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT cost FROM detection_runs WHERE id=?',(rid,)).fetchone()[0],1)
   db.execute('UPDATE detection_runs SET poll_at=0 WHERE id=?',(rid,))
  with patch('baota_probe.poll',return_value=provider.summarize([packet()],['7'])):detectors.tick(self.connect,self.cipher)
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT status FROM detection_runs WHERE id=?',(rid,)).fetchone()[0],'宝塔 TCP 可达')
   self.assertIsNone(boce_dns_gate(db,1,'8.8.8.8',59218))
  self.assertNotIn(KEY,json.dumps(self.client.get('/api/detection',headers=self.headers).json))
 def test_submission_failure_not_retried(self):
  source=self.source();self.plan(source,nodes=['7'])
  with patch('baota_probe.create',side_effect=IntegrationError('response lost')) as create:
   rid=detectors.start_run(self.connect,self.cipher,1);detectors.tick(self.connect,self.cipher)
   create.assert_called_once()
  with self.connect() as db:
   self.assertIn('不自动重试',db.execute('SELECT status FROM detection_runs WHERE id=?',(rid,)).fetchone()[0])
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_five_minute_timeout_does_not_infer_target_failure(self):
  source=self.source();self.plan(source,nodes=['7'])
  with patch('baota_probe.create',return_value='v2-task'):rid=detectors.start_run(self.connect,self.cipher,1)
  now=int(time.time())
  with self.connect() as db:db.execute('UPDATE detection_runs SET created=?,poll_at=0 WHERE id=?',(now-180,rid))
  with patch('baota_probe.poll',return_value=None):detectors.tick(self.connect,self.cipher)
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT status FROM detection_runs WHERE id=?',(rid,)).fetchone()[0],'pending')
   db.execute('UPDATE detection_runs SET created=? WHERE id=?',(now-301,rid))
  detectors.tick(self.connect,self.cipher)
  with self.connect() as db:self.assertIn('不能判定目标不通',db.execute('SELECT status FROM detection_runs WHERE id=?',(rid,)).fetchone()[0])
 def test_all_selected_nodes_required_for_dns(self):
  source=self.source();self.plan(source,nodes=['7','9'])
  with patch('baota_probe.create',return_value='v2-task'):rid=detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:db.execute('UPDATE detection_runs SET poll_at=0 WHERE id=?',(rid,))
  with patch('baota_probe.poll',return_value=provider.summarize([packet()],['7','9'])):detectors.tick(self.connect,self.cipher)
  with self.connect() as db:
   self.assertIsNotNone(boce_dns_gate(db,1,'8.8.8.8',443))
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_confirmed_scheduled_failures_record_incident_and_queue_one_reboot(self):
  source=self.source();self.plan(source,nodes=['7'],automatic=True,response_mode='reboot',failure_threshold=2)
  for cycle in range(2):
   with self.connect() as db:db.execute('UPDATE detection_plans SET next_at=0 WHERE server_id=1')
   with patch('baota_probe.create',return_value='v2-task'):rid=detectors.start_run(self.connect,self.cipher,1,scheduled=True)
   with self.connect() as db:db.execute('UPDATE detection_runs SET poll_at=0 WHERE id=?',(rid,))
   with patch('baota_probe.poll',return_value=provider.summarize([packet(0)],['7'])):detectors.tick(self.connect,self.cipher)
   with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],cycle)
  with self.connect() as db:
   incident=db.execute('SELECT * FROM detection_incidents WHERE confirmed_at IS NOT NULL').fetchone()
   self.assertEqual(incident['source_id'],source);self.assertEqual(incident['ip'],'8.8.8.8')
 def test_manual_failed_result_does_not_reboot(self):
  source=self.source();self.plan(source,nodes=['7'],automatic=True,response_mode='reboot',failure_threshold=2)
  for cycle in range(3):
   with self.connect() as db:db.execute('UPDATE detection_plans SET next_at=0 WHERE server_id=1')
   with patch('baota_probe.create',return_value='v2-task'):rid=detectors.start_run(self.connect,self.cipher,1)
   with self.connect() as db:db.execute('UPDATE detection_runs SET poll_at=0 WHERE id=?',(rid,))
   with patch('baota_probe.poll',return_value=provider.summarize([packet(0)],['7'])):detectors.tick(self.connect,self.cipher)
  with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_budget_blocks_before_provider_submission(self):
  source=self.source();self.plan(source,nodes=['7'],daily_limit=1)
  with patch('baota_probe.create',return_value='v2-task'):rid=detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:db.execute("UPDATE detection_runs SET status='completed' WHERE id=?",(rid,))
  with patch('baota_probe.create') as create,self.assertRaises(IntegrationError):detectors.start_run(self.connect,self.cipher,1)
  create.assert_not_called()
