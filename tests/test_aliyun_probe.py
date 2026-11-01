import json
import time
import unittest
from unittest.mock import patch
import aliyun_probe as provider
import detectors
import test_detectors as fixtures
from ip_dns import IntegrationError

SECRET=json.dumps({'access_key_id':'test-access-key','access_key_secret':'test-secret-value'})
NODE={'City':'546','Isp':'232','Country.en':'China','CityName.en':'Beijing','IspName.en':'China-Unicom'}

def log(code=0,node='546:232',task='remote1'):
 city,isp=node.split(':')
 return dict(taskId=task,city=city,isp=isp,errorCode=code,tcpConnectTime=15,taskEndTimestamp=int(time.time()*1000))

class ProviderTest(unittest.TestCase):
 def test_signing_and_no_secret_in_errors(self):
  with patch('aliyun_probe.request_json',return_value={'Success':'true','Code':'200'}) as request:
   provider.call(SECRET,'DescribeSiteMonitorISPCityList')
  from urllib.parse import parse_qs
  url,headers,payload=request.call_args.args
  fields=parse_qs(payload)
  self.assertEqual(url,'https://metrics.cn-hangzhou.aliyuncs.com/')
  self.assertEqual(fields['Version'],['2019-01-01'])
  self.assertIn('Signature',fields);self.assertNotIn('test-secret-value',payload)
  with patch('aliyun_probe.request_json',side_effect=IntegrationError(SECRET)):
   with self.assertRaises(IntegrationError) as error:provider.call(SECRET,'X')
  self.assertNotIn('test-secret-value',str(error.exception))
 def test_nodes_only_mainland(self):
  with patch('aliyun_probe.call',return_value={'IspCityList':{'IspCity':[NODE,{**NODE,'Country.en':'Japan'}]}}):
   self.assertEqual(provider.nodes(SECRET),[{'id':'546:232','name':'Beijing','isp':'China-Unicom'}])
 def test_create_selects_only_explicit_idc_nodes(self):
  with patch('aliyun_probe.nodes',return_value=[{'id':'546:232'}]),patch('aliyun_probe.call',return_value={'CreateResultList':[{'TaskId':'remote1'}]}) as call:
   self.assertEqual(provider.create(SECRET,'8.8.8.8',50332,['546:232'],12),'remote1')
  args=call.call_args.kwargs
  self.assertEqual(args['TaskType'],'TCP');self.assertEqual(args['AgentGroup'],'PC')
  self.assertEqual(json.loads(args['OptionsJson']),{'port':50332})
  self.assertEqual(json.loads(args['IspCities']),[{'city':'546','isp':'232','type':'IDC'}])
  self.assertNotIn('RandomIspCity',args)
 def test_poll_conservative_and_complete(self):
  for code,state in [(0,'reachable'),(611,'unreachable'),(610,'unknown'),(550,'unknown'),(None,'unknown'),(999,'unknown')]:
   with self.subTest(code=code),patch('aliyun_probe.call',return_value={'Data':json.dumps([log(code)])}):
    self.assertEqual(provider.poll(SECRET,'remote1',['546:232'],int(time.time())-1)[0]['state'],state)
  for data in [{'Data':[]},{'Data':[log(task='wrong')]},{'Data':[log()],'NextToken':'more'}]:
   with patch('aliyun_probe.call',return_value=data):self.assertIsNone(provider.poll(SECRET,'remote1',['546:232'],int(time.time())-1))
  with patch('aliyun_probe.call',return_value={'Data':[log(611),log(0)]}):
   self.assertEqual(provider.poll(SECRET,'remote1',['546:232'],int(time.time())-1)[0]['state'],'reachable')

class IntegrationTest(fixtures.DetectorTest):
 def aliyun_source(self):
  response=self.post('/sources',dict(kind='aliyun',name='阿里云',secret=SECRET))
  self.assertEqual(response.status_code,200,response.json)
  return response.json['id']
 def test_aliyun_lifecycle_budget_and_auth(self):
  source=self.aliyun_source()
  with self.connect() as db:
   encrypted=db.execute('SELECT secret FROM detection_sources WHERE id=?',(source,)).fetchone()[0]
   self.assertNotIn('test-secret-value',encrypted)
  listing=self.client.get('/api/detection',headers=self.headers).json
  self.assertNotIn('test-secret-value',json.dumps(listing))
  with patch('aliyun_probe.nodes',return_value=[{'id':'546:232','name':'北京','isp':'联通'}]):
   self.assertEqual(self.post('/sources/'+str(source)+'/test').status_code,200)
   self.assertEqual(self.post('/sources/'+str(source)+'/nodes').status_code,200)
  self.plan(source,nodes=['546:232'],interval_s=120,port=50332)
  with patch('aliyun_probe.create',return_value='remote1') as create:
   rid=detectors.start_run(self.connect,self.cipher,1)
   self.assertEqual(create.call_count,1)
   with self.assertRaises(IntegrationError):detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:
   run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
   self.assertEqual(run['cost'],1);self.assertEqual(run['status'],'pending')
   db.execute('UPDATE detection_runs SET poll_at=0 WHERE id=?',(rid,))
  with patch('aliyun_probe.poll',return_value=[{'node_id':'546:232','name':'北京联通','state':'reachable','latency_ms':15}]):detectors.tick(self.connect,self.cipher)
  with self.connect() as db:
   run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
   self.assertIn('可达',run['status'])
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
  self.assertEqual(self.client.post('/api/detection/sources/'+str(source)+'/nodes',json={}).status_code,403)
 def test_unknown_timeout_and_submission_error_do_not_act(self):
  source=self.aliyun_source();self.plan(source,nodes=['546:232'])
  with patch('aliyun_probe.create',side_effect=IntegrationError('timeout')) as create:
   rid=detectors.start_run(self.connect,self.cipher,1)
   self.assertEqual(create.call_count,1)
  with self.connect() as db:
   self.assertIn('不自动重试',db.execute('SELECT status FROM detection_runs WHERE id=?',(rid,)).fetchone()[0])
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_reject_invalid_nodes_and_unverified_automatic_actions(self):
  source=self.aliyun_source()
  self.assertEqual(self.post('/plans/1',dict(source_id=source,nodes=['1'])).status_code,400)
  self.assertEqual(self.post('/sources',dict(kind='aliyun',name='bad',secret='not-json')).status_code,400)
  with self.connect() as db:db.execute('UPDATE detection_sources SET verified_at=? WHERE id=?',(int(time.time()),source))
  self.assertEqual(self.post('/plans/1',dict(source_id=source,nodes=['546:232'],automatic=True,response_mode='reboot')).status_code,400)

if __name__=='__main__':unittest.main()
