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
 def test_http_and_business_errors_include_safe_diagnostics(self):
  from ip_dns import UpstreamHTTPError
  for status in (400,403,429,500,200):
   data={'Code':'InvalidQueryParameter','Message':'TaskType does not exists test-secret-value test-access-key',
         'RequestId':'req-123','Recommend':'https://example.com/secret'}
   with self.subTest(status=status):
    options={'return_value':data} if status==200 else {'side_effect':UpstreamHTTPError(status,data)}
    with patch('aliyun_probe.request_json',**options),self.assertRaises(IntegrationError) as caught:
     provider.call(SECRET,'CreateInstantSiteMonitor')
    message=str(caught.exception)
    for expected in ('CreateInstantSiteMonitor','HTTP '+str(status),'InvalidQueryParameter','req-123','TaskType does not exists'):
     self.assertIn(expected,message)
    for hidden in ('test-secret-value','test-access-key','https://example.com'):
     self.assertNotIn(hidden,message)
 def test_non_json_http_error_retains_status_without_echoing_body(self):
  from ip_dns import UpstreamHTTPError
  with patch('aliyun_probe.request_json',side_effect=UpstreamHTTPError(502)),self.assertRaises(IntegrationError) as caught:
   provider.call(SECRET,'DescribeSiteMonitorLog')
  self.assertIn('HTTP 502',str(caught.exception))
  self.assertIn('DescribeSiteMonitorLog',str(caught.exception))
 def test_transport_preserves_only_known_safe_reason(self):
  reason='API 地址必须解析到公网地址'
  with patch('aliyun_probe.request_json',side_effect=IntegrationError(reason)),self.assertRaises(IntegrationError) as caught:
   provider.call(SECRET,'CreateInstantSiteMonitor')
  self.assertIn(reason,str(caught.exception));self.assertIn('HTTP 未取得',str(caught.exception))
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
  for code,state in [(0,'reachable'),(0.0,'reachable'),('0','reachable'),(False,'unknown'),(611.0,'unreachable'),(611,'unreachable'),(610,'unknown'),(550,'unknown'),(None,'unknown'),(999,'unknown')]:
   with self.subTest(code=code),patch('aliyun_probe.call',return_value={'Data':json.dumps([log(code)])}):
    self.assertEqual(provider.poll(SECRET,'remote1',['546:232'],int(time.time())-1)[0]['state'],state)
  for data in [{'Data':[]},{'Data':[log(task='wrong')]},{'Data':[log()],'NextToken':'more'}]:
   with patch('aliyun_probe.call',return_value=data):self.assertIsNone(provider.poll(SECRET,'remote1',['546:232'],int(time.time())-1))
  with patch('aliyun_probe.call',return_value={'Data':[log(611),log(0)]}):
   self.assertEqual(provider.poll(SECRET,'remote1',['546:232'],int(time.time())-1)[0]['state'],'reachable')

class IntegrationTest(unittest.TestCase):
 setUp=fixtures.DetectorTest.setUp
 post=fixtures.DetectorTest.post
 plan=fixtures.DetectorTest.plan
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
 def test_poll_error_is_visible_without_becoming_unreachable(self):
  source=self.aliyun_source();self.plan(source,nodes=['546:232'])
  with patch('aliyun_probe.create',return_value='remote1'):
   rid=detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:db.execute('UPDATE detection_runs SET poll_at=0 WHERE id=?',(rid,))
  reason='阿里云 DescribeSiteMonitorLog；HTTP 403；Code=Forbidden；RequestId=req-456'
  with patch('aliyun_probe.poll',side_effect=IntegrationError(reason)):detectors.tick(self.connect,self.cipher)
  with self.connect() as db:
   row=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
   self.assertIn(reason,row['status']);self.assertEqual(json.loads(row['details']),[])
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
 def test_reject_invalid_nodes_and_unverified_automatic_actions(self):
  source=self.aliyun_source()
  self.assertEqual(self.post('/plans/1',dict(source_id=source,nodes=['1'])).status_code,400)
  self.assertEqual(self.post('/sources',dict(kind='aliyun',name='bad',secret='not-json')).status_code,400)
  with self.connect() as db:db.execute('UPDATE detection_sources SET verified_at=? WHERE id=?',(int(time.time()),source))
  self.assertEqual(self.post('/plans/1',dict(source_id=source,nodes=['546:232'],automatic=True,response_mode='reboot')).status_code,400)

if __name__=='__main__':unittest.main()

class RobustnessTest(unittest.TestCase):
 def test_bad_payloads_fail_safely(self):
  for secret in ['null','[]','{}','bad',json.dumps({'access_key_id':False,'access_key_secret':'abcdefgh'})]:
   with self.subTest(secret=secret),self.assertRaises(IntegrationError):provider.credentials(secret)
  for data in [{'IspCityList':None},{'IspCityList':[]},{'IspCityList':{'IspCity':'bad'}}]:
   with patch('aliyun_probe.call',return_value=data),self.assertRaises(IntegrationError):provider.nodes(SECRET)
  for raw in ['bad','{}',None]:
   with patch('aliyun_probe.call',return_value={'Data':raw}),self.assertRaises(IntegrationError):provider.poll(SECRET,'remote1',['546:232'],1)
 def test_stale_missing_and_foreign_logs_never_complete(self):
  for rows in [[{**log(), 'taskEndTimestamp':1}],[log(node='1:2')],[log()], [{**log(),'taskEndTimestamp':float('nan')}]]:
   with patch('aliyun_probe.call',return_value={'Data':rows}):
    self.assertIsNone(provider.poll(SECRET,'remote1',['546:232','572:232'],int(time.time())-1))
 def test_raw_latency_not_mislabelled_as_ms(self):
  with patch('aliyun_probe.call',return_value={'Data':[log()]}):
   row=provider.poll(SECRET,'remote1',['546:232'],int(time.time())-1)[0]
   self.assertIsNone(row['latency_ms']);self.assertEqual(row['raw_tcp_connect_time'],15)
 def test_invalid_or_unavailable_target_does_not_create_billable_task(self):
  for ip,port,selected in [('127.0.0.1',443,['546:232']),('8.8.8.8',True,['546:232']),('8.8.8.8',0,['546:232']),('8.8.8.8',443,[])]:
   with patch('aliyun_probe.call') as call,self.assertRaises(IntegrationError):provider.create(SECRET,ip,port,selected,1)
   call.assert_not_called()
  with patch('aliyun_probe.nodes',return_value=[{'id':'1:2'}]),patch('aliyun_probe.call') as call,self.assertRaises(IntegrationError):
   provider.create(SECRET,'8.8.8.8',443,['546:232'],1)
  call.assert_not_called()

class OperationalTest(IntegrationTest):
 def test_daily_budget_and_pending_expiry(self):
  source=self.aliyun_source();self.plan(source,nodes=['546:232'],daily_limit=1)
  with patch('aliyun_probe.create',return_value='remote1'):rid=detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:db.execute('UPDATE detection_runs SET created=?,poll_at=0 WHERE id=?',(int(time.time())-130,rid))
  with patch('aliyun_probe.poll') as poll:detectors.tick(self.connect,self.cipher)
  poll.assert_not_called()
  with self.connect() as db:
   run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
   self.assertIn('不能判定目标不通',run['status']);self.assertEqual(json.loads(run['details']),[])
   db.execute('UPDATE detection_plans SET next_at=0 WHERE server_id=1')
  with patch('aliyun_probe.create') as create,self.assertRaises(IntegrationError):detectors.start_run(self.connect,self.cipher,1)
  create.assert_not_called()
 def test_stale_result_does_not_replace_reconfigured_plan(self):
  source=self.aliyun_source();self.plan(source,nodes=['546:232'],port=443)
  with patch('aliyun_probe.create',return_value='remote1'):rid=detectors.start_run(self.connect,self.cipher,1)
  self.plan(source,nodes=['572:232'],port=50332)
  with self.connect() as db:db.execute('UPDATE detection_runs SET poll_at=0 WHERE id=?',(rid,))
  with patch('aliyun_probe.poll',return_value=[{'node_id':'546:232','name':'old','state':'unreachable','latency_ms':None}]):detectors.tick(self.connect,self.cipher)
  with self.connect() as db:
   self.assertEqual(db.execute('SELECT status FROM detection_plans WHERE server_id=1').fetchone()[0],'等待新配置检测')
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)

class HTTPErrorBodyTest(unittest.TestCase):
 def test_pinned_transport_retains_only_selected_json_fields(self):
  from unittest.mock import MagicMock
  import ip_dns
  for body in (json.dumps({'Code':'Forbidden','Message':'denied','RequestId':'req','secret':'hidden'}).encode(),b'<html>failure</html>'):
   conn=MagicMock();response=conn.getresponse.return_value
   response.status=403;response.read.return_value=body
   with patch('ip_dns.socket.getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443))]),patch('ip_dns.socket.create_connection'),patch('ip_dns.ssl.create_default_context'),patch('ip_dns.http.client.HTTPSConnection',return_value=conn):
    with self.assertRaises(ip_dns.UpstreamHTTPError) as caught:ip_dns.request_json('https://example.com/')
   error=caught.exception
   self.assertEqual(error.status,403);self.assertNotIn('hidden',str(error));self.assertNotIn('secret',error.details)
   if body.startswith(b'{'):self.assertEqual(error.details['RequestId'],'req')
   else:self.assertEqual(error.details,{})
   conn.close.assert_called_once()
