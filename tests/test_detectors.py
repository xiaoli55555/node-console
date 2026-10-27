import importlib.util
import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch
from cryptography.fernet import Fernet
from flask import Flask,request
import detectors
from ip_dns import init_schema,IntegrationError

class DetectorTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);path=self.tmp.name+'/db';self.cipher=Fernet(Fernet.generate_key())
  @contextmanager
  def connect():
   db=sqlite3.connect(path);db.row_factory=sqlite3.Row;db.execute('PRAGMA foreign_keys=ON')
   try:
    with db:yield db
   finally:db.close()
  self.connect=connect
  with connect() as db:
   db.executescript('CREATE TABLE users(id INTEGER PRIMARY KEY,role TEXT); CREATE TABLE servers(id INTEGER PRIMARY KEY,name TEXT,metrics TEXT,seen INTEGER); CREATE TABLE commands(id INTEGER PRIMARY KEY,server_id INTEGER,user_id INTEGER,action TEXT,status TEXT,created INTEGER,updated INTEGER);')
   db.execute("INSERT INTO users VALUES(1,'admin')")
   db.execute('INSERT INTO servers VALUES(1,?,?,?)',('test',json.dumps({'public_ips':['8.8.8.8'],'capabilities':['reboot']}),int(time.time())))
  init_schema(connect);detectors.initialize(connect)
  with connect() as db:db.execute('INSERT INTO ip_monitors(server_id) VALUES(1)')
  def auth(admin=False):
   def wrap(fn):
    from functools import wraps
    @wraps(fn)
    def run(*args,**kwargs):
     if request.headers.get('X-Admin')!='yes':return {'error':'denied'},403
     return fn(*args,**kwargs)
    return run
   return wrap
  app=Flask(__name__);detectors.register(app,connect,self.cipher,auth,lambda:request.get_json(silent=True) or {},lambda m,status=400:({'error':m},status),lambda *a:None)
  self.client=app.test_client();self.headers={'X-Admin':'yes'}
 def post(self,p,d=None):return self.client.post('/api/detection'+p,json=d or {},headers=self.headers)
 def source(self,kind='boce'):
  r=self.post('/sources',{'kind':kind,'name':'test','secret':'testsecret' if kind=='boce' else ''});self.assertEqual(r.status_code,200);return r.json
 def plan(self,source,**kwargs):
  if kwargs.get('response_mode','none')!='none':
   with self.connect() as db:db.execute('UPDATE detection_sources SET verified_at=? WHERE id=?',(int(time.time()),source))
  r=self.post('/plans/1',{'source_id':source,'nodes':['1','2'],'interval_s':600,'daily_limit':1000,**kwargs});self.assertEqual(r.status_code,200,r.json)
 def test_secret_encryption_and_admin_only(self):
  self.source();self.assertEqual(self.client.get('/api/detection').status_code,403)
  data=self.client.get('/api/detection',headers=self.headers).text;self.assertNotIn('testsecret',data)
  with self.connect() as db:self.assertNotIn('testsecret',db.execute('SELECT secret FROM detection_sources').fetchone()[0])
 def test_boce_source_test_verifies_credentials_without_creating_a_run(self):
  source=self.source()
  with patch('detectors.boce',return_value={'data':{'list':[{'id':1},{'id':2}]}}) as boce:
   r=self.post('/sources/'+str(source['id'])+'/test')
  self.assertEqual(r.status_code,200,r.json);self.assertTrue(r.json['usable']);self.assertIn('2 个检测节点',r.json['message'])
  self.assertEqual(boce.call_args.args[1],'node/list')
  with self.connect() as db:
   self.assertIsNotNone(db.execute('SELECT verified_at FROM detection_sources WHERE id=?',(source['id'],)).fetchone()[0])
   self.assertEqual(db.execute('SELECT COUNT(*) FROM detection_runs').fetchone()[0],0)
 def test_monitor_status_returns_latest_per_plan_without_creating_tasks(self):
  source=self.source()['id'];self.plan(source)
  other=self.source()['id']
  with self.connect() as db:
   db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details) VALUES(1,?,'8.8.8.8',443,'[]','TCP 可达',1,2,?)",(source,json.dumps([{'node_id':'1','name':'广州','state':'reachable','latency_ms':12}])))
   # More recent runs for another source must not replace the configured source result.
   for i in range(55):db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated) VALUES(1,?,'1.1.1.1',443,'[]','其他来源',3,4)",(other,))
  with patch('detectors.boce') as upstream:
   response=self.client.get('/api/detection/monitor-status',headers=self.headers)
   upstream.assert_not_called()
  self.assertEqual(response.status_code,200)
  item=response.json['monitors'][0]
  self.assertEqual(item['run']['status'],'TCP 可达');self.assertEqual(item['run']['details'][0]['latency_ms'],12)
  self.assertNotIn('testsecret',response.text)
  self.assertEqual(self.client.get('/api/detection/monitor-status').status_code,403)

 def test_custom_probe_port_is_saved_and_sent_to_boce(self):
  source=self.source()['id'];self.plan(source,port=23456)
  with patch('detectors.boce',return_value={'data':{'id':'task123'}}) as call:detectors.start_run(self.connect,self.cipher,1)
  self.assertEqual(call.call_args.args[2]['host'],'8.8.8.8:23456')
  overview=self.client.get('/api/detection',headers=self.headers).json
  self.assertEqual(overview['plans'][0]['port'],23456)
  bad=self.post('/plans/1',{'source_id':source,'nodes':['1'],'port':0})
  self.assertEqual(bad.status_code,400)
 def test_old_port_result_does_not_update_reconfigured_plan(self):
  source=self.source()['id'];self.plan(source)
  with patch('detectors.boce',return_value={'data':{'id':'task123'}}):detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:
   db.execute('UPDATE ip_monitors SET port=23456 WHERE server_id=1')
   run=dict(db.execute('SELECT * FROM detection_runs').fetchone())
   detectors.finish(db,run,'old-port-result',[{'state':'unreachable'}])
   self.assertNotEqual(db.execute('SELECT status FROM detection_plans').fetchone()[0],'old-port-result')

 def test_boce_error_shows_safe_upstream_reason(self):
  with patch('detectors.request_json',return_value={'error_code':401,'error':'invalid API key: testsecret'}):
   with self.assertRaises(IntegrationError) as raised:detectors.boce('testsecret','node/list')
  self.assertIn('401',str(raised.exception));self.assertIn('invalid API key',str(raised.exception))
  self.assertNotIn('testsecret',str(raised.exception))
 def test_boce_sends_key_and_parameters_as_documented_query(self):
  with patch('detectors.request_json',return_value={'error_code':0}) as call:
   detectors.boce('testsecret','task/create/tcping',{'node_ids':'1,2','host':'8.8.8.8:443'})
  self.assertEqual(call.call_args.args[0],'https://api.boce.com/v3/task/create/tcping?key=testsecret&node_ids=1%2C2&host=8.8.8.8%3A443')
  self.assertEqual(len(call.call_args.args),1)
 def test_self_probe_test_uses_authenticated_heartbeat(self):
  source=self.source('self')
  r=self.post('/sources/'+str(source['id'])+'/test')
  self.assertEqual(r.status_code,400);self.assertIn('未在线',r.json['error'])
  heartbeat=self.client.post('/api/probe/jobs',json={},headers={'Authorization':'Bearer '+source['probe_token']})
  self.assertEqual(heartbeat.status_code,200)
  r=self.post('/sources/'+str(source['id'])+'/test')
  self.assertEqual(r.status_code,200,r.json);self.assertTrue(r.json['usable']);self.assertIn('在线',r.json['message'])
 def test_automatic_response_requires_recent_source_test(self):
  source=self.source()
  payload={'source_id':source['id'],'nodes':['1'],'automatic':True,'response_mode':'reboot'}
  self.assertEqual(self.post('/plans/1',payload).status_code,400)
  with patch('detectors.boce',return_value={'data':{'list':[{'id':1}]}}):self.assertEqual(self.post('/sources/'+str(source['id'])+'/test').status_code,200)
  self.assertEqual(self.post('/plans/1',payload).status_code,200)
 def test_boce_create_and_pending_not_a_failure(self):
  self.plan(self.source()['id'])
  with patch('detectors.boce',return_value={'data':{'id':'task123'}}) as call:
   rid=detectors.start_run(self.connect,self.cipher,1);self.assertEqual(call.call_args.args[1],'task/create/tcping');self.assertEqual(call.call_args.args[2]['host'],'8.8.8.8:443')
  with self.assertRaises(IntegrationError):detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:db.execute('UPDATE detection_runs SET poll_at=0')
  with patch('detectors.boce',return_value={'done':False}):detectors.tick(self.connect,self.cipher)
  with self.connect() as db:self.assertEqual(db.execute('SELECT status FROM detection_runs').fetchone()[0],'pending')
 def test_summary_incomplete_offline_and_zero_samples_unknown(self):
  for rows in [[],[{'node_id':1,'error':'not found node'}],[{'node_id':1,'packets_transmitted':0,'packets_received':0}]]:
   status,result=detectors.summarize(rows,['1']);self.assertEqual(result[0]['state'],'unknown')
  status,result=detectors.summarize([{'node_id':1,'error_code':0,'packets_transmitted':10,'packets_received':0}],['1']);self.assertEqual(result[0]['state'],'unreachable');self.assertIn('待复核',status)
 def test_source_switch_preserves_dns_and_ignores_old_result(self):
  first=self.source()['id'];self.plan(first)
  with patch('detectors.boce',return_value={'data':{'id':'abc'}}):detectors.start_run(self.connect,self.cipher,1)
  second=self.source('self')['id'];self.plan(second)
  with self.connect() as db:
   r=db.execute('SELECT * FROM detection_runs').fetchone();detectors.finish(db,r,'old result',[])
   self.assertNotEqual(db.execute('SELECT status FROM detection_plans').fetchone()[0],'old result')
   self.assertEqual(db.execute('SELECT COUNT(*) FROM dns_bindings').fetchone()[0],0)
 def test_daily_budget_blocks_creation(self):
  self.plan(self.source()['id'],daily_limit=1)
  with patch('detectors.boce') as call:
   with self.assertRaises(IntegrationError):detectors.start_run(self.connect,self.cipher,1)
   call.assert_not_called()
 def test_submission_failure_reason_is_persisted_visible_and_masks_key(self):
  self.plan(self.source()['id'])
  with patch('detectors.boce',side_effect=IntegrationError('BOCE 返回错误码 5：quota testsecret')):
   detectors.start_run(self.connect,self.cipher,1)
  result=self.client.get('/api/detection/monitor-status',headers=self.headers)
  self.assertIn('quota',result.json['monitors'][0]['run']['status'])
  self.assertNotIn('testsecret',result.text)
  with self.connect() as db:self.assertIn('quota',db.execute('SELECT status FROM detection_plans').fetchone()[0])
 def test_boce_wrapped_create_poll_and_error_responses(self):
  response={'code':200,'data':{'error_code':0,'error':'','data':{'id':'20261028_task_123'}}}
  with patch('detectors.request_json',return_value=response):
   data=detectors.boce('testsecret','task/create/tcping')
  self.assertEqual(data['data']['id'],'20261028_task_123')
  with patch('detectors.request_json',return_value={'code':200,'data':{'done':False,'id':'20261028_task_123','list':[]}}):
   self.assertIs(detectors.boce('testsecret','task/tcping/20261028_task_123')['done'],False)
  with patch('detectors.request_json',return_value={'code':200,'data':{'error_code':1,'error':'invalid testsecret'}}):
   with self.assertRaises(IntegrationError) as caught:detectors.boce('testsecret','task/create/tcping')
  self.assertNotIn('testsecret',str(caught.exception));self.assertIn('1',str(caught.exception))

 def test_task_ids_are_opaque_strings_and_encoded_when_polled(self):
  self.plan(self.source()['id'])
  with patch('detectors.boce',return_value={'data':{'id':'task-123_abc/part?x=1'}}):detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:db.execute('UPDATE detection_runs SET poll_at=0')
  with patch('detectors.boce',return_value={'done':False}) as call:detectors.tick(self.connect,self.cipher)
  self.assertEqual(call.call_args.args[1],'task/tcping/task-123_abc%2Fpart%3Fx%3D1')
  with self.connect() as db:self.assertEqual(db.execute('SELECT status FROM detection_runs').fetchone()[0],'pending')

 def test_malformed_task_response_is_recorded_without_crashing(self):
  self.plan(self.source()['id'])
  with patch('detectors.boce',return_value={'data':None}):detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:self.assertIn('BOCE 未返回有效任务 ID',db.execute('SELECT status FROM detection_runs').fetchone()[0])

 def test_ambiguous_submission_persists_cost_no_retry(self):
  self.plan(self.source()['id'])
  with patch('detectors.boce',side_effect=IntegrationError('timeout')):detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:
   r=db.execute('SELECT * FROM detection_runs').fetchone();self.assertEqual(r['cost'],2);self.assertIn('提交异常',r['status'])
  with self.assertRaises(IntegrationError):detectors.start_run(self.connect,self.cipher,1)
 def test_self_probe_auth_target_binding_replay_and_expiry(self):
  source=self.source('self');self.plan(source['id']);rid=detectors.start_run(self.connect,self.cipher,1)
  self.assertEqual(self.client.post('/api/probe/jobs',json={}).status_code,401)
  headers={'Authorization':'Bearer '+source['probe_token']}
  job=self.client.post('/api/probe/jobs',json={},headers=headers).json['job'];self.assertEqual(job['id'],rid)
  self.assertIsNone(self.client.post('/api/probe/jobs',json={},headers=headers).json['job'])
  result={'ip':'1.1.1.1','port':443,'reachable':True,'latency_ms':3}
  self.assertEqual(self.client.post('/api/probe/results/'+str(rid),json=result,headers=headers).status_code,409)
  result['ip']='8.8.8.8';self.assertEqual(self.client.post('/api/probe/results/'+str(rid),json=result,headers=headers).status_code,200)
  self.assertEqual(self.client.post('/api/probe/results/'+str(rid),json=result,headers=headers).status_code,409)
 def test_result_timeout_not_target_failure(self):
  self.plan(self.source('self')['id']);detectors.start_run(self.connect,self.cipher,1)
  with self.connect() as db:db.execute('UPDATE detection_runs SET created=1')
  detectors.tick(self.connect,self.cipher)
  with self.connect() as db:self.assertIn('不能判定',db.execute('SELECT status FROM detection_runs').fetchone()[0])
 def test_boce_nodes_request_uses_default_mainland(self):
  sid=self.source()['id']
  with patch('detectors.boce',return_value={'data':{'list':[{'id':6,'node_name':'河北','isp_name':'电信'}]}}) as call:
   r=self.post('/sources/'+str(sid)+'/nodes');self.assertEqual(r.json['nodes'][0]['id'],'6');self.assertEqual(call.call_args.args[1],'node/list')

 def test_automatic_reboot_requires_consecutive_scheduled_complete_failures(self):
  source=self.source('self')['id'];self.plan(source,automatic=True,response_mode='reboot',failure_threshold=2)
  rows=[{'node_id':'self','name':'probe','state':'unreachable','latency_ms':None}]
  for run_id in (1,2):
   with self.connect() as db:
    db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,scheduled) VALUES(1,?,'8.8.8.8',443,'[\"self\"]','检测中',?,?,1)",(source,int(time.time()),int(time.time())))
    run=dict(db.execute('SELECT * FROM detection_runs WHERE id=?',(run_id,)).fetchone())
    detectors.finish(db,run,'自建探针 TCP 不通（待复核）',rows)
  with self.connect() as db:
   self.assertEqual(db.execute("SELECT COUNT(*) FROM commands WHERE action='reboot' AND status='queued'").fetchone()[0],1)
   self.assertIn('已排队自动重启',db.execute('SELECT action_result FROM detection_runs WHERE id=2').fetchone()[0])
   self.assertEqual(db.execute('SELECT failure_streak FROM detection_plans').fetchone()[0],0)

 def test_manual_or_incomplete_detection_never_reboots_and_resets_streak(self):
  source=self.source('self')['id'];self.plan(source,automatic=True,response_mode='reboot',failure_threshold=2)
  with self.connect() as db:
   db.execute('UPDATE detection_plans SET failure_streak=1')
   db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,scheduled) VALUES(1,?,'8.8.8.8',443,'[\"self\"]','检测中',?,?,0)",(source,int(time.time()),int(time.time())))
   run=dict(db.execute('SELECT * FROM detection_runs').fetchone())
   detectors.finish(db,run,'检测异常或结果不完整',[{'node_id':'self','state':'unknown'}])
   self.assertEqual(db.execute('SELECT failure_streak FROM detection_plans').fetchone()[0],1)
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)
  with self.connect() as db:
   db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,scheduled) VALUES(1,?,'8.8.8.8',443,'[\"self\"]','检测中',?,?,1)",(source,int(time.time()),int(time.time())))
   run=dict(db.execute('SELECT * FROM detection_runs ORDER BY id DESC LIMIT 1').fetchone())
   detectors.finish(db,run,'检测异常或结果不完整',[{'node_id':'self','state':'unknown'}])
   self.assertEqual(db.execute('SELECT failure_streak FROM detection_plans').fetchone()[0],0)
   self.assertEqual(db.execute('SELECT COUNT(*) FROM commands').fetchone()[0],0)

 def test_auto_reboot_requires_timer_and_valid_threshold(self):
  source=self.source('self')['id']
  r=self.post('/plans/1',{'source_id':source,'nodes':['self'],'interval_s':600,'daily_limit':1000,'automatic':False,'response_mode':'reboot','failure_threshold':3})
  self.assertEqual(r.status_code,400)
  r=self.post('/plans/1',{'source_id':source,'nodes':['self'],'interval_s':600,'daily_limit':1000,'automatic':True,'response_mode':'reboot','failure_threshold':1})
  self.assertEqual(r.status_code,400)

 def test_queued_change_ip_is_cancelled_after_monitor_port_changes(self):
  source=self.source()['id']
  with self.connect() as db:
   action=db.execute('INSERT INTO ip_connections(name,kind,config,secret) VALUES(?,?,?,?)',('dry-run','change_ip','{}',self.cipher.encrypt(b'dummy').decode())).lastrowid
  self.plan(source,automatic=True,response_mode='change_api',action_connection_id=action)
  with self.connect() as db:
   db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,scheduled,action_status) VALUES(1,?,'8.8.8.8',443,'[]','failed',?,?,1,'queued')",(source,int(time.time()),int(time.time())))
   db.execute('UPDATE ip_monitors SET port=23456 WHERE server_id=1')
  with patch('detectors.invoke_change_ip_api') as api:
   detectors.execute_change_ip_actions(self.connect,self.cipher)
   api.assert_not_called()
  with self.connect() as db:self.assertEqual(db.execute('SELECT action_status FROM detection_runs').fetchone()[0],'cancelled')

 def test_change_ip_api_runs_once_after_confirmed_scheduled_failures(self):
  source=self.source('self')['id']
  with self.connect() as db:
   encrypted=self.cipher.encrypt(b'api-token').decode()
   action_id=db.execute('INSERT INTO ip_connections(name,kind,config,secret) VALUES(?,?,?,?)',('provider','change_ip',json.dumps({'url':'https://provider.example/change','header':'Authorization','prefix':'Bearer ','body_json':'{}'}),encrypted)).lastrowid
  self.plan(source,automatic=True,response_mode='change_api',action_connection_id=action_id,failure_threshold=2)
  rows=[{'node_id':'self','name':'probe','state':'unreachable','latency_ms':None}]
  for run_id in (1,2):
   with self.connect() as db:
    db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,scheduled) VALUES(1,?,'8.8.8.8',443,'[\"self\"]','检测中',?,?,1)",(source,int(time.time()),int(time.time())))
    run=dict(db.execute('SELECT * FROM detection_runs WHERE id=?',(run_id,)).fetchone())
    detectors.finish(db,run,'自建探针 TCP 不通（待复核）',rows)
  with self.connect() as db:self.assertEqual(db.execute('SELECT action_status FROM detection_runs WHERE id=2').fetchone()[0],'queued')
  with patch('detectors.invoke_change_ip_api',return_value='submitted') as call:
   detectors.execute_change_ip_actions(self.connect,self.cipher)
   detectors.execute_change_ip_actions(self.connect,self.cipher)
  self.assertEqual(call.call_count,1)
  with self.connect() as db:self.assertEqual(db.execute('SELECT action_status FROM detection_runs WHERE id=2').fetchone()[0],'submitted')

 def test_initialize_adds_response_columns_to_existing_database(self):
  path=self.tmp.name+'/legacy-db'
  @contextmanager
  def legacy_connect():
   db=sqlite3.connect(path);db.row_factory=sqlite3.Row
   try:
    with db:yield db
   finally:db.close()
  with legacy_connect() as db:
   db.executescript('''CREATE TABLE servers(id INTEGER PRIMARY KEY); CREATE TABLE detection_sources(id INTEGER PRIMARY KEY,name TEXT,kind TEXT,secret TEXT,enabled INTEGER); CREATE TABLE detection_plans(server_id INTEGER PRIMARY KEY,source_id INTEGER,nodes TEXT,interval_s INTEGER,automatic INTEGER,daily_limit INTEGER,next_at INTEGER,status TEXT,checked INTEGER); CREATE TABLE detection_runs(id INTEGER PRIMARY KEY,server_id INTEGER,source_id INTEGER,ip TEXT,port INTEGER,nodes TEXT,status TEXT,remote_id TEXT,created INTEGER,updated INTEGER,details TEXT,poll_at INTEGER,cost INTEGER);''')
   db.execute("INSERT INTO detection_sources VALUES(1,'legacy','self','secret',1)")
   db.execute("INSERT INTO detection_plans VALUES(1,1,'[\"self\"]',600,0,1000,0,'等待检测',NULL)")
   db.execute("INSERT INTO detection_runs VALUES(1,1,1,'8.8.8.8',443,'[\"self\"]','done',NULL,1,1,'[]',0,0)")
  detectors.initialize(legacy_connect)
  with legacy_connect() as db:
   plan=db.execute('SELECT * FROM detection_plans').fetchone();run=db.execute('SELECT * FROM detection_runs').fetchone()
   self.assertEqual(plan['response_mode'],'none');self.assertEqual(plan['failure_threshold'],3);self.assertEqual(plan['nodes'],'["self"]')
   self.assertEqual(run['scheduled'],0);self.assertIsNone(run['action_result']);self.assertEqual(run['status'],'done')
