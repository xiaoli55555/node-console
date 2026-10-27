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
   db.executescript('CREATE TABLE servers(id INTEGER PRIMARY KEY,name TEXT,metrics TEXT,seen INTEGER);')
   db.execute('INSERT INTO servers VALUES(1,?,?,?)',('test',json.dumps({'public_ips':['8.8.8.8']}),int(time.time())))
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
  r=self.post('/plans/1',{'source_id':source,'nodes':['1','2'],'interval_s':600,'daily_limit':1000,**kwargs});self.assertEqual(r.status_code,200,r.json)
 def test_secret_encryption_and_admin_only(self):
  self.source();self.assertEqual(self.client.get('/api/detection').status_code,403)
  data=self.client.get('/api/detection',headers=self.headers).text;self.assertNotIn('testsecret',data)
  with self.connect() as db:self.assertNotIn('testsecret',db.execute('SELECT secret FROM detection_sources').fetchone()[0])
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
