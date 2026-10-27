import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch, MagicMock
from cryptography.fernet import Fernet
from flask import Flask, request
import ip_dns

class IPDNSTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=self.temp.name+'/panel.db';self.cipher=Fernet(Fernet.generate_key())
        @contextmanager
        def connect():
            db=sqlite3.connect(self.path);db.row_factory=sqlite3.Row;db.execute('PRAGMA foreign_keys=ON')
            try:
                with db:yield db
            finally:db.close()
        self.connect=connect
        with connect() as db:
            db.executescript('CREATE TABLE servers(id INTEGER PRIMARY KEY,name TEXT,metrics TEXT,seen INTEGER);')
            db.execute('INSERT INTO servers VALUES(1,?,?,?)',('CMHK',json.dumps({'public_ips':['8.8.4.4']}),int(time.time())))
        ip_dns.init_schema(connect)
        def auth(admin=False):
            def decorator(fn):
                from functools import wraps
                @wraps(fn)
                def wrapped(*a,**k):
                    if request.headers.get('X-Test-Admin')!='yes':return {'error':'denied'},403
                    return fn(*a,**k)
                return wrapped
            return decorator
        app=Flask(__name__)
        ip_dns.register(app,connect,self.cipher,auth,lambda:request.get_json(silent=True) or {},lambda m:({'error':m},400),lambda *a:None)
        self.client=app.test_client();self.headers={'X-Test-Admin':'yes'}
        self.record={'RecordId':'123','RR':'addf','Line':'cmcc','Type':'A','Value':'8.8.8.8','TTL':600,'Status':'ENABLE'}
        self.mock=patch('ip_dns.alidns',side_effect=self.alidns);self.calls=[];self.mock.start();self.addCleanup(self.mock.stop);self.addCleanup(self.temp.cleanup)
        self.cid=self.post('/connections',{'kind':'alidns','name':'Ali','config':{'access_key_id':'test-id'},'secret':'secret-test'}).json['id']
    def alidns(self,c,action,**kw):
        self.calls.append((action,kw))
        if action=='DescribeDomainRecords':return {'DomainRecords':{'Record':[dict(self.record)]}}
        if action=='UpdateDomainRecord':self.record['Value']=kw['Value'];return {'RecordId':'123'}
        return dict(self.record)
    def post(self,path,data):return self.client.post('/api/ip-dns'+path,json=data,headers=self.headers)
    def binding(self,**kw):
        self.post('/monitors',{'server_ids':[1],'port':443})
        d={'server_id':1,'connection_id':self.cid,'domain':'example.com','rr':'addf','record_id':'123','line':'cmcc','expected_ip':'8.8.8.8','port':443,**kw}
        r=self.post('/bindings',d);self.assertEqual(r.status_code,200,r.json);return r.json['id']
    def test_secrets_encrypted_not_returned(self):
        with self.connect() as db:self.assertNotIn('secret-test',db.execute('SELECT secret FROM ip_connections').fetchone()[0])
        data=self.client.get('/api/ip-dns',headers=self.headers)
        self.assertNotIn('secret-test',data.text);self.assertNotIn('"secret"',data.text)
    def test_admin_routes_reject_unauthorized(self):
        self.assertEqual(self.client.get('/api/ip-dns').status_code,403)
        self.assertEqual(self.client.post('/api/ip-dns/connections',json={}).status_code,403)
    def test_identity_validation_blocks_wrong_line(self):
        r=self.post('/bindings',{'server_id':1,'connection_id':self.cid,'domain':'example.com','rr':'addf','record_id':'123','line':'telecom','expected_ip':'8.8.8.8'})
        self.assertEqual(r.status_code,400)
    def test_same_hostname_carrier_lines_bind_as_separate_records(self):
        records=[{'RecordId':'telecom-1','RR':'addf','Line':'telecom','Type':'A','Value':'1.1.1.1','TTL':600,'Status':'ENABLE'},
                 {'RecordId':'mobile-2','RR':'addf','Line':'mobile','Type':'A','Value':'8.8.8.8','TTL':600,'Status':'ENABLE'}]
        def ali(connection,action,**kwargs):
            if action=='DescribeDomainRecords':return {'DomainRecords':{'Record':[r for r in records if r['RR']==kwargs.get('RRKeyWord')]}}
            return next(r for r in records if r['RecordId']==kwargs['RecordId'])
        self.post('/monitors',{'server_ids':[1]})
        with patch('ip_dns.alidns',side_effect=ali):
            first=self.post('/bindings',{'server_id':1,'connection_id':self.cid,'domain':'example.com','rr':'addf','record_id':'telecom-1','line':'telecom','expected_ip':'1.1.1.1','port':443})
            second=self.post('/bindings',{'server_id':1,'connection_id':self.cid,'domain':'example.com','rr':'addf','record_id':'mobile-2','line':'mobile','expected_ip':'8.8.8.8','port':443})
        self.assertEqual(first.status_code,200,first.json);self.assertEqual(second.status_code,200,second.json)
        with self.connect() as db:
            rows=db.execute('SELECT record_id,line,expected_ip FROM dns_bindings ORDER BY record_id').fetchall()
            self.assertEqual([tuple(r) for r in rows],[('mobile-2','mobile','8.8.8.8'),('telecom-1','telecom','1.1.1.1')])
    def test_stable_candidate_updates_only_bound_record(self):
        bid=self.binding()
        result=ip_dns.run_binding(self.connect,self.cipher,bid,True)
        self.assertIn('60',result['status']);self.assertFalse(any(a=='UpdateDomainRecord' for a,k in self.calls))
        with self.connect() as db:db.execute('UPDATE dns_bindings SET candidate_since=? WHERE id=?',(int(time.time())-65,bid))
        with patch('ip_dns.socket.create_connection',return_value=MagicMock()):ip_dns.run_binding(self.connect,self.cipher,bid,True)
        writes=[k for a,k in self.calls if a=='UpdateDomainRecord'];self.assertEqual(len(writes),1)
        self.assertEqual(writes[0],{'RecordId':'123','RR':'addf','Type':'A','Value':'8.8.4.4','Line':'cmcc','TTL':600})
        with self.connect() as db:self.assertEqual(db.execute('SELECT expected_ip FROM dns_bindings').fetchone()[0],'8.8.4.4')
    def test_old_ip_changed_by_operator_blocks_update(self):
        bid=self.binding();self.record['Value']='1.1.1.1'
        with self.assertRaises(ip_dns.IntegrationError):ip_dns.run_binding(self.connect,self.cipher,bid,True)
        self.assertFalse(any(a=='UpdateDomainRecord' for a,k in self.calls))
    def test_offline_agent_and_multiple_addresses_block(self):
        bid=self.binding()
        with self.connect() as db:db.execute('UPDATE servers SET seen=1')
        with self.assertRaises(ip_dns.IntegrationError):ip_dns.run_binding(self.connect,self.cipher,bid,True)
        with self.connect() as db:db.execute('UPDATE servers SET seen=?,metrics=?',(int(time.time()),json.dumps({'public_ips':['8.8.4.4','1.1.1.1']})))
        with self.assertRaises(ip_dns.IntegrationError):ip_dns.run_binding(self.connect,self.cipher,bid,True)
    def test_port_failure_resets_candidate_no_dns_write(self):
        bid=self.binding();ip_dns.run_binding(self.connect,self.cipher,bid)
        with self.connect() as db:db.execute('UPDATE dns_bindings SET candidate_since=1')
        with patch('ip_dns.socket.create_connection',side_effect=OSError):
            with self.assertRaises(ip_dns.IntegrationError):ip_dns.run_binding(self.connect,self.cipher,bid,True)
        self.assertFalse(any(a=='UpdateDomainRecord' for a,k in self.calls))
        with self.connect() as db:self.assertIsNone(db.execute('SELECT candidate FROM dns_bindings').fetchone()[0])
    def test_provider_field_mapping_and_private_ips(self):
        c={'config':{'url':'https://api.example.com/node','header':'Authorization','prefix':'Bearer ','ip_path':'data.0.ip'},'secret':'abc'}
        with patch('ip_dns.request_json',return_value={'data':[{'ip':'1.1.1.1'}]}) as call:
            self.assertEqual(ip_dns.provider_ip(c),'1.1.1.1');self.assertEqual(call.call_args.args[1]['Authorization'],'Bearer abc')
        with patch('ip_dns.request_json',return_value={'data':[{'ip':'127.0.0.1'}]}):
            with self.assertRaises(ip_dns.IntegrationError):ip_dns.provider_ip(c)
    def test_monitor_falls_back_to_existing_unique_fresh_egress_ipv4(self):
        with self.connect() as db:
            db.execute('UPDATE servers SET metrics=? WHERE id=1',(json.dumps({'public_ips':[],'egress_ips':['1.1.1.1'],'egress_checked':int(time.time())}),))
            self.assertEqual(ip_dns.candidate_ip(db,{'server_id':1,'source_id':None},self.cipher),'1.1.1.1')
    def test_monitor_rejects_multiple_or_stale_egress_ipv4(self):
        with self.connect() as db:
            for ips,checked in [(['1.1.1.1','8.8.8.8'],int(time.time())),(['1.1.1.1'],int(time.time())-181)]:
                db.execute('UPDATE servers SET metrics=? WHERE id=1',(json.dumps({'public_ips':[],'egress_ips':ips,'egress_checked':checked}),))
                with self.assertRaises(ip_dns.IntegrationError):ip_dns.candidate_ip(db,{'server_id':1,'source_id':None},self.cipher)
    def test_change_ip_connection_validates_without_sending_request(self):
        config={'url':'https://provider.example/change','header':'Authorization','prefix':'Bearer ','body_json':'{"id":"{{server_id}}"}'}
        with patch('ip_dns.request_json') as request:
            saved=self.post('/connections',{'kind':'change_ip','name':'provider','config':config,'secret':'secret'})
            self.assertEqual(saved.status_code,200,saved.json)
            tested=self.post('/connections/'+str(saved.json['id'])+'/test',{})
            self.assertEqual(tested.status_code,200,tested.json)
            self.assertFalse(tested.json['test_supported'])
            request.assert_not_called()
        with self.connect() as db:
            row=db.execute('SELECT * FROM ip_connections WHERE id=?',(saved.json['id'],)).fetchone()
            self.assertNotIn('secret',row['secret'])
    def test_change_ip_api_expands_placeholders_and_posts_json(self):
        connection={'config':{'url':'https://provider.example/change','header':'X-Token','prefix':'Token ','body_json':'{"instance":"{{server_name}}","ip":"{{current_ip}}","id":"{{server_id}}"}'},'secret':'abc'}
        with patch('ip_dns.request_json',return_value={'success':True}) as request:
            result=ip_dns.invoke_change_ip_api(connection,7,'edge-7','8.8.8.8')
        self.assertIn('已接受',result)
        self.assertEqual(request.call_args.args[1]['X-Token'],'Token abc')
        self.assertEqual(json.loads(request.call_args.args[2]),{'instance':'edge-7','ip':'8.8.8.8','id':'7'})
    def test_ssrf_dns_rebinding_guard_and_url_validation(self):
        for url in ['http://example.com','https://user:pass@example.com','https://example.com:8080']:
            with self.assertRaises(ip_dns.IntegrationError):ip_dns.endpoint(url)
        with patch('ip_dns.socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]),patch('ip_dns.socket.create_connection') as connect:
            with self.assertRaises(ip_dns.IntegrationError):ip_dns.request_json('https://example.com')
            connect.assert_not_called()
    def test_recheck_before_write_detects_race(self):
        bid=self.binding();ip_dns.run_binding(self.connect,self.cipher,bid)
        with self.connect() as db:db.execute('UPDATE dns_bindings SET candidate_since=1')
        def mutate(*args,**kwargs):self.record['Value']='1.1.1.1';return MagicMock()
        with patch('ip_dns.socket.create_connection',side_effect=mutate):
            with self.assertRaises(ip_dns.IntegrationError):ip_dns.run_binding(self.connect,self.cipher,bid,True)
        self.assertFalse(any(a=='UpdateDomainRecord' for a,k in self.calls))

    def test_monitor_selection_pause_and_no_unselected_nodes(self):
        self.assertEqual(self.post('/monitors',{'server_ids':[999]}).status_code,400)
        self.assertEqual(self.post('/monitors',{'server_ids':[1,1],'port':8443}).status_code,200)
        rows=self.client.get('/api/ip-dns',headers=self.headers).json['monitors']
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['port'],8443)
        self.assertEqual(self.client.patch('/api/ip-dns/monitors/1',json={'port':443,'enabled':False},headers=self.headers).status_code,200)
        with self.assertRaises(ip_dns.IntegrationError):ip_dns.check_monitor(self.connect,1)
    def test_monitor_tracks_old_new_ip_and_log(self):
        self.post('/monitors',{'server_ids':[1]})
        with patch('ip_dns.socket.create_connection',return_value=MagicMock()):
            ip_dns.check_monitor(self.connect,1)
            with self.connect() as db:db.execute('UPDATE servers SET metrics=?',(json.dumps({'public_ips':['1.1.1.1']}),))
            result=ip_dns.check_monitor(self.connect,1)
        self.assertEqual(result['ip'],'1.1.1.1');self.assertEqual(result['previous_ip'],'8.8.4.4')
        with self.connect() as db:self.assertIn('8.8.4.4 → 1.1.1.1',db.execute('SELECT message FROM dns_events').fetchone()[0])
    def test_remove_monitor_requires_disable_auto_dns(self):
        self.binding(automatic=True)
        self.assertEqual(self.client.delete('/api/ip-dns/monitors/1',headers=self.headers).status_code,400)
