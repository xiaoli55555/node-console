import unittest, tempfile, os, json, time, importlib.util
os.environ['DATA_DIR']=tempfile.mkdtemp(prefix='console-test-')
os.environ['COOKIE_SECURE']='0'
import server
from werkzeug.security import generate_password_hash

class PanelTest(unittest.TestCase):
    def setUp(self):
        with server.connect() as db:
            for table in ['sessions','commands','servers','audit','attempts','announcements','client_subscriptions','messages','forwarding_requests','users']:db.execute('DELETE FROM '+table)
            db.execute("UPDATE settings SET value='/admin' WHERE key='admin_path'")
            for name,role in [('admin','admin'),('alice','client'),('bob','client')]:
                db.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(name,generate_password_hash('correct-password-123'),role))
        self.admin,self.alice,self.bob=[server.app.test_client() for _ in range(3)]
        self.admin.environ_base['HTTP_X_PANEL_ENTRY']='/admin'
        self.tokens={}
        for client,name in [(self.admin,'admin'),(self.alice,'alice'),(self.bob,'bob')]:
            self.assertEqual(client.post('/api/login',json={'username':name,'password':'correct-password-123'}).status_code,200)
            self.tokens[name]=client.get('/api/me').json['csrf']
    def post(self,path,data=None):return self.admin.post(path,json=data or {},headers={'X-CSRF-Token':self.tokens['admin']})
    def test_simulated_boce_moonvm_agent_alidns_full_flow(self):
        from unittest.mock import patch, MagicMock
        from urllib.parse import urlsplit, parse_qs
        import detectors, ip_dns
        old_ip,new_ip,port='8.8.8.8','1.1.1.1',23456
        clock=[int(time.time())];created=[];dns_writes=[]
        records={
            'mobile-record':{'RecordId':'mobile-record','RR':'edge','Line':'cmcc','Type':'A','Value':old_ip,'TTL':600,'Status':'ENABLE'},
            'telecom-record':{'RecordId':'telecom-record','RR':'edge','Line':'telecom','Type':'A','Value':'9.9.9.9','TTL':600,'Status':'ENABLE'},
        }
        def dns(connection,action,**params):
            if action=='DescribeDomainRecords':return {'DomainRecords':{'Record':[dict(r) for r in records.values()]}}
            if action=='UpdateDomainRecord':
                self.assertEqual(params['RecordId'],'mobile-record');self.assertEqual(params['Line'],'cmcc')
                self.assertEqual(params['Value'],new_ip);self.assertEqual(params['TTL'],600)
                dns_writes.append(dict(params));records['mobile-record']['Value']=params['Value']
                return {'RecordId':'mobile-record'}
            return dict(records[params['RecordId']])
        def boce_response(url,*args,**kwargs):
            path=urlsplit(url).path;query=parse_qs(urlsplit(url).query)
            if path.endswith('/node/list'):return {'code':200,'data':{'error_code':0,'data':{'list':[{'id':13},{'id':14}]}}}
            if path.endswith('/create/tcping'):
                self.assertEqual(query['host'],[old_ip+':'+str(port)]);self.assertEqual(query['node_ids'],['13,14'])
                task='20261028_simulated_'+str(len(created)+1);created.append(task)
                return {'code':200,'data':{'error_code':0,'data':{'id':task}}}
            self.assertIn(path.rsplit('/',1)[-1],created)
            return {'code':200,'data':{'done':True,'list':[{'node_id':i,'node_name':str(i),'packets_transmitted':10,'packets_received':0,'error_code':0} for i in [13,14]]}}
        def saved(path,data):
            response=self.post(path,data);self.assertIn(response.status_code,(200,201),response.json);return response.json
        with patch('time.time',side_effect=lambda:clock[0]),patch('detectors.request_json',side_effect=boce_response),patch('ip_dns.alidns',side_effect=dns),patch('ip_dns.request_moonvm',return_value='accepted (simulation)') as moonvm,patch('ip_dns.socket.create_connection',return_value=MagicMock()) as tcp,patch('detectors.queue_reboot',side_effect=AssertionError('Reboot must never be called')) as reboot:
            node=saved('/api/servers',{'name':'full-flow-dry-run'});sid=node['id'];agent={'Authorization':'Bearer '+node['token']}
            def report(address):
                # Exercise the actual authenticated Agent report route, including IP history.
                response=self.admin.post('/api/agent/report',json={'public_ips':[],'egress_ips':[address],'egress_checked':clock[0],'uptime':clock[0]},headers=agent)
                self.assertEqual(response.status_code,200,response.json)
            report(old_ip)
            saved('/api/ip-dns/monitors',{'server_ids':[sid],'port':port})
            ip_dns.check_monitor(server.connect,sid,server.CIPHER)
            source=saved('/api/detection/sources',{'name':'simulated BOCE','kind':'boce','secret':'dummy-boce'})
            saved('/api/detection/sources/'+str(source['id'])+'/test',{})
            action=saved('/api/ip-dns/connections',{'name':'simulated MoonVM','kind':'change_ip','config':{'provider':'moonvm','url':'https://store.moonvm.com/ddns.php?product=12345&flag=changeip&iptoken=dummy-token-12345'}})
            ali=saved('/api/ip-dns/connections',{'name':'simulated AliDNS','kind':'alidns','config':{'access_key_id':'dummy-id'},'secret':'dummy-secret'})
            binding=saved('/api/ip-dns/bindings',{'server_id':sid,'connection_id':ali['id'],'domain':'example.com','rr':'edge','record_id':'mobile-record','line':'cmcc','expected_ip':old_ip,'port':port,'automatic':True})
            saved('/api/detection/plans/'+str(sid),{'source_id':source['id'],'nodes':['13','14'],'port':port,'interval_s':120,'daily_limit':1000,'automatic':True,'response_mode':'change_api','action_connection_id':action['id'],'failure_threshold':3})
            start=clock[0]
            for n in range(3):
                clock[0]=start+n*120;report(old_ip)
                detectors.tick(server.connect,server.CIPHER)
                clock[0]+=10
                detectors.tick(server.connect,server.CIPHER)
                self.assertEqual(moonvm.call_count,1 if n==2 else 0)
            self.assertEqual(len(created),3);self.assertEqual(moonvm.call_count,1)
            # Claiming again must not resend the provider request.
            detectors.execute_change_ip_actions(server.connect,server.CIPHER);self.assertEqual(moonvm.call_count,1)
            clock[0]+=1;report(new_ip)
            monitor=ip_dns.check_monitor(server.connect,sid,server.CIPHER);self.assertEqual(monitor['ip'],new_ip)
            first=ip_dns.run_binding(server.connect,server.CIPHER,binding['id'],apply=True)
            self.assertIn('60',first['status']);self.assertEqual(dns_writes,[])
            clock[0]+=61;report(new_ip)
            ip_dns.check_monitor(server.connect,sid,server.CIPHER)
            final=ip_dns.run_binding(server.connect,server.CIPHER,binding['id'],apply=True)
            self.assertIn('回读验证',final['status']);self.assertEqual(len(dns_writes),1)
            tcp.assert_any_call((new_ip,port),timeout=4)
            self.assertEqual(records['mobile-record']['Value'],new_ip)
            self.assertEqual(records['telecom-record']['Value'],'9.9.9.9')
            ip_dns.run_binding(server.connect,server.CIPHER,binding['id'],apply=True)
            self.assertEqual(len(dns_writes),1);self.assertEqual(moonvm.call_count,1);reboot.assert_not_called()
            with server.connect() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM commands WHERE server_id=?',(sid,)).fetchone()[0],0)
                b=db.execute('SELECT * FROM dns_bindings WHERE id=?',(binding['id'],)).fetchone()
                self.assertEqual(b['expected_ip'],new_ip);self.assertIsNone(b['candidate'])
                run=db.execute('SELECT action_status FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1',(sid,)).fetchone()
                self.assertEqual(run['action_status'],'submitted')
            history=self.admin.get(f'/api/servers/{sid}/ip-history').json
            self.assertEqual(history['events'][0]['addresses'],[new_ip]);self.assertEqual(history['events'][0]['previous_addresses'],[old_ip])

    def test_natural_month_subscription_settings_and_countdown(self):
        from datetime import date, datetime, timezone
        from unittest.mock import patch
        self.assertEqual(server.add_calendar_months(date(2024,1,31),1),date(2024,2,29))
        self.assertEqual(server.add_calendar_months(date(2025,1,31),1),date(2025,2,28))
        self.assertEqual(server.add_calendar_months(date(2024,1,31),12),date(2025,1,31))
        uid=self.alice.get('/api/me').json['id']
        self.assertIsNone(self.alice.get('/api/subscription').json['expires_on'])
        self.assertEqual(self.alice.get(f'/api/users/{uid}/subscription').status_code,403)
        with patch('server.shanghai_today',return_value=date(2024,1,31)):
            saved=self.admin.patch(f'/api/users/{uid}/subscription',json={'expires_on':'2024-01-31','cycle_months':1},headers={'X-CSRF-Token':self.tokens['admin']})
            self.assertEqual(saved.status_code,200)
            self.assertEqual(saved.json['starts_on'],'2024-01-31')
            self.assertEqual(self.alice.get('/api/subscription').json['expires_on'],'2024-01-31')
            renewed=self.admin.post(f'/api/users/{uid}/subscription/renew',json={},headers={'X-CSRF-Token':self.tokens['admin']})
            self.assertEqual(renewed.status_code,200)
            self.assertEqual(renewed.json['expires_on'],'2024-02-29')
        client_view=self.alice.get('/api/subscription').json
        expected=int(datetime(2024,3,1,0,0,tzinfo=server.SHANGHAI).timestamp())
        self.assertEqual(client_view['expires_at'],expected)
        self.assertEqual(client_view['cycle_months'],1)
        self.assertEqual(self.admin.patch(f'/api/users/{uid}/subscription',json={'expires_on':'2024-02-30','cycle_months':1},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,400)
        self.assertEqual(self.admin.patch(f'/api/users/{uid}/subscription',json={'expires_on':'2024-03-01','cycle_months':0},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,400)
        self.assertEqual(self.admin.delete(f'/api/users/{uid}/subscription',headers={'X-CSRF-Token':self.tokens['admin']}).status_code,200)
        self.assertIsNone(self.alice.get('/api/subscription').json['expires_on'])
        self.assertEqual(self.alice.get('/api/users').status_code,403)

    def test_announcements_admin_crud_and_client_visibility(self):
        self.assertEqual(self.alice.get('/api/admin/announcements').status_code,403)
        self.assertEqual(self.alice.post('/api/announcements',json={'title':'not allowed','content':'x'},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,403)
        self.assertEqual(self.alice.get('/api/announcements').json,[])
        created=self.post('/api/announcements',{'title':'维护通知','content':'今晚 23:00 进行网络维护','published':False})
        self.assertEqual(created.status_code,201)
        aid=created.json['id']
        self.assertEqual(self.alice.get('/api/announcements').json,[])
        managed=self.admin.get('/api/admin/announcements').json
        self.assertEqual(managed[0]['published'],0)
        self.assertEqual(self.admin.patch(f'/api/announcements/{aid}',json={'published':True},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,200)
        visible=self.alice.get('/api/announcements').json
        self.assertEqual([(x['title'],x['content']) for x in visible],[('维护通知','今晚 23:00 进行网络维护')])
        self.assertEqual(self.admin.patch(f'/api/announcements/{aid}',json={'title':'x'*81},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,400)
        self.assertEqual(self.admin.patch(f'/api/announcements/{aid}',json={'published':1},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,400)
        self.assertEqual(self.admin.patch(f'/api/announcements/{aid}',json={'published':False},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,200)
        self.assertEqual(self.alice.get('/api/announcements').json,[])
        self.assertEqual(self.admin.delete(f'/api/announcements/{aid}',headers={'X-CSRF-Token':self.tokens['admin']}).status_code,200)
        self.assertEqual(self.alice.get('/api/announcements').json,[])
        self.assertEqual(self.admin.get('/api/admin/announcements').json,[])


    def test_secure_customer_admin_message_threads_and_unread(self):
        alice_id=self.alice.get('/api/me').json['id'];bob_id=self.bob.get('/api/me').json['id']
        self.assertEqual(self.bob.get(f'/api/messages/threads/{alice_id}').status_code,404)
        self.assertEqual(self.alice.get('/api/messages/threads').status_code,403)
        self.assertEqual(self.alice.get('/api/messages/unread').json['unread'],0)
        sent=self.alice.post(f'/api/messages/threads/{alice_id}',json={'content':'VPS 无法连接，请协助处理。'},headers={'X-CSRF-Token':self.tokens['alice']})
        self.assertEqual(sent.status_code,201)
        self.assertEqual(self.admin.get('/api/messages/unread').json['unread'],1)
        threads=self.admin.get('/api/messages/threads').json
        self.assertEqual(next(x for x in threads if x['user_id']==alice_id)['unread'],1)
        conversation=self.admin.get(f'/api/messages/threads/{alice_id}').json
        self.assertEqual(conversation['messages'][0]['content'],'VPS 无法连接，请协助处理。')
        self.assertEqual(self.admin.get('/api/messages/unread').json['unread'],0)
        reply=self.admin.post(f'/api/messages/threads/{alice_id}',json={'content':'已收到，我正在检查。'},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(reply.status_code,201)
        self.assertEqual(self.alice.get('/api/messages/unread').json['unread'],1)
        self.assertEqual(self.alice.get(f'/api/messages/threads/{alice_id}').json['messages'][-1]['sender_name'],'admin')
        self.assertEqual(self.alice.get('/api/messages/unread').json['unread'],0)
        self.assertEqual(self.alice.post(f'/api/messages/threads/{alice_id}',json={'content':' '},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,400)
        self.assertEqual(self.alice.post(f'/api/messages/threads/{alice_id}',json={'content':'x'*2001},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,400)
        self.assertEqual(self.bob.post(f'/api/messages/threads/{alice_id}',json={'content':'跨客户'},headers={'X-CSRF-Token':self.tokens['bob']}).status_code,404)
        self.assertEqual(self.admin.post(f'/api/messages/threads/{bob_id}',json={'content':'管理员发起'},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,201)

    def test_forwarding_request_permissions_idempotence_and_admin_listing(self):
        alice_id=self.alice.get('/api/me').json['id']
        admin_id=self.admin.get('/api/me').json['id']
        self.assertEqual(self.admin.get('/api/forwarding-request').status_code,403)
        self.assertEqual(self.alice.get('/api/admin/forwarding-requests').status_code,403)
        self.assertEqual(self.alice.get('/api/forwarding-request').json,{'id':None,'created':None})
        first=self.alice.post('/api/forwarding-request',json={},headers={'X-CSRF-Token':self.tokens['alice']})
        self.assertEqual(first.status_code,201)
        self.assertFalse(first.json['already_submitted'])
        self.assertEqual(self.alice.get('/api/forwarding-request').json['id'],first.json['id'])
        duplicate=self.alice.post('/api/forwarding-request',json={},headers={'X-CSRF-Token':self.tokens['alice']})
        self.assertEqual(duplicate.status_code,200)
        self.assertTrue(duplicate.json['already_submitted'])
        self.assertEqual(duplicate.json['id'],first.json['id'])
        requests=self.admin.get('/api/admin/forwarding-requests').json
        self.assertEqual(len(requests),1)
        self.assertEqual((requests[0]['user_id'],requests[0]['username']),(alice_id,'alice'))
        self.assertIsInstance(requests[0]['created'],int)
        self.assertEqual(self.admin.post('/api/forwarding-request',json={},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,403)
        self.assertEqual(self.alice.post('/api/forwarding-request',json={}).status_code,403)

    def test_udp_unit_change_removes_only_old_udp_history(self):
        result=self.post('/api/servers',{'name':'udp-test'}).json
        sid=result['id'];headers={'Authorization':'Bearer '+result['token']}
        self.assertEqual(self.admin.post('/api/agent/report',json={'udp':9,'cpu_percent':30},headers=headers).status_code,200)
        self.assertEqual(self.admin.post('/api/agent/report',json={'udp':177,'cpu_percent':40,'udp_method':'socket'},headers=headers).status_code,200)
        with server.connect() as db:
            points=db.execute('SELECT cpu,udp FROM metric_points WHERE server_id=?',(sid,)).fetchall()
            self.assertTrue(points);self.assertTrue(all(p['udp'] is None for p in points));self.assertEqual(points[0]['cpu'],30)
        current=self.admin.get('/api/servers').json[0]['metrics']
        self.assertEqual(current['udp'],177);self.assertEqual(current['udp_method'],'socket')

    def test_tenant_boundary(self):
        r=self.post('/api/servers',{'name':'HK-01'});self.assertEqual(r.status_code,201);sid=r.json['id'];token=r.json['token']
        alice_id=self.alice.get('/api/me').json['id']
        self.assertEqual(self.admin.patch('/api/servers/'+str(sid),json={'owner_id':alice_id},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,200)
        self.assertEqual(len(self.alice.get('/api/servers').json),1)
        self.assertEqual(self.bob.get('/api/servers').json,[])
        self.assertEqual(self.bob.post('/api/servers',json={'name':'bad'},headers={'X-CSRF-Token':self.tokens['bob']}).status_code,403)
        self.assertEqual(self.bob.delete('/api/servers/'+str(sid),headers={'X-CSRF-Token':self.tokens['bob']}).status_code,403)
        self.assertEqual(self.bob.get('/api/users').status_code,403)
        result=self.admin.post('/api/agent/report',json={'tcp':2427,'udp':12},headers={'Authorization':'Bearer '+token})
        self.assertEqual(result.status_code,200)
        row=self.alice.get('/api/servers').json[0]
        self.assertEqual(row['metrics']['tcp'],2427);self.assertTrue(row['online']);self.assertNotIn('agent_hash',row)
        self.assertNotIn(token,json.dumps(row))
        with server.connect() as db:db.execute('UPDATE servers SET seen=?',(int(time.time())-100,))
        self.assertFalse(self.alice.get('/api/servers').json[0]['online'])
    def test_csrf_and_auth(self):
        self.assertEqual(server.app.test_client().get('/api/servers').status_code,401)
        self.assertEqual(self.admin.post('/api/servers',json={'name':'a'}).status_code,403)
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1}).status_code,401)
        self.assertEqual(self.post('/api/users',{'username':'eve','password':'short'}).status_code,400)
    def test_token_rotation_and_metrics(self):
        r=self.post('/api/servers',{'name':'node'}).json;headers={'Authorization':'Bearer '+r['token']}
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':-1},headers=headers).status_code,400)
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1.5},headers=headers).status_code,400)
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':None,'udp':None},headers=headers).status_code,200)
        self.post('/api/servers/'+str(r['id'])+'/rotate')
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1},headers=headers).status_code,401)
    def test_password_revokes_sessions(self):
        r=self.alice.post('/api/password',json={'old':'correct-password-123','new':'new-password-123'},headers={'X-CSRF-Token':self.tokens['alice']})
        self.assertEqual(r.status_code,200);self.assertEqual(self.alice.get('/api/me').status_code,401)
    def test_backup(self):
        destination=tempfile.mktemp()
        import sqlite3
        with server.connect() as src,sqlite3.connect(destination) as dst:src.backup(dst)
        with sqlite3.connect(destination) as db:self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone()[0],3)
        os.unlink(destination)
    def test_tcp_parser(self):
        spec=importlib.util.spec_from_file_location('agent',server.ROOT/'agent/agent.py');agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
        from pathlib import Path
        root=Path(tempfile.mkdtemp());(root/'net').mkdir()
        (root/'net/tcp').write_text('header\n0: local remote 01\n1: local remote 0A\n')
        (root/'net/tcp6').write_text('header\n0: local remote 01\n')
        self.assertEqual(agent.tcp_count(root),2)
    def test_login_throttle(self):
        c=server.app.test_client()
        for _ in range(10):self.assertEqual(c.post('/api/login',json={'username':'nobody','password':'bad'}).status_code,401)
        self.assertEqual(c.post('/api/login',json={'username':'nobody','password':'bad'}).status_code,429)
    def test_network_and_ip_access(self):
        from unittest.mock import patch
        r=self.post('/api/servers',{'name':'network-node'}).json;sid=r['id']
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch('/api/servers/'+str(sid),json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        h={'Authorization':'Bearer '+r['token']};base=int(time.time())
        with patch('server.time.time',return_value=base):
            self.assertEqual(self.admin.post('/api/agent/report',json={'rx_bytes':1000,'tx_bytes':2000,'uptime':100,'public_ips':['8.8.8.8']},headers=h).status_code,200)
        with patch('server.time.time',return_value=base+15):
            self.assertEqual(self.admin.post('/api/agent/report',json={'rx_bytes':2500,'tx_bytes':5000,'uptime':115,'public_ips':['1.1.1.1']},headers=h).status_code,200)
            d=self.alice.get(f'/api/servers/{sid}/network').json
            self.assertEqual(d['rx_bps'],800);self.assertEqual(d['tx_bps'],1600)
            self.assertEqual(d['traffic']['today_rx'],1500)
            ips=self.alice.get(f'/api/servers/{sid}/ip-history').json
            self.assertEqual(len(ips['events']),2)
            self.assertEqual(ips['events'][0]['addresses'],['1.1.1.1'])
        self.assertEqual(self.bob.get(f'/api/servers/{sid}/network').status_code,404)
        self.assertEqual(self.bob.get(f'/api/servers/{sid}/ip-history').status_code,404)
        # Omitted IP data from old agents does not erase the history.
        self.admin.post('/api/agent/report',json={'tcp':1},headers=h)
        self.assertEqual(len(self.alice.get(f'/api/servers/{sid}/ip-history').json['events']),2)
        self.assertEqual(self.admin.post('/api/agent/report',json={'public_ips':['127.0.0.1']},headers=h).status_code,400)

    def test_reboot_permissions_one_time_delivery_and_completion(self):
        r=self.post('/api/servers',{'name':'reboot-test'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch('/api/servers/'+str(sid),json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        ah={'X-CSRF-Token':self.tokens['alice']};bh={'X-CSRF-Token':self.tokens['bob']}
        # Offline and legacy clients cannot receive commands.
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=ah).status_code,409)
        self.admin.post('/api/agent/report',json={'uptime':100},headers=h)
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=ah).status_code,409)
        self.admin.post('/api/agent/report',json={'uptime':100,'capabilities':['reboot']},headers=h)
        self.assertEqual(self.bob.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=bh).status_code,404)
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True}).status_code,403)
        job=self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=ah)
        self.assertEqual(job.status_code,202);cid=job.json['id']
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=ah).status_code,409)
        result=self.admin.post('/api/agent/report',json={'uptime':115,'capabilities':['reboot']},headers=h).json
        self.assertEqual(result['command'],{'id':cid,'action':'reboot'})
        self.assertIsNone(self.admin.post('/api/agent/report',json={'uptime':116,'capabilities':['reboot']},headers=h).json['command'])
        self.assertEqual(self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers={'Authorization':'Bearer bad'}).status_code,401)
        self.assertEqual(self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers=h).status_code,200)
        self.assertEqual(self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers=h).status_code,409)
        self.admin.post('/api/agent/report',json={'uptime':5,'capabilities':['reboot']},headers=h)
        self.assertEqual(self.alice.get('/api/servers').json[0]['last_command']['status'],'completed')
    def test_reboot_revoked_after_reassignment(self):
        r=self.post('/api/servers',{'name':'reassign-test'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        self.admin.post('/api/agent/report',json={'uptime':100,'capabilities':['reboot']},headers=h)
        self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers={'X-CSRF-Token':self.tokens['alice']})
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':None},headers={'X-CSRF-Token':self.tokens['admin']})
        report=self.admin.post('/api/agent/report',json={'uptime':115,'capabilities':['reboot']},headers=h)
        self.assertIsNone(report.json['command'])
        self.assertEqual(self.admin.get('/api/servers').json[0]['last_command']['status'],'cancelled')

    def test_admin_entry_role_separation_and_change(self):
        c=server.app.test_client()
        self.assertEqual(c.post('/api/login',json={'username':'admin','password':'correct-password-123'}).status_code,401)
        self.assertEqual(c.post('/api/login',json={'username':'alice','password':'correct-password-123'},headers={'X-Panel-Entry':'/admin'}).status_code,401)
        self.assertEqual(self.alice.get('/api/settings').status_code,403)
        with self.admin.get('/admin') as response:self.assertEqual(response.status_code,200)
        self.assertEqual(self.admin.patch('/api/settings',json={'admin_path':'/api/hidden'},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,400)
        r=self.admin.patch('/api/settings',json={'admin_path':'/secure/panel-123'},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(r.status_code,200)
        self.assertEqual(c.get('/admin').status_code,404)
        with c.get('/secure/panel-123') as response:self.assertEqual(response.status_code,200)
        self.assertEqual(self.admin.get('/api/me').status_code,404)
        self.admin.environ_base['HTTP_X_PANEL_ENTRY']='/secure/panel-123'
        self.assertEqual(self.admin.get('/api/me').status_code,401)
        self.assertEqual(self.admin.post('/api/login',json={'username':'admin','password':'correct-password-123'}).status_code,200)
        self.assertEqual(self.admin.get('/api/me').status_code,200)
        self.assertEqual(self.alice.get('/api/me').status_code,200)
        self.assertEqual(c.get('/api/entry').json,{'kind':'client'})

    def test_reboot_expired_and_late_ack_revocation(self):
        from unittest.mock import patch
        r=self.post('/api/servers',{'name':'expire-test'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']};base=int(time.time())
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        self.admin.post('/api/agent/report',json={'uptime':100,'capabilities':['reboot']},headers=h)
        job=self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers={'X-CSRF-Token':self.tokens['alice']}).json
        with patch('server.time.time',return_value=base+125):
            result=self.admin.post('/api/agent/report',json={'uptime':225,'capabilities':['reboot']},headers=h)
            self.assertIsNone(result.json['command'])
        # Fresh task issued, but revoked before the agent acknowledges.
        with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(base,sid))
        job=self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers={'X-CSRF-Token':self.tokens['alice']}).json
        self.admin.post('/api/agent/report',json={'uptime':230,'capabilities':['reboot']},headers=h)
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':None},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(self.admin.post('/api/agent/commands/'+str(job['id'])+'/ack',json={},headers=h).status_code,403)

    def test_egress_ip_changes_are_recorded_without_interface_public_ip(self):
        r=self.post('/api/servers',{'name':'nat-node'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        now=int(time.time())
        for address in ['8.8.8.8','1.1.1.1','1.1.1.1']:
            response=self.admin.post('/api/agent/report',json={'public_ips':[],'egress_ips':[address],'egress_checked':now},headers=h)
            self.assertEqual(response.status_code,200)
        history=self.admin.get(f'/api/servers/{sid}/ip-history').json
        self.assertEqual(history['total'],2)
        self.assertTrue(history['available'])
        self.assertEqual(history['events'][0]['addresses'],['1.1.1.1'])
        self.assertEqual(history['events'][0]['previous_addresses'],['8.8.8.8'])
        # Failed or stale external observations must not create empty/false events.
        for sample in [{'public_ips':[],'egress_ips':None}, {'public_ips':[],'egress_ips':['9.9.9.9'],'egress_checked':now-100}]:
            self.assertEqual(self.admin.post('/api/agent/report',json=sample,headers=h).status_code,200)
        self.assertEqual(self.admin.get(f'/api/servers/{sid}/ip-history').json['total'],2)

    def test_complete_ip_history_pagination_and_ownership(self):
        r=self.post('/api/servers',{'name':'cmhk-node'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        # More than the previous 1000-entry cap must survive a new report.
        with server.connect() as db:
            for i in range(1005):db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(?,?,?)',(sid,json.dumps(['8.8.8.8' if i%2 else '1.1.1.1']),1000+i))
        self.admin.post('/api/agent/report',json={'uptime':10,'public_ips':['9.9.9.9']},headers=h)
        first=self.alice.get(f'/api/servers/{sid}/ip-history').json
        self.assertEqual(first['total'],1006);self.assertEqual(len(first['events']),50);self.assertTrue(first['has_more'])
        self.assertEqual(first['events'][0]['addresses'],['9.9.9.9'])
        self.assertEqual(first['events'][0]['previous_addresses'],['1.1.1.1'])
        seen=[];cursor=None
        while True:
            page=self.alice.get(f'/api/servers/{sid}/ip-history'+(f'?before={cursor}' if cursor else '')).json
            seen.extend(e['id'] for e in page['events'])
            if not page['has_more']:break
            cursor=page['next_cursor']
        self.assertEqual(len(seen),1006);self.assertEqual(len(set(seen)),1006)
        self.assertEqual(self.bob.get(f'/api/servers/{sid}/ip-history?before='+str(first['next_cursor'])).status_code,404)
        self.assertEqual(self.alice.get(f'/api/servers/{sid}/ip-history?before=invalid').status_code,400)

    def test_metric_history_scope_values_and_validation(self):
        r=self.post('/api/servers',{'name':'metric-node'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(self.admin.post('/api/agent/report',json={'cpu_percent':25,'memory_percent':60,'tcp':1234,'udp':20},headers=h).status_code,200)
        data=self.alice.get(f'/api/servers/{sid}/metrics').json
        self.assertEqual(data['current']['tcp'],1234)
        self.assertEqual(data['points'][-1]['cpu'],25)
        self.assertEqual(data['points'][-1]['memory'],60)
        self.assertEqual(data['points'][-1]['udp'],20)
        self.assertEqual(self.bob.get(f'/api/servers/{sid}/metrics').status_code,404)
        self.assertEqual(self.alice.get(f'/api/servers/{sid}/metrics?range=invalid').status_code,400)
        self.assertEqual(self.alice.get(f'/api/servers/{sid}/metrics?range=24h').status_code,200)
        with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(int(time.time())-100,sid))
        offline=self.alice.get(f'/api/servers/{sid}/metrics').json
        self.assertFalse(offline['online']);self.assertEqual(offline['current'],{})
        self.assertTrue(offline['points'])

    def test_one_command_enrollment_is_single_use_and_preserves_server(self):
        r=self.post('/api/servers',{'name':'quick-install'}).json;sid=r['id'];ticket=r['ticket']
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/install-ticket',json={},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,403)
        self.assertEqual(self.admin.post('/api/agent/enroll',json={'ticket':'bad'}).status_code,401)
        result=self.admin.post('/api/agent/enroll',json={'ticket':ticket})
        self.assertEqual(result.status_code,200);token=result.json['token']
        self.assertNotEqual(token,r['token'])
        self.assertEqual(self.admin.post('/api/agent/enroll',json={'ticket':ticket}).status_code,401)
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1},headers={'Authorization':'Bearer '+r['token']}).status_code,401)
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1},headers={'Authorization':'Bearer '+token}).status_code,200)
        rows=self.admin.get('/api/servers').json
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['id'],sid)
        pending=self.post(f'/api/servers/{sid}/install-ticket').json['ticket']
        # Generating a command does not interrupt the installed client.
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1},headers={'Authorization':'Bearer '+token}).status_code,200)
        with server.connect() as db:db.execute('UPDATE install_tickets SET expires=? WHERE hash=?',(int(time.time())-1,server.digest(pending)))
        self.assertEqual(self.admin.post('/api/agent/enroll',json={'ticket':pending}).status_code,401)
    def test_regenerating_install_command_revokes_previous_ticket(self):
        r=self.post('/api/servers',{'name':'ticket-node'}).json;sid=r['id']
        newer=self.post(f'/api/servers/{sid}/install-ticket').json['ticket']
        self.assertEqual(self.admin.post('/api/agent/enroll',json={'ticket':r['ticket']}).status_code,401)
        self.assertEqual(self.admin.post('/api/agent/enroll',json={'ticket':newer}).status_code,200)

    def test_admin_can_retrieve_and_edit_client_credentials(self):
        created=self.post('/api/users',{'username':'new-client','password':'initial-password-123'})
        self.assertEqual(created.status_code,201)
        user=next(u for u in self.admin.get('/api/users').json if u['username']=='new-client');uid=user['id']
        creds=self.post(f'/api/users/{uid}/credentials').json
        self.assertEqual(creds['password'],'initial-password-123')
        self.assertNotIn('password',user)
        with server.connect() as db:
            row=db.execute('SELECT password,password_encrypted FROM users WHERE id=?',(uid,)).fetchone()
            self.assertNotEqual(row['password'],'initial-password-123')
            self.assertNotIn('initial-password-123',row['password_encrypted'])
        # A fresh client object can log in, but cannot retrieve admin-only secrets.
        c=server.app.test_client();self.assertEqual(c.post('/api/login',json={'username':'new-client','password':'initial-password-123'}).status_code,200)
        csrf=c.get('/api/me').json['csrf']
        self.assertEqual(c.post(f'/api/users/{uid}/credentials',json={},headers={'X-CSRF-Token':csrf}).status_code,403)
        changed=self.admin.patch(f'/api/users/{uid}',json={'username':'renamed-client','password':'updated-password-456'},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(changed.status_code,200);self.assertEqual(c.get('/api/me').status_code,401)
        self.assertEqual(c.post('/api/login',json={'username':'renamed-client','password':'updated-password-456'}).status_code,200)
        self.assertEqual(self.post(f'/api/users/{uid}/credentials').json['password'],'updated-password-456')
        self.assertEqual(self.admin.patch(f'/api/users/{uid}',json={'username':'admin'},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,409)
        self.assertEqual(self.post('/api/users/'+str(self.admin.get('/api/me').json['id'])+'/credentials').status_code,404)
    def test_legacy_password_needs_reset_and_self_change_updates_encryption(self):
        uid=self.alice.get('/api/me').json['id']
        self.assertIsNone(self.post(f'/api/users/{uid}/credentials').json['password'])
        self.assertEqual(self.alice.post('/api/password',json={'old':'correct-password-123','new':'self-updated-password'},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,200)
        self.assertEqual(self.post(f'/api/users/{uid}/credentials').json['password'],'self-updated-password')
    def test_encryption_key_persistence_and_missing_key_protection(self):
        from credential_store import load_cipher
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            cipher=load_cipher(folder);encrypted=cipher.encrypt(b'test-only')
            self.assertEqual(load_cipher(folder,True).decrypt(encrypted),b'test-only')
            self.assertEqual((Path(folder)/'credential.key').stat().st_mode & 0o777,0o600)
            (Path(folder)/'credential.key').unlink()
            with self.assertRaises(RuntimeError):load_cipher(folder,True)

class NetworkDeltaTest(unittest.TestCase):
    def test_midnight_reset_and_missing(self):
        import sqlite3,datetime
        from network import record_network,TZ
        db=sqlite3.connect(':memory:')
        db.executescript('CREATE TABLE metric_points(server_id INTEGER,stamp INTEGER,cpu REAL,memory REAL,tcp REAL,udp REAL,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));CREATE TABLE traffic_daily(server_id INTEGER,day TEXT,rx INTEGER,tx INTEGER,PRIMARY KEY(server_id,day));CREATE TABLE network_points(server_id INTEGER,stamp INTEGER,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));')
        start=int(datetime.datetime(2026,10,22,23,59,50,tzinfo=TZ).timestamp())
        old={'rx_bytes':1000,'tx_bytes':2000,'uptime':100}
        row={'id':1,'seen':start,'metrics':json.dumps(old)}
        m={'rx_bytes':3000,'tx_bytes':6000,'uptime':120}
        record_network(db,row,m,start+20)
        self.assertEqual(m['rx_bps'],800)
        rows=db.execute('SELECT day,rx,tx FROM traffic_daily ORDER BY day').fetchall()
        self.assertEqual(rows,[('2026-10-22',1000,2000),('2026-10-23',1000,2000)])
        reset={'rx_bytes':100,'tx_bytes':200,'uptime':1}
        record_network(db,{'id':1,'seen':start+20,'metrics':json.dumps(m)},reset,start+35)
        self.assertIsNone(reset['rx_bps'])
        self.assertEqual(db.execute('SELECT SUM(rx) FROM traffic_daily').fetchone()[0],2000)
        # Long reporting gaps count observed monotonic traffic but not real-time rate.
        later={'rx_bytes':1100,'tx_bytes':2200,'uptime':121}
        record_network(db,{'id':1,'seen':start+35,'metrics':json.dumps(reset)},later,start+155)
        self.assertIsNone(later['rx_bps'])
        self.assertEqual(db.execute('SELECT SUM(rx) FROM traffic_daily').fetchone()[0],3000)
        first={'rx_bytes':999999,'tx_bytes':999999,'uptime':12}
        record_network(db,{'id':2,'seen':None,'metrics':None},first,start)
        self.assertIsNone(first['rx_bps'])
        db.close()

if __name__=='__main__':unittest.main()


