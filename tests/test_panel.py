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
        old_ip,new_ip,bad_ip,port='8.8.8.8','1.1.1.1','8.8.4.4',23456
        clock=[int(time.time())];created=[];dns_writes=[];targets={};dns_failures=[1]
        records={
            'mobile-record':{'RecordId':'mobile-record','RR':'edge','Line':'cmcc','Type':'A','Value':old_ip,'TTL':600,'Status':'ENABLE'},
            'telecom-record':{'RecordId':'telecom-record','RR':'edge','Line':'telecom','Type':'A','Value':'9.9.9.9','TTL':600,'Status':'ENABLE'},
        }
        def dns(connection,action,**params):
            if action=='DescribeDomainRecords':return {'DomainRecords':{'Record':[dict(r) for r in records.values()]}}
            if action=='UpdateDomainRecord':
                if dns_failures[0]:
                    dns_failures[0]-=1
                    raise ip_dns.IntegrationError('simulated AliDNS failure')
                self.assertEqual(params['RecordId'],'mobile-record');self.assertEqual(params['Line'],'cmcc')
                self.assertEqual(params['Value'],new_ip);self.assertEqual(params['TTL'],600)
                dns_writes.append(dict(params));records['mobile-record']['Value']=params['Value']
                return {'RecordId':'mobile-record'}
            return dict(records[params['RecordId']])
        def boce_response(url,*args,**kwargs):
            path=urlsplit(url).path;query=parse_qs(urlsplit(url).query)
            if path.endswith('/node/list'):return {'code':200,'data':{'error_code':0,'data':{'list':[{'id':13},{'id':14}]}}}
            if path.endswith('/create/tcping'):
                self.assertIn(query['host'][0],[ip+':'+str(port) for ip in [old_ip,new_ip,bad_ip]]);self.assertEqual(query['node_ids'],['13,14'])
                task='20261028_simulated_'+str(len(created)+1);created.append(task);targets[task]=query['host'][0]
                return {'code':200,'data':{'error_code':0,'data':{'id':task}}}
            self.assertIn(path.rsplit('/',1)[-1],created)
            return {'code':200,'data':{'done':True,'list':[{'node_id':i,'node_name':str(i),'packets_transmitted':10,'packets_received':10 if targets[path.rsplit('/',1)[-1]]==new_ip+':'+str(port) else 0,'error_code':0} for i in [13,14]]}}
        def saved(path,data):
            response=self.post(path,data);self.assertIn(response.status_code,(200,201),response.json);return response.json
        with patch('time.time',side_effect=lambda:clock[0]),patch('detectors.request_json',side_effect=boce_response),patch('ip_dns.alidns',side_effect=dns),patch('ip_dns.request_moonvm',side_effect=[ip_dns.IntegrationError('provider rejected (simulation)'),'accepted bad IP (simulation)','accepted good IP (simulation)']) as moonvm,patch('ip_dns.socket.create_connection',return_value=MagicMock()) as tcp,patch('detectors.queue_reboot',side_effect=AssertionError('Reboot must never be called')) as reboot:
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
            # Explicit rejection retries without a one-hour delay; accepted requests wait for IP.
            detectors.execute_change_ip_actions(server.connect,server.CIPHER);self.assertEqual(moonvm.call_count,2)
            detectors.execute_change_ip_actions(server.connect,server.CIPHER);self.assertEqual(moonvm.call_count,2)
            clock[0]+=1;report(bad_ip)
            ip_dns.check_monitor(server.connect,sid,server.CIPHER)
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            self.assertIn('等待',ip_dns.run_binding(server.connect,server.CIPHER,binding['id'],apply=True)['status'])
            self.assertEqual(dns_writes,[])
            # The first new IP is still blocked: three complete failures trigger another change.
            for n in range(3):
                if n:clock[0]+=110
                report(bad_ip);detectors.tick(server.connect,server.CIPHER)
                clock[0]+=10;detectors.tick(server.connect,server.CIPHER)
            self.assertEqual(moonvm.call_count,3)
            self.assertEqual(records['mobile-record']['Value'],old_ip)
            clock[0]+=1;report(new_ip)
            monitor=ip_dns.check_monitor(server.connect,sid,server.CIPHER);self.assertEqual(monitor['ip'],new_ip)
            with server.connect() as db:self.assertLessEqual(db.execute('SELECT next_at FROM detection_plans WHERE server_id=?',(sid,)).fetchone()[0],clock[0])
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            self.assertIn('等待',ip_dns.run_binding(server.connect,server.CIPHER,binding['id'],apply=True)['status'])
            for n in range(1):
                report(new_ip);detectors.tick(server.connect,server.CIPHER)
                clock[0]+=10;detectors.tick(server.connect,server.CIPHER)
                self.assertEqual(dns_writes,[])
                with server.connect() as db:self.assertIsNone(ip_dns.boce_dns_gate(db,sid,new_ip,port))
            self.assertEqual(len(created),7)
            # A DNS error must retry DNS only, never change an already verified IP again.
            with self.assertRaises(ip_dns.IntegrationError):ip_dns.run_binding(server.connect,server.CIPHER,binding['id'],apply=True)
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            self.assertEqual(moonvm.call_count,3)
            clock[0]+=1;report(new_ip)
            final=ip_dns.run_binding(server.connect,server.CIPHER,binding['id'],apply=True)
            self.assertIn('回读验证',final['status']);self.assertEqual(len(dns_writes),1)
            clock[0]+=11;report(new_ip)
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            tcp.assert_any_call((new_ip,port),timeout=4)
            self.assertEqual(records['mobile-record']['Value'],new_ip)
            self.assertEqual(records['telecom-record']['Value'],'9.9.9.9')
            ip_dns.run_binding(server.connect,server.CIPHER,binding['id'],apply=True)
            detectors.execute_change_ip_actions(server.connect,server.CIPHER)
            self.assertEqual(len(dns_writes),1);self.assertEqual(moonvm.call_count,3);reboot.assert_not_called()
            with server.connect() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM commands WHERE server_id=?',(sid,)).fetchone()[0],0)
                b=db.execute('SELECT * FROM dns_bindings WHERE id=?',(binding['id'],)).fetchone()
                self.assertEqual(b['expected_ip'],new_ip);self.assertIsNone(b['candidate'])
                run=db.execute('SELECT action_status FROM detection_runs WHERE server_id=? AND action_status IS NOT NULL ORDER BY id DESC LIMIT 1',(sid,)).fetchone()
                self.assertEqual(run['action_status'],'completed')
            history=self.admin.get(f'/api/servers/{sid}/ip-history').json
            self.assertEqual(history['events'][0]['addresses'],[new_ip]);self.assertEqual(history['events'][0]['previous_addresses'],[bad_ip])

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

    def test_client_can_manage_only_owned_preconfigured_dns_auto_sync(self):
        node=self.post('/api/servers',{'name':'client-dns'}).json;sid=node['id']
        uid=self.alice.get('/api/me').json['id'];headers={'X-CSRF-Token':self.tokens['alice']}
        self.admin.patch('/api/servers/'+str(sid),json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        with server.connect() as db:
            db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,443,1)',(sid,))
            conn=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('hidden','alidns','{}','secret')").lastrowid
            bid=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic,verify_new_ip) VALUES(?,?,'example.com','rec1','edge','cmcc','8.8.8.8',443,0,0)",(sid,conn)).lastrowid
        own='/api/client/servers/'+str(sid)+'/dns-bindings'
        self.assertEqual(self.alice.get(own).status_code,200)
        self.assertNotIn('secret',self.alice.get(own).text)
        self.assertEqual(self.bob.get(own).status_code,404)
        toggle='/api/client/dns-bindings/'+str(bid)
        denied=self.alice.patch(toggle,json={'automatic':True},headers=headers)
        self.assertEqual(denied.status_code,409)
        with server.connect() as db:
            source=db.execute("INSERT INTO detection_sources(name,kind,secret,enabled) VALUES('probe','self','',1)").lastrowid
            db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,automatic,interval_s,daily_limit) VALUES(?,?,?,1,120,100)",(sid,source,'[\"self\"]'))
        enabled=self.alice.patch(toggle,json={'automatic':True,'verify_new_ip':False},headers=headers)
        self.assertEqual(enabled.status_code,200)
        with server.connect() as db:
            row=db.execute('SELECT automatic,verify_new_ip FROM dns_bindings WHERE id=?',(bid,)).fetchone()
            self.assertEqual(tuple(row),(1,1))
        self.assertEqual(self.bob.patch(toggle,json={'automatic':False},headers={'X-CSRF-Token':self.tokens['bob']}).status_code,404)

    def test_client_can_configure_private_alidns_moonvm_and_automatic_action(self):
        from unittest.mock import patch
        node=self.post('/api/servers',{'name':'client-full-auto'}).json;sid=node['id']
        uid=self.alice.get('/api/me').json['id'];ah={'X-CSRF-Token':self.tokens['alice']}
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        self.admin.post('/api/agent/report',json={'public_ips':['8.8.8.8'],'uptime':100},headers={'Authorization':'Bearer '+node['token']})
        monitor=self.alice.patch(f'/api/client/servers/{sid}/monitor',json={'port':23456,'enabled':True},headers=ah)
        self.assertEqual(monitor.status_code,200,monitor.json)
        with patch('detectors.boce',return_value={'data':{'list':[{'id':13,'node_name':'上海电信','isp_name':'电信'}]}}):
            saved=self.alice.post(f'/api/client/servers/{sid}/probe-source',json={'secret':'client-boce-private-key'},headers=ah)
            self.assertEqual(saved.status_code,200,saved.json)
            configured=self.alice.put(f'/api/client/servers/{sid}/probe-config',json={'source_id':saved.json['source_id'],'nodes':['13'],'interval_s':120,'daily_limit':100,'automatic':True},headers=ah)
            self.assertEqual(configured.status_code,200,configured.json)
        record={'RecordId':'record-client-1','RR':'edge','Line':'cmcc','Type':'A','Value':'8.8.8.8','TTL':600,'Status':'ENABLE'}
        with patch('ip_dns.alidns',return_value={'DomainRecords':{'Record':[record]},'TotalCount':1}):
            ali=self.alice.post(f'/api/client/servers/{sid}/dns-connections',json={'name':'Alice AliDNS','config':{'access_key_id':'client-access-key-id'},'secret':'client-access-key-secret','domain':'example.com'},headers=ah)
            self.assertEqual(ali.status_code,201,ali.json)
            self.assertNotIn('client-access-key-secret',ali.text)
            binding=self.alice.post(f'/api/client/servers/{sid}/dns-bindings',json={'connection_id':ali.json['connection']['id'],'domain':'example.com','record_id':'record-client-1','rr':'edge','line':'cmcc'},headers=ah)
            self.assertEqual(binding.status_code,200,binding.json)
        enabled=self.alice.patch(f"/api/client/dns-bindings/{binding.json['id']}",json={'automatic':True},headers=ah)
        self.assertEqual(enabled.status_code,200,enabled.json)
        moon='https://store.moonvm.com/ddns.php?product=13688&flag=changeip&iptoken=client-token-12345678'
        action=self.alice.post(f'/api/client/servers/{sid}/change-ip-api',json={'url':moon},headers=ah)
        self.assertEqual(action.status_code,201,action.json)
        self.assertNotIn('client-token-12345678',action.text)
        result=self.alice.put(f'/api/client/servers/{sid}/action-config',json={'response_mode':'change_api','action_connection_id':action.json['connection']['id'],'action_enabled':True,'failure_threshold':3},headers=ah)
        self.assertEqual(result.status_code,200,result.json)
        with server.connect() as db:
            plan=db.execute('SELECT p.response_mode,p.action_enabled,p.action_connection_id,c.owner_id,c.server_id FROM detection_plans p JOIN ip_connections c ON c.id=p.action_connection_id WHERE p.server_id=?',(sid,)).fetchone()
            self.assertEqual((plan['response_mode'],plan['action_enabled'],plan['owner_id'],plan['server_id']),('change_api',1,uid,sid))
            self.assertNotEqual(db.execute('SELECT secret FROM ip_connections WHERE id=?',(ali.json['connection']['id'],)).fetchone()['secret'],'client-access-key-secret')
        self.assertEqual(self.bob.get(f'/api/client/servers/{sid}/dns-bindings').status_code,404)
        self.assertNotIn('client-access-key-id',self.admin.get('/api/ip-dns').text)
        self.assertEqual(self.admin.patch(f'/api/servers/{sid}',json={'owner_id':self.bob.get('/api/me').json['id']},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,200)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM ip_connections WHERE owner_id=? AND server_id=?',(uid,sid)).fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM dns_bindings WHERE server_id=?',(sid,)).fetchone()[0],0)
            plan=db.execute('SELECT owner_id,response_mode,action_enabled,action_connection_id FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
            self.assertEqual(tuple(plan),(None,'none',0,None))

    def test_client_can_bind_cloudflare_record_and_sync_new_ip_without_losing_proxy_settings(self):
        from unittest.mock import patch, MagicMock
        node=self.post('/api/servers',{'name':'client-cloudflare'}).json;sid=node['id']
        uid=self.alice.get('/api/me').json['id'];headers={'X-CSRF-Token':self.tokens['alice']}
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        self.admin.post('/api/agent/report',json={'public_ips':['8.8.8.8'],'uptime':100},headers={'Authorization':'Bearer '+node['token']})
        self.assertEqual(self.alice.patch(f'/api/client/servers/{sid}/monitor',json={'port':443,'enabled':True},headers=headers).status_code,200)
        zone={'id':'a'*32,'name':'example.com','status':'active'}
        record={'id':'b'*32,'name':'edge.example.com','type':'A','content':'8.8.8.8','ttl':1,'proxied':True,'comment':'origin','tags':['managed'],'settings':{}}
        def records(connection):
            self.assertEqual(connection['secret'],'customer-cloudflare-token')
            return [{'RecordId':record['id'],'RR':'edge','Type':'A','Line':'default','Value':record['content'],'TTL':record['ttl'],'Status':'ENABLE','Proxied':record['proxied']}]
        with patch('ip_dns.cloudflare_find_zone',return_value=zone),patch('ip_dns.cloudflare_records',side_effect=records):
            saved=self.alice.post(f'/api/client/servers/{sid}/dns-connections',json={'provider':'cloudflare','name':'Alice Cloudflare','domain':'example.com','config':{},'secret':'customer-cloudflare-token'},headers=headers)
            self.assertEqual(saved.status_code,201,saved.json)
            self.assertNotIn('customer-cloudflare-token',saved.text)
            binding=self.alice.post(f'/api/client/servers/{sid}/dns-bindings',json={'connection_id':saved.json['connection']['id'],'domain':'example.com','record_id':record['id'],'rr':'edge','line':'default'},headers=headers)
            self.assertEqual(binding.status_code,200,binding.json)
        own=self.alice.get(f'/api/client/servers/{sid}/dns-bindings')
        self.assertEqual(own.json['bindings'][0]['dns_provider'],'cloudflare')
        self.assertEqual(own.json['connections'][0]['zone_name'],'example.com')
        self.assertEqual(self.bob.get(f'/api/client/servers/{sid}/dns-bindings').status_code,404)
        self.assertNotIn('customer-cloudflare-token',self.admin.get('/api/ip-dns').text)

        self.admin.post('/api/agent/report',json={'public_ips':['9.9.9.9'],'uptime':200},headers={'Authorization':'Bearer '+node['token']})
        record_new=dict(record,content='9.9.9.9')
        with patch('ip_dns.cloudflare_record',side_effect=[record,record,record_new]),patch('ip_dns.update_cloudflare_record',return_value=record_new) as update,patch('ip_dns.socket.create_connection',return_value=MagicMock()):
            with server.connect() as db:db.execute('UPDATE dns_bindings SET verify_new_ip=0 WHERE id=?',(binding.json['id'],))
            result=self.alice.post(f"/api/client/dns-bindings/{binding.json['id']}/check",json={'apply':True},headers=headers)
            self.assertEqual(result.status_code,200,result.json)
            args=update.call_args.args
            self.assertEqual(args[1]['proxied'],True)
            self.assertEqual(args[1]['ttl'],1)
            self.assertEqual(args[1]['comment'],'origin')
            self.assertEqual(args[1]['tags'],['managed'])
            self.assertEqual(args[2],'9.9.9.9')
        with server.connect() as db:self.assertEqual(db.execute('SELECT expected_ip FROM dns_bindings WHERE id=?',(binding.json['id'],)).fetchone()[0],'9.9.9.9')

    def test_client_can_set_private_boce_key_and_probe_nodes_for_owned_server(self):
        from unittest.mock import patch
        node=self.post('/api/servers',{'name':'client-probe'}).json;sid=node['id']
        uid=self.alice.get('/api/me').json['id'];headers={'X-CSRF-Token':self.tokens['alice']}
        self.admin.patch('/api/servers/'+str(sid),json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        with server.connect() as db:
            db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,443,1)',(sid,))
            shared=db.execute("INSERT INTO detection_sources(name,kind,secret,enabled) VALUES('shared probe','boce',?,1)",(server.CIPHER.encrypt(b'shared-secret').decode(),)).lastrowid
            db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,daily_limit,response_mode,action_enabled) VALUES(?,?,?,600,1,300,'reboot',0)",(sid,shared,'[\"13\"]'))
        own='/api/client/servers/'+str(sid)+'/probe-config'
        result=self.alice.get(own)
        self.assertEqual(result.status_code,200)
        self.assertNotIn('secret',result.text);self.assertNotIn('shared-secret',result.text)
        self.assertEqual(result.json['sources'],[])
        self.assertIsNone(result.json['plan']['source_id'])
        self.assertNotIn('response_mode',result.json['plan']);self.assertNotIn('action_enabled',result.json['plan'])
        self.assertEqual(self.bob.get(own).status_code,404)
        nodes=[{'id':13,'node_name':'上海电信','isp_name':'电信'},{'id':27,'node_name':'广州联通','isp_name':'联通'}]
        self.assertEqual(self.alice.post(f'/api/client/servers/{sid}/probe-source',json={'secret':'client-private-boce-key'}).status_code,403)
        with patch('detectors.boce',return_value={'data':{'list':nodes}}) as boce:
            saved=self.alice.post(f'/api/client/servers/{sid}/probe-source',json={'secret':'client-private-boce-key'},headers=headers)
            self.assertEqual(saved.status_code,200,saved.json)
            self.assertEqual([x['id'] for x in saved.json['nodes']],['13','27'])
            self.assertEqual(boce.call_args.args[0],'client-private-boce-key')
            self.assertNotIn('client-private-boce-key',saved.text)
            source_id=saved.json['source_id']
            shared_choice=self.alice.put(own,json={'source_id':shared,'nodes':['13'],'interval_s':240,'daily_limit':500,'automatic':False},headers=headers)
            self.assertEqual(shared_choice.status_code,404)
            response=self.alice.put(own,json={'source_id':source_id,'nodes':['13','27'],'interval_s':240,'daily_limit':500,'automatic':False,'response_mode':'change_api'},headers=headers)
            self.assertEqual(response.status_code,200,response.json)
            self.assertEqual({x['id'] for x in self.alice.get(own).json['sources']},{source_id})
        with server.connect() as db:
            source=db.execute('SELECT owner_id,server_id,secret FROM detection_sources WHERE id=?',(source_id,)).fetchone()
            self.assertEqual((source['owner_id'],source['server_id']),(uid,sid))
            self.assertNotEqual(source['secret'],'client-private-boce-key')
            plan=db.execute('SELECT source_id,nodes,interval_s,daily_limit,automatic,response_mode,action_enabled FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
            self.assertEqual((plan['source_id'],plan['nodes'],plan['interval_s'],plan['daily_limit'],plan['automatic'],plan['response_mode'],plan['action_enabled']),(source_id,'["13", "27"]',240,500,0,'reboot',0))
        self.assertEqual(self.bob.post(f'/api/client/servers/{sid}/probe-sources/{source_id}/nodes',json={},headers={'X-CSRF-Token':self.tokens['bob']}).status_code,404)
        with patch('detectors.boce',return_value={'data':{'list':nodes}}):
            self.assertEqual(self.alice.put(own,json={'source_id':shared,'nodes':['999'],'interval_s':240,'daily_limit':500,'automatic':False},headers=headers).status_code,404)
            with server.connect() as db:db.execute("UPDATE detection_plans SET automatic=0,action_enabled=1,response_mode='reboot',owner_id=NULL WHERE server_id=?",(sid,))
            safe=self.alice.get(own).json['plan']
            self.assertTrue(safe['actions_locked']);self.assertNotIn('response_mode',safe);self.assertNotIn('action_enabled',safe)
            blocked=self.alice.put(own,json={'source_id':source_id,'nodes':['13','27'],'interval_s':240,'daily_limit':500,'automatic':True},headers=headers)
            self.assertEqual(blocked.status_code,409)
            blocked=self.alice.put(own,json={'source_id':source_id,'nodes':['13'],'interval_s':240,'daily_limit':500,'automatic':False},headers=headers)
            self.assertEqual(blocked.status_code,409)
            paused=self.alice.put(own,json={'source_id':source_id,'nodes':['13','27'],'interval_s':240,'daily_limit':500,'automatic':False},headers=headers)
            self.assertEqual(paused.status_code,200,paused.json)
            pause_endpoint=self.alice.patch(f'/api/client/servers/{sid}/probe-config',json={'automatic':False},headers=headers)
            self.assertEqual(pause_endpoint.status_code,200,pause_endpoint.json)
            self.assertEqual(self.alice.patch(f'/api/client/servers/{sid}/probe-config',json={'automatic':True},headers=headers).status_code,403)

    def test_client_vps_rotation_switches_dns_drains_connections_and_refreshes_standby_ip(self):
        from unittest.mock import patch, MagicMock
        import rotation
        uid=self.alice.get('/api/me').json['id'];headers={'X-CSRF-Token':self.tokens['alice']}
        nodes=[];ips=['8.8.8.8','1.1.1.1'];port=23456;now=int(time.time())
        for label in ('primary','standby'):
            node=self.post('/api/servers',{'name':'rotation-'+label}).json;sid=node['id'];nodes.append((sid,node['token']))
            self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
            with server.connect() as db:
                db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,?,1)',(sid,port))
                source=db.execute("INSERT INTO detection_sources(name,kind,secret,enabled,owner_id,server_id) VALUES(?, 'boce', ?,1,?,?)",('BOCE '+label,server.CIPHER.encrypt(b'private-boce').decode(),uid,sid)).lastrowid
                action=db.execute("INSERT INTO ip_connections(name,kind,config,secret,owner_id,server_id) VALUES(?,'change_ip',?,?,?,?)",('MoonVM '+label,json.dumps({'provider':'moonvm','product':'12345'}),server.CIPHER.encrypt(b'private-token-'+label.encode()).decode(),uid,sid)).lastrowid
                db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,daily_limit,next_at,response_mode,action_connection_id,failure_threshold,owner_id) VALUES(?,?,?,120,1,1000,?,'change_api',?,3,?)",(sid,source,'[\"13\"]',now,action,uid))
        binding_id=None
        with server.connect() as db:
            dns=db.execute("INSERT INTO ip_connections(name,kind,config,secret,owner_id,server_id) VALUES('Rotation DNS','alidns',?,?,?,?)",(json.dumps({'access_key_id':'test-id'}),server.CIPHER.encrypt(b'private-dns-secret').decode(),uid,nodes[0][0])).lastrowid
            binding_id=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic) VALUES(?,?,'example.com','record-1','edge','default',?,?,0)",(nodes[0][0],dns,ips[0],port)).lastrowid
        clock=[now]
        record={'RecordId':'record-1','RR':'edge','Line':'default','Type':'A','Value':ips[0],'TTL':60,'Status':'ENABLE'}
        def report(i,tcp=25):
            sid,token=nodes[i]
            return self.admin.post('/api/agent/report',json={'public_ips':[],'egress_ips':[ips[i]],'egress_checked':clock[0],'connections_sampled':clock[0],'tcp':tcp,'udp':0,'uptime':clock[0],'rx_bytes':0,'tx_bytes':0},headers={'Authorization':'Bearer '+token})
        with patch('time.time',side_effect=lambda:clock[0]),patch('rotation.get_dns_record',side_effect=lambda *_:dict(record)),patch('rotation.update_dns_record',side_effect=lambda _c,_b,_r,new:(record.update(Value=new) or dict(record))),patch('rotation.socket.create_connection',return_value=MagicMock()),patch('rotation.invoke_change_ip_api',return_value='换 IP 已受理') as change:
            self.assertEqual(report(0).status_code,200);self.assertEqual(report(1).status_code,200)
            with server.connect() as db:
                for i,(sid,_) in enumerate(nodes):
                    source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(sid,)).fetchone()[0]
                    db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details) VALUES(?,?,?,?,'[\"13\"]','所选检测点 TCP 可达',?,?,?)",(sid,source,ips[i],port,clock[0]-10,clock[0],json.dumps([{'node_id':'13','state':'reachable'}])))
            with server.connect() as db:db.execute("UPDATE detection_plans SET response_mode='none',action_connection_id=NULL WHERE server_id=?",(nodes[1][0],))
            with server.connect() as db:db.execute('UPDATE dns_bindings SET automatic=1 WHERE id=?',(binding_id,))
            preflight=self.alice.post(f'/api/client/servers/{nodes[0][0]}/rotation/readiness',json={'other_server_id':nodes[1][0],'binding_id':binding_id},headers=headers)
            self.assertEqual(preflight.status_code,200,preflight.json);self.assertTrue(preflight.json['ok'],preflight.json)
            self.assertEqual(change.call_count,0);self.assertEqual(record['Value'],ips[0])
            config=self.alice.put(f'/api/client/servers/{nodes[0][0]}/rotation',json={'other_server_id':nodes[1][0],'binding_id':binding_id,'interval_s':7200,'connection_threshold':80,'enabled':True},headers=headers)
            self.assertEqual(config.status_code,200,config.json)
            self.assertEqual(config.json['rotation']['active_server_id'],nodes[0][0])
            self.assertEqual(config.json['rotation']['next_switch_at'],clock[0]+7200-120)
            self.assertEqual(self.bob.get(f'/api/client/servers/{nodes[0][0]}/rotation').status_code,404)
            self.assertEqual(self.alice.patch(f'/api/client/dns-bindings/{binding_id}',json={'automatic':True},headers=headers).status_code,409)
            with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE binding_id=?',(clock[0]-1,binding_id))
            rotation.tick(server.connect,server.CIPHER)
            with server.connect() as db:
                row=db.execute('SELECT * FROM vps_rotations WHERE binding_id=?',(binding_id,)).fetchone()
                self.assertEqual(row['phase'],'draining');self.assertEqual(row['active_server_id'],nodes[1][0]);self.assertEqual(row['drain_server_id'],nodes[0][0])
                self.assertEqual(row['drain_grace_s'],120)
                self.assertEqual(db.execute('SELECT expected_ip FROM dns_bindings WHERE id=?',(binding_id,)).fetchone()[0],ips[1])
            rotation.tick(server.connect,server.CIPHER)
            with server.connect() as db:self.assertEqual(db.execute('SELECT low_samples FROM vps_rotations').fetchone()[0],0)
            with server.connect() as db:
                row=db.execute('SELECT * FROM vps_rotations WHERE binding_id=?',(binding_id,)).fetchone()
                db.execute('UPDATE vps_rotations SET drain_started=?,drain_grace_s=0 WHERE id=?',(clock[0]-100,row['id']))
            clock[0]+=15;self.assertEqual(report(0,tcp=80).status_code,200);rotation.tick(server.connect,server.CIPHER)
            with server.connect() as db:self.assertEqual(db.execute('SELECT low_samples FROM vps_rotations').fetchone()[0],0)
            clock[0]+=15;self.assertEqual(report(0,tcp=70).status_code,200);rotation.tick(server.connect,server.CIPHER)
            with server.connect() as db:self.assertEqual(db.execute('SELECT low_samples FROM vps_rotations').fetchone()[0],1)
            clock[0]+=15;self.assertEqual(report(0,tcp=70).status_code,200);rotation.tick(server.connect,server.CIPHER)
            self.assertEqual(change.call_count,1)
            with server.connect() as db:self.assertEqual(db.execute('SELECT phase FROM vps_rotations').fetchone()[0],'waiting_ip')
            ips[0]='9.9.9.9';clock[0]+=10;self.assertEqual(report(0,tcp=30).status_code,200);rotation.tick(server.connect,server.CIPHER)
            with server.connect() as db:
                row=db.execute('SELECT * FROM vps_rotations').fetchone();self.assertEqual(row['phase'],'waiting_probe')
                source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(nodes[0][0],)).fetchone()[0]
                db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details) VALUES(?,?,?,?,'[\"13\"]','所选检测点 TCP 可达',?,?,?)",(nodes[0][0],source,ips[0],port,clock[0],clock[0],json.dumps([{'node_id':'13','state':'reachable'}])))
            clock[0]+=5;rotation.tick(server.connect,server.CIPHER)
            with server.connect() as db:
                row=db.execute('SELECT * FROM vps_rotations').fetchone()
                self.assertEqual(row['phase'],'active');self.assertEqual(row['active_server_id'],nodes[1][0]);self.assertIsNone(row['drain_server_id'])
            self.assertEqual(change.call_count,1)
            # Active B fails before its timer: return DNS to healthy A, bypass B's 200 connections.
            self.assertEqual(report(1,tcp=200).status_code,200)
            with server.connect() as db:
                source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(nodes[1][0],)).fetchone()[0]
                db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details) VALUES(?,?,?,?,'[\"13\"]','国内不通',?,?,?)",(nodes[1][0],source,ips[1],port,clock[0],clock[0],json.dumps([{'node_id':'13','state':'unreachable'}])))
            rotation.tick(server.connect,server.CIPHER)
            with server.connect() as db:
                row=db.execute('SELECT * FROM vps_rotations').fetchone()
                self.assertEqual(row['active_server_id'],nodes[0][0])
                self.assertEqual(row['phase'],'waiting_ip')
                self.assertEqual(row['emergency'],1)
            self.assertEqual(change.call_count,2)
            reassigned=self.admin.patch(f'/api/servers/{nodes[1][0]}',json={'owner_id':self.bob.get('/api/me').json['id']},headers={'X-CSRF-Token':self.tokens['admin']})
            self.assertEqual(reassigned.status_code,200,reassigned.json)
            with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_rotations').fetchone()[0],0)

    def test_personal_boce_configuration_flow_is_available_to_multiple_customers(self):
        from unittest.mock import patch
        nodes={'data':{'list':[{'id':13,'node_name':'上海电信','isp_name':'电信'}]}}
        users=[('alice',self.alice),('bob',self.bob)]
        with patch('detectors.boce',return_value=nodes):
            for username,client in users:
                server_node=self.post('/api/servers',{'name':'personal-boce-'+username}).json
                sid=server_node['id'];uid=client.get('/api/me').json['id']
                self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
                with server.connect() as db:db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,443,1)',(sid,))
                headers={'X-CSRF-Token':self.tokens[username]};endpoint=f'/api/client/servers/{sid}'
                self.assertEqual(client.get(endpoint+'/probe-config').json['sources'],[])
                # Exercise first-time save, update, and re-read as separate customer sessions.
                for revision in (1,2):
                    key=f'{username}-private-boce-key-{revision}'
                    saved=client.post(endpoint+'/probe-source',json={'secret':key},headers=headers)
                    self.assertEqual(saved.status_code,200,saved.json)
                    source_id=saved.json['source_id']
                    self.assertNotIn(key,saved.text)
                    state=client.get(endpoint+'/probe-config').json
                    self.assertEqual([source['id'] for source in state['sources']],[source_id])
                    self.assertEqual(state['sources'][0]['personal'],1)
                    configured=client.put(endpoint+'/probe-config',json={'source_id':source_id,'nodes':['13'],'interval_s':240,'daily_limit':300,'automatic':True},headers=headers)
                    self.assertEqual(configured.status_code,200,configured.json)
                    self.assertEqual(client.get(endpoint+'/probe-config').json['plan']['source_id'],source_id)
                other=self.bob if username=='alice' else self.alice
                self.assertEqual(other.get(endpoint+'/probe-config').status_code,404)


    def test_server_reassignment_disables_and_clears_previous_customer_boce_key(self):
        from unittest.mock import patch
        node=self.post('/api/servers',{'name':'handoff'}).json;sid=node['id']
        alice_id=self.alice.get('/api/me').json['id'];bob_id=self.bob.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':alice_id},headers={'X-CSRF-Token':self.tokens['admin']})
        with server.connect() as db:db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,443,1)',(sid,))
        with patch('detectors.boce',return_value={'data':{'list':[{'id':13,'node_name':'node'}]}}):
            saved=self.alice.post(f'/api/client/servers/{sid}/probe-source',json={'secret':'alice-private-key'},headers={'X-CSRF-Token':self.tokens['alice']})
            self.assertEqual(saved.status_code,200,saved.json)
            configured=self.alice.put(f'/api/client/servers/{sid}/probe-config',json={'source_id':saved.json['source_id'],'nodes':['13'],'interval_s':120,'daily_limit':100,'automatic':True},headers={'X-CSRF-Token':self.tokens['alice']})
            self.assertEqual(configured.status_code,200,configured.json)
        assigned=self.admin.patch(f'/api/servers/{sid}',json={'owner_id':bob_id},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(assigned.status_code,200,assigned.json)
        with server.connect() as db:
            source=db.execute('SELECT enabled,secret FROM detection_sources WHERE id=?',(saved.json['source_id'],)).fetchone()
            self.assertEqual(source['enabled'],0)
            self.assertEqual(server.CIPHER.decrypt(source['secret'].encode()),b'')
            plan=db.execute('SELECT automatic,action_enabled,response_mode FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
            self.assertEqual(tuple(plan),(0,0,'none'))
        self.assertEqual(self.alice.get(f'/api/client/servers/{sid}/probe-config').status_code,404)
        self.assertEqual(self.bob.get(f'/api/client/servers/{sid}/probe-config').json['sources'],[])

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
        with server.connect() as db:
            source=db.execute("INSERT INTO detection_sources(name,kind,secret,enabled) VALUES('test probe','self','',1)").lastrowid
            db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,next_at,response_mode) VALUES(?,?,?,?,?,?,?)",(sid,source,'[\"self\"]',600,1,int(time.time())+600,'reboot'))
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
        with server.connect() as db:self.assertLessEqual(db.execute('SELECT next_at FROM detection_plans WHERE server_id=?',(sid,)).fetchone()[0],int(time.time()))
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


