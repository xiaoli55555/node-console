"""Plan-only failover saves and metadata-only labels preserve live identity."""
import json
import unittest
from unittest.mock import patch
import test_panel as panel_fixture
import test_rotation_multi as rotation_fixture
import server
import failover
from ip_dns import IntegrationError


class Labels(unittest.TestCase):
    setUp=panel_fixture.PanelTest.setUp
    post=panel_fixture.PanelTest.post

    def patch(self,path,data):
        return self.admin.patch(path,json=data,headers={'X-CSRF-Token':self.tokens['admin']})

    def test_vps_rename_preserves_owner_agent_and_customer_credentials(self):
        n=self.post('/api/servers',{'name':'old'}).json
        uid=self.alice.get('/api/me').json['id']
        self.assertEqual(self.patch('/api/servers/'+str(n['id']),{'owner_id':uid}).status_code,200)
        with server.connect() as db:
            before=dict(db.execute('SELECT * FROM servers WHERE id=?',(n['id'],)).fetchone())
            cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret,owner_id,server_id) VALUES('private','change_ip','{}','encrypted',?,?)",(uid,n['id'])).lastrowid
        self.assertEqual(self.patch('/api/servers/'+str(n['id']),{'name':'  HKT 主承载  '}).status_code,200)
        with server.connect() as db:
            after=dict(db.execute('SELECT * FROM servers WHERE id=?',(n['id'],)).fetchone())
            self.assertTrue(db.execute('SELECT 1 FROM ip_connections WHERE id=?',(cid,)).fetchone())
        self.assertEqual(after['name'],'HKT 主承载')
        self.assertEqual({k:v for k,v in before.items() if k!='name'},{k:v for k,v in after.items() if k!='name'})

    def test_names_validate_and_customer_cannot_rename_admin_objects(self):
        n=self.post('/api/servers',{'name':'old'}).json
        for bad in ('',' '*5,'x'*65,12,True,None):
            self.assertEqual(self.patch('/api/servers/'+str(n['id']),{'name':bad}).status_code,400)
        self.assertEqual(self.alice.patch('/api/servers/'+str(n['id']),json={'name':'new'},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,403)
        self.assertEqual(self.patch('/api/servers/999999',{'name':'new'}).status_code,404)

    def test_moonvm_custom_name_and_metadata_rename_preserve_secret(self):
        payload={'name':'HKT2 · MoonVM','kind':'change_ip','config':{'provider':'moonvm','url':'https://store.moonvm.com/ddns.php?product=12345&flag=changeip&iptoken=dummy-token-12345'}}
        with patch('ip_dns.request_moonvm') as action:
            saved=self.post('/api/ip-dns/connections',payload)
            self.assertEqual(saved.status_code,200,saved.json);cid=saved.json['id']
            with server.connect() as db:before=dict(db.execute('SELECT * FROM ip_connections WHERE id=?',(cid,)).fetchone())
            self.assertEqual(before['name'],payload['name'])
            self.assertEqual(self.patch('/api/ip-dns/connections/'+str(cid),{'name':'移动备用 · API'}).status_code,200)
            action.assert_not_called()
        with server.connect() as db:after=dict(db.execute('SELECT * FROM ip_connections WHERE id=?',(cid,)).fetchone())
        self.assertEqual(after['name'],'移动备用 · API')
        self.assertEqual({k:v for k,v in before.items() if k!='name'},{k:v for k,v in after.items() if k!='name'})
        self.assertEqual(self.patch('/api/ip-dns/connections/'+str(cid),{'name':'new','secret':'changed'}).status_code,400)

    def test_hkt_custom_name_and_rename_do_not_reset_generated_token(self):
        n=self.post('/api/servers',{'name':'HKT2'}).json
        self.admin.post('/api/agent/report',json={'capabilities':['hkt_dhcp'],'public_ips':['42.98.100.156'],'uptime':1000},headers={'Authorization':'Bearer '+n['token']})
        path=f'/api/admin/servers/{n["id"]}/hkt-dhcp/api'
        cfg=self.post(path,{'name':'HKT2 · DHCP API'}).json;cid=cfg['connection_id']
        with server.connect() as db:before=dict(db.execute('SELECT * FROM hkt_dhcp_apis WHERE server_id=?',(n['id'],)).fetchone())
        self.assertEqual(self.patch('/api/ip-dns/connections/'+str(cid),{'name':'联通主机 · DHCP'}).status_code,200)
        overview=self.admin.get('/api/ip-dns').json
        api=next(c for c in overview['connections'] if c['id']==cid)
        self.assertEqual(api['used_by'],[{'id':n['id'],'name':'HKT2'}])
        self.assertNotIn(cfg['token'],json.dumps(api))
        with server.connect() as db:
            self.assertEqual(dict(db.execute('SELECT * FROM hkt_dhcp_apis WHERE server_id=?',(n['id'],)).fetchone()),before)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commands WHERE server_id=?',(n['id'],)).fetchone()[0],0)
        self.post(path)
        with server.connect() as db:self.assertEqual(db.execute('SELECT name FROM ip_connections WHERE id=?',(cid,)).fetchone()[0],'联通主机 · DHCP')

    def test_private_api_cannot_be_renamed_by_admin_endpoint(self):
        uid=self.alice.get('/api/me').json['id']
        with server.connect() as db:cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret,owner_id) VALUES('private','change_ip','{}','encrypted',?)",(uid,)).lastrowid
        self.assertEqual(self.patch('/api/ip-dns/connections/'+str(cid),{'name':'new'}).status_code,403)


class PlanFailover(unittest.TestCase):
    setUp=rotation_fixture.MultiPlan.setUp
    tearDown=rotation_fixture.MultiPlan.tearDown
    post=rotation_fixture.MultiPlan.post
    sid=rotation_fixture.MultiPlan.sid
    refresh=rotation_fixture.MultiPlan.refresh
    save=rotation_fixture.MultiPlan.save
    row=rotation_fixture.MultiPlan.row
    put=rotation_fixture.MultiPlan.put
    drop_first=rotation_fixture.MultiPlan.drop_first
    multi=rotation_fixture.MultiPlan.multi

    def patch(self,data):
        return self.admin.patch(f'/api/admin/rotations/{self.rid}/failover',json=data,headers={'X-CSRF-Token':self.tokens['admin']})

    def test_save_preserves_schedule_and_inflight_state_without_actions(self):
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,action_attempts=2,force_drain_threshold=180 WHERE id=?",(self.sid('B'),self.clock[0],self.rid))
        before=self.row();records=json.dumps(self.records,sort_keys=True)
        result=self.patch({'failover_server_id':self.sid('C'),'failover_recovery_s':45})
        self.assertEqual(result.status_code,200,result.json)
        after=self.row()
        for key in ('phase','enabled','active_server_id','next_switch_at','drain_server_id','drain_started','action_started','action_attempts','force_drain_threshold'):
            self.assertEqual(after[key],before[key],key)
        self.assertEqual(after['failover_server_id'],self.sid('C'));self.assertEqual(after['failover_recovery_s'],45)
        self.assertEqual(json.dumps(self.records,sort_keys=True),records);self.change.assert_not_called()

    def test_multi_record_group_is_saved_atomically(self):
        self.multi()
        result=self.patch({'failover_server_id':self.sid('C')})
        self.assertEqual(result.status_code,200,result.json)
        with server.connect() as db:self.assertEqual({r[0] for r in db.execute('SELECT failover_server_id FROM vps_rotations')},{self.sid('C')})
        self.assertEqual(self.patch({'failover_server_id':None}).status_code,200)
        actual=failover.configure;calls=[]
        def reject_second(db,cipher,rid,body,now):
            calls.append(rid)
            if len(calls)==2:raise IntegrationError('injected second-record validation failure')
            return actual(db,cipher,rid,body,now)
        with patch('failover.configure',side_effect=reject_second):
            self.assertEqual(self.patch({'failover_server_id':self.sid('C')}).status_code,409)
        with server.connect() as db:self.assertEqual({r[0] for r in db.execute('SELECT failover_server_id FROM vps_rotations')},{None})

    def test_takeover_and_invalid_changes_are_rejected(self):
        for bad in (True,'3',self.sid('A'),self.sid('B'),999999):
            self.assertNotEqual(self.patch({'failover_server_id':bad}).status_code,200)
        self.assertEqual(self.patch({'failover_server_id':self.sid('C'),'interval_s':60}).status_code,400)
        self.assertEqual(self.patch({'failover_server_id':self.sid('C')}).status_code,200)
        with server.connect() as db:
            db.execute("INSERT INTO vps_failover_leases(binding_id,rotation_id,original_ip,current_ip,updated) VALUES(?,?,'8.8.8.8','9.9.9.9',?)",(self.bindings['mobile'],self.rid,self.clock[0]))
        self.assertEqual(self.patch({'failover_server_id':None}).status_code,409)
        self.assertEqual(self.alice.patch(f'/api/admin/rotations/{self.rid}/failover',json={'failover_server_id':None},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,403)
