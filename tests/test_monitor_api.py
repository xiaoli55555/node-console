"""Read-only credentials are scoped, revocable, and cannot leak provider data."""
import json
import unittest
from unittest.mock import patch
import test_failover as fixture
import server

class MonitorAPI(unittest.TestCase):
    setUpBase=fixture.PrimaryFailover.setUp
    tearDown=fixture.PrimaryFailover.tearDown
    post=fixture.PrimaryFailover.post
    sid=fixture.PrimaryFailover.sid
    refresh=fixture.PrimaryFailover.refresh
    save=fixture.PrimaryFailover.save
    def setUp(self):
        self.setUpBase()
        with server.connect() as db:db.execute('DELETE FROM monitor_tokens')
    def issue(self):
        r=self.post('/api/admin/monitor-token',{})
        self.assertEqual(r.status_code,201,r.json)
        return r.json['token']
    def read(self,token,path='/api/monitor/snapshot'):
        return server.app.test_client().get(path,headers={'Authorization':'Bearer '+token})
    def test_snapshot_requires_bearer_not_cookie_or_query(self):
        key=self.issue()
        self.assertEqual(self.admin.get('/api/monitor/snapshot').status_code,401)
        self.assertEqual(self.read('incorrect').status_code,401)
        self.assertEqual(server.app.test_client().get('/api/monitor/snapshot?token='+key).status_code,401)
        self.assertEqual(self.read(key).status_code,200)
    def test_rotation_and_revocation_invalidate_previous_key(self):
        old=self.issue();new=self.issue()
        self.assertEqual(self.read(old).status_code,401)
        self.assertEqual(self.read(new).status_code,200)
        self.assertEqual(self.admin.delete('/api/admin/monitor-token',headers={'X-CSRF-Token':self.tokens['admin']}).status_code,200)
        self.assertEqual(self.read(new).status_code,401)
    def test_expiry_and_hash_only_storage(self):
        key=self.issue()
        with server.connect() as db:
            row=db.execute('SELECT * FROM monitor_tokens').fetchone()
            self.assertNotIn(key,str(dict(row)))
            db.execute('UPDATE monitor_tokens SET expires=?',(self.clock[0]-1,))
        self.assertEqual(self.read(key).status_code,401)
    def test_readonly_token_has_no_admin_or_agent_permissions(self):
        key=self.issue();client=server.app.test_client();headers={'Authorization':'Bearer '+key}
        self.assertEqual(client.post('/api/admin/monitor-token',headers=headers,json={}).status_code,401)
        self.assertEqual(client.post('/api/agent/report',headers=headers,json={}).status_code,401)
        self.assertEqual(client.get('/api/servers',headers=headers).status_code,401)
        self.assertEqual(client.post('/api/monitor/snapshot',headers=headers,json={}).status_code,405)
    def test_management_requires_admin_session_and_csrf(self):
        self.assertEqual(self.admin.post('/api/admin/monitor-token',json={}).status_code,403)
        self.assertEqual(server.app.test_client().get('/api/admin/monitor-token').status_code,401)
        self.assertEqual(self.alice.get('/api/admin/monitor-token').status_code,403)
        self.assertEqual(self.alice.post('/api/admin/monitor-token',json={},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,403)
    def test_snapshot_is_database_only_and_does_not_expose_secrets(self):
        key=self.issue()
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET status='Bearer PRIVATE_MARKER https://provider/?key=PRIVATE_MARKER',dns_intent='PRIVATE_MARKER'")
            db.execute("INSERT INTO vps_rotation_events(rotation_id,server_id,message,created) VALUES(?,?,?,?)",(self.rid,self.sid('A'),'provider failure PRIVATE_MARKER',self.clock[0]))
            before=db.total_changes
        with patch('rotation.update_dns_record') as dns,patch('rotation.invoke_change_ip_api') as action:
            r=self.read(key)
        self.assertEqual(r.status_code,200,r.json)
        dns.assert_not_called();action.assert_not_called()
        self.assertNotIn('PRIVATE_MARKER',r.get_data(as_text=True))
        self.assertNotIn(key,r.get_data(as_text=True))
        self.assertEqual(r.headers['Cache-Control'],'no-store')
        self.assertEqual(r.json['dns_values_source'],'panel_last_confirmed_not_live_provider')
        self.assertEqual(r.json['rotations'][0]['dns_write_pending'],True)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT dns_intent FROM vps_rotations WHERE id=?',(self.rid,)).fetchone()[0],'PRIVATE_MARKER')
    def test_event_cursor_validation(self):
        key=self.issue()
        r=self.read(key)
        cursor=r.json['next_after_id']
        self.assertEqual(self.read(key,'/api/monitor/snapshot?after_id='+str(cursor)).json['events'],[])
        self.assertEqual(self.read(key,'/api/monitor/snapshot?after_id=-1').status_code,400)
        self.assertEqual(self.read(key,'/api/monitor/snapshot?after_id=1e9').status_code,400)
    def test_status_does_not_return_key_or_hash(self):
        key=self.issue();r=self.admin.get('/api/admin/monitor-token')
        self.assertEqual(r.status_code,200)
        self.assertNotIn(key,r.get_data(as_text=True))
        self.assertNotIn('token_hash',r.json)
