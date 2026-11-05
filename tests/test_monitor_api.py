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

    def test_structured_evidence_preserves_event_time_and_omits_secrets(self):
        import rotation
        key=self.issue();now=self.clock[0]
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET dns_intent='PRIVATE_MARKER',status='PRIVATE_MARKER' WHERE id=?",(self.rid,))
            rotation._event(db,self.rid,self.sid('A'),'PRIVATE_MARKER',now,kind='handoff_source_observed',trigger='tcp_suspected_pending_recheck')
            first=db.execute('SELECT MAX(id) FROM vps_rotation_events').fetchone()[0]
            db.execute('UPDATE vps_rotations SET active_server_id=?,next_switch_at=? WHERE id=?',(self.sid('B'),now+100,self.rid))
            rotation._event(db,self.rid,self.sid('B'),'PRIVATE_MARKER',now+2,kind='dns_switch_confirmed',trigger='tcp_suspected_pending_recheck')
        with patch('rotation.get_dns_record') as dns,patch('rotation.invoke_change_ip_api') as change:
            result=self.read(key,'/api/monitor/snapshot?after_id='+str(first-1)).json
        dns.assert_not_called();change.assert_not_called()
        self.assertNotIn('PRIVATE_MARKER',json.dumps(result))
        before,after=result['events']
        self.assertEqual(before['audit']['incident_id'],after['audit']['incident_id'])
        evidence=after['audit']['evidence']
        self.assertEqual(evidence['previous_state']['active_server_id'],self.sid('A'))
        self.assertEqual(evidence['state']['active_server_id'],self.sid('B'))
        self.assertEqual(evidence['elapsed_since_previous_event_s'],2)
        # Later state changes cannot rewrite an earlier event's evidence.
        self.assertEqual(before['audit']['evidence']['state']['active_server_id'],self.sid('A'))
        self.assertTrue(before['audit']['evidence']['state']['dns_intent'])

    def test_filtered_pagination_statistics_and_legacy_unknown(self):
        import rotation
        key=self.issue();now=self.clock[0]
        with server.connect() as db:
            db.execute('DELETE FROM rotation_audit');db.execute('DELETE FROM vps_rotation_events')
            for i in range(505):
                # Legacy records remain unknown, even when the message says failure.
                db.execute('INSERT INTO vps_rotation_events(rotation_id,server_id,message,created) VALUES(?,?,?,?)',(self.rid,self.sid('A'),'failure',now+i))
            rotation._event(db,self.rid,self.sid('B'),'handoff',now+505,kind='dns_switch_confirmed',trigger='scheduled_switch')
        path=f'/api/monitor/snapshot?start_at={now}&end_at={now+505}&rotation_id={self.rid}'
        first=self.read(key,path).json
        self.assertEqual(len(first['events']),200);self.assertTrue(first['has_more_events'])
        stats=first['event_statistics']
        self.assertEqual(stats['event_count'],506);self.assertEqual(stats['missing_evidence_count'],505)
        self.assertIsNone(first['events'][0]['audit'])
        second=self.read(key,path+'&after_id='+str(first['next_after_id'])).json
        self.assertEqual(len(second['events']),200);self.assertTrue(second['has_more_events'])
        self.assertEqual(second['event_statistics'],stats)
        self.assertGreater(second['events'][0]['id'],first['events'][-1]['id'])
        third=self.read(key,path+'&after_id='+str(second['next_after_id'])).json
        self.assertEqual(len(third['events']),106);self.assertFalse(third['has_more_events'])
        self.assertEqual(third['event_statistics'],stats)
        incident=third['events'][-1]['audit']['incident_id']
        chain=self.read(key,'/api/monitor/snapshot?incident_id='+incident).json
        self.assertEqual(len(chain['events']),1)
        self.assertEqual(chain['event_statistics']['event_count'],1)
        self.assertEqual(self.read(key,path+'&server_id='+str(self.sid('B'))).json['event_statistics']['event_count'],1)
        for query in ('start_at=-1','start_at=2&end_at=1','server_id=１','incident_id=bogus','incident_id=1:2%27'):
            self.assertEqual(self.read(key,'/api/monitor/snapshot?'+query).status_code,400,query)

    def test_coordination_is_not_reported_as_confirmed_split(self):
        from monitor_api import category
        self.assertEqual(category('多记录协调中'),'group_coordination')
        self.assertEqual(category('线路状态不一致'),'group_split')
