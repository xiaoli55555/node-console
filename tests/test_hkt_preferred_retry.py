"""Nonpreferred HKT addresses must resume through drain gates, never a test bypass."""
import unittest
import server
import hkt_dhcp
import test_hkt_dhcp as fixtures
import test_rotation_heartbeat_guard as rotation_fixture


class PreferredRetry(fixtures.HKTAPI):
    def test_nonpreferred_failure_can_retry_and_keeps_history(self):
        node=self.node(); self.generate(node)
        with server.connect() as db:
            uid=db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()[0]
            jid=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp','failed',1,1)",(node['id'],uid)).lastrowid
            self.assertTrue(hkt_dhcp.preferred_ip_retry_allowed(db,node['id']))
            db.execute("UPDATE servers SET metrics=? WHERE id=?", ('{"public_ips":["42.98.100.156"]}',node['id']))
            self.assertFalse(hkt_dhcp.preferred_ip_retry_allowed(db,node['id']))
            db.execute("UPDATE servers SET metrics=? WHERE id=?", ('{"public_ips":["219.79.212.57"]}',node['id']))
            db.execute('UPDATE hkt_dhcp_apis SET reset_after=? WHERE server_id=?',(jid,node['id']))
            self.assertTrue(hkt_dhcp.preferred_ip_retry_allowed(db,node['id']))
            db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp','accepted',2,2)",(node['id'],uid))
            self.assertFalse(hkt_dhcp.preferred_ip_retry_allowed(db,node['id']))
            self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(jid,)).fetchone()[0],'failed')

    def test_unlocked_nonpreferred_candidate_returns_to_drain_without_action(self):
        case=rotation_fixture.HeartbeatGuard(methodName='runTest');case.setUp()
        self.addCleanup(case.doCleanups)
        case.takeover();f=case.f
        with server.connect() as db:
            action=db.execute('SELECT action_connection_id FROM detection_plans WHERE server_id=?',(f.sid('A'),)).fetchone()[0]
            uid=db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()[0]
            jid=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp','failed',1,1)",(f.sid('A'),uid)).lastrowid
            db.execute("INSERT INTO hkt_dhcp_apis VALUES(?,?,'test',?)",(f.sid('A'),action,jid))
            db.execute("UPDATE vps_rotations SET phase='waiting_ip',repair_check_required=0,repair_check=NULL,action_started=? WHERE id=?",(f.clock[0],f.rid))
        f.refresh('A',ip='219.79.212.57');f.tick()
        deadline=f.row()['next_switch_at']
        f.advance(2,online=('A','B'));f.tick()
        row=f.row()
        self.assertEqual(row['phase'],'draining')
        self.assertEqual(row['low_samples'],0)
        self.assertEqual(row['old_ip'],'219.79.212.57')
        self.assertEqual(row['next_switch_at'],deadline)
        self.assertEqual(f.value('mobile'),'1.1.1.1')
        f.change.assert_not_called()

    def test_external_selection_skips_wait_but_keeps_tcp_and_carrier_guards(self):
        import time
        from unittest.mock import patch
        from ip_dns import IntegrationError
        node=self.node();other=self.node('carrier');cfg=self.generate(node)
        now=int(time.time());self.report(node,public_ips=['219.79.212.57'],tcp=10,connections_sampled=now)
        with server.connect() as db:
            uid=db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()[0]
            cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('dns','alidns','{}','test')").lastrowid
            bid=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port) VALUES(?,?,'example.com','r','edge','default','1.1.1.1',443)",(node['id'],cid)).lastrowid
            rid=db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,phase,next_switch_at,updated,drain_server_id,drain_started,drain_grace_s,low_samples,connection_threshold) VALUES(?,?,?,?,?,1,'waiting_probe',?,?,?,?,3600,0,80)",(uid,node['id'],other['id'],bid,other['id'],now+7200,now,node['id'],now)).lastrowid
            failed=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp','failed',1,1)",(node['id'],uid)).lastrowid
        with patch('ip_dns.load_connection',return_value={}),patch('ip_dns.get_dns_record',return_value={'Value':'1.1.1.1'}),patch('ip_dns.validate_dns_record'):
            self.report(node,public_ips=['219.79.212.57'],tcp=80,connections_sampled=now)
            with self.assertRaisesRegex(IntegrationError,'连接'):hkt_dhcp.queue(node['id'])
            self.report(node,public_ips=['219.79.212.57'],tcp=10,connections_sampled=now)
            jid=hkt_dhcp.queue(node['id']);self.assertGreater(jid,failed)
            self.assertEqual(hkt_dhcp.queue(node['id']),jid)
            with server.connect() as db:
                self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(failed,)).fetchone()[0],'failed')
                db.execute("UPDATE commands SET status='failed' WHERE id=?",(jid,))
            with patch('ip_dns.get_dns_record',return_value={'Value':'219.79.212.57'}):
                with self.assertRaisesRegex(IntegrationError,'DNS'):hkt_dhcp.queue(node['id'])
            self.report(node,public_ips=['42.98.100.156'],tcp=10,connections_sampled=now)
            with self.assertRaisesRegex(IntegrationError,'轮换管理'):hkt_dhcp.queue(node['id'])
            with server.connect() as db:db.execute('UPDATE vps_rotations SET low_samples=2,drain_grace_s=0 WHERE id=?',(rid,))
            retried=hkt_dhcp.queue(node['id'],managed=True)
            self.assertGreater(retried,jid) # Terminal failure no longer permanently locks DHCP.

    def test_selection_provider_wait_does_not_hold_writer_and_rechecks_race(self):
        import time
        from unittest.mock import patch
        from ip_dns import IntegrationError
        node=self.node();other=self.node('carrier');cfg=self.generate(node)
        now=int(time.time());self.report(node,public_ips=['219.79.212.57'],tcp=10,connections_sampled=now)
        with server.connect() as db:
            uid=db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()[0]
            cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('dns','alidns','{}','test')").lastrowid
            bid=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port) VALUES(?,?,'example.com','r','edge','default','1.1.1.1',443)",(node['id'],cid)).lastrowid
            rid=db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,phase,next_switch_at,updated,drain_server_id,drain_started,drain_grace_s,low_samples,connection_threshold) VALUES(?,?,?,?,?,1,'waiting_probe',?,?,?,?,3600,0,80)",(uid,node['id'],other['id'],bid,other['id'],now+7200,now,node['id'],now)).lastrowid
            failed=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp','failed',1,1)",(node['id'],uid)).lastrowid
        def dns_during_other_writer(*args):
            with server.connect() as concurrent:
                concurrent.execute('PRAGMA busy_timeout=50')
                concurrent.execute("UPDATE vps_rotations SET active_server_id=? WHERE id=?",(node['id'],rid))
                concurrent.execute("INSERT INTO audit(action,created) VALUES('concurrent writer completed',?)",(now,))
            return {'Value':'1.1.1.1'}
        with patch('ip_dns.load_connection',return_value={}),patch('ip_dns.validate_dns_record'),patch('ip_dns.get_dns_record',side_effect=dns_during_other_writer):
            with self.assertRaises(IntegrationError):hkt_dhcp.queue(node['id'])
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='concurrent writer completed'").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commands WHERE action='hkt_dhcp' AND status='queued'").fetchone()[0],0)
