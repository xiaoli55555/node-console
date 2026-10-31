"""Shared standby: independent probes, leases, recovery and schema upgrade."""
import json
import sqlite3
import unittest
from unittest.mock import patch
import test_server_failover as fixture
import test_failover as rotation_fixture
import server
import server_failover as sf
import shared_failover as shared
import failover
import rotation


class SharedStandby(unittest.TestCase):
    post=fixture.ServerFailover.post
    row=fixture.ServerFailover.row
    save=fixture.ServerFailover.save
    sid=fixture.ServerFailover.sid
    refresh=fixture.ServerFailover.refresh
    advance=fixture.ServerFailover.advance
    down=fixture.ServerFailover.down
    value=fixture.ServerFailover.value
    config=fixture.ServerFailover.config
    state=fixture.ServerFailover.state

    def setUp(self):
        fixture.ServerFailover.setUp(self)
        with server.connect() as db:
            cid=db.execute('SELECT connection_id FROM dns_bindings LIMIT 1').fetchone()[0]
            self.b_binding=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic,verify_new_ip) VALUES(?,?,'example.com','b-record','backup-edge','mobile','1.1.1.1',443,1,1)",(self.sid('B'),cid)).lastrowid
            self.records[self.b_binding]={'RecordId':'b-record','RR':'backup-edge','Line':'mobile','Type':'A','Value':'1.1.1.1','TTL':60,'Status':'ENABLE'}
            self.sources={name:db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(self.sid(name),)).fetchone()[0] for name in ('A','B')}
        response=self.config_b()
        self.assertEqual(response.status_code,200,response.json)

    def tearDown(self):
        fixture.ServerFailover.tearDown(self)
        with server.connect() as db:db.execute('DELETE FROM vps_failover_probe_state')

    def config_b(self,**changes):
        return self.admin.put(f'/api/servers/{self.sid("B")}/failover',json=dict({'backup_id':self.sid('C'),'recovery_s':30,'offline_s':30},**changes),headers={'X-CSRF-Token':self.tokens['admin']})

    def probe(self,good=True):
        self.health[self.sid('C')]=good
        self.refresh('C')

    def both_down(self):
        self.clock[0]+=31;self.probe();sf.tick(server.connect,server.CIPHER)

    def lease_count(self,sid):
        with server.connect() as db:return db.execute('SELECT COUNT(*) FROM server_failover_leases WHERE server_id=?',(sid,)).fetchone()[0]

    def test_two_failures_use_distinct_profiles_then_share_C(self):
        self.both_down();self.assertEqual(self.lease_count(self.sid('A')),0)
        self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('A')),3)
        self.assertEqual(self.lease_count(self.sid('B')),0)
        with server.connect() as db:self.assertEqual(db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0],self.sources['B'])
        self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('B')),1)
        self.assertEqual(self.records[self.b_binding]['Value'],'9.9.9.9')
        for line in self.bindings:self.assertEqual(self.value(line),'9.9.9.9')

    def test_failed_B_profile_does_not_reuse_A_success(self):
        self.both_down();self.probe();sf.tick(server.connect,server.CIPHER)
        self.probe(False);sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('A')),3)
        self.assertEqual(self.lease_count(self.sid('B')),0)
        self.assertEqual(self.records[self.b_binding]['Value'],'1.1.1.1')

    def test_A_recovers_first_without_stopping_B_or_its_probes(self):
        self.both_down();self.probe();sf.tick(server.connect,server.CIPHER);self.probe();sf.tick(server.connect,server.CIPHER)
        self.refresh('A');sf.tick(server.connect,server.CIPHER)
        self.clock[0]+=30;self.refresh('A');self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('A')),0)
        self.assertEqual(self.lease_count(self.sid('B')),1)
        self.assertEqual(self.records[self.b_binding]['Value'],'9.9.9.9')
        with server.connect() as db:
            self.assertTrue(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0])
            self.assertTrue(db.execute('SELECT active FROM server_failovers WHERE server_id=?',(self.sid('B'),)).fetchone()[0])
        self.refresh('B');sf.tick(server.connect,server.CIPHER)
        self.clock[0]+=30;self.refresh('A');self.refresh('B');self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('B')),0)
        with server.connect() as db:self.assertFalse(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0])

    def test_remove_idle_A_does_not_restore_or_pause_active_B(self):
        self.down('B');self.clock[0]+=31;self.refresh('A');self.probe();sf.tick(server.connect,server.CIPHER)
        self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('B')),1)
        response=self.config(backup_id=None)
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(self.lease_count(self.sid('B')),1)
        self.assertEqual(self.records[self.b_binding]['Value'],'9.9.9.9')
        with server.connect() as db:self.assertTrue(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0])

    def test_waiting_async_probe_is_not_overwritten_by_other_parent(self):
        self.both_down()
        with server.connect() as db:
            p=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()
            rid=db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details,scheduled) VALUES(?,?,?,443,?,'pending',?,?,'[]',1)",(self.sid('C'),p['source_id'],'9.9.9.9',p['nodes'],self.clock[0],self.clock[0])).lastrowid
        self.clock[0]+=31;sf.tick(server.connect,server.CIPHER)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0],p['source_id'])
            self.assertEqual(db.execute('SELECT status FROM detection_runs WHERE id=?',(rid,)).fetchone()[0],'pending')

    def test_shared_probe_cost_is_charged_to_the_profile_being_run(self):
        self.both_down()
        with server.connect() as db:self.assertEqual(failover.budget_primary(db,self.sid('C')),self.sid('A'))
        self.probe();sf.tick(server.connect,server.CIPHER)
        with server.connect() as db:self.assertEqual(failover.budget_primary(db,self.sid('C')),self.sid('B'))

    def test_removing_all_references_restores_original_standby_settings(self):
        self.assertEqual(self.config(backup_id=None).status_code,200)
        with server.connect() as db:self.assertFalse(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0])
        self.assertEqual(self.config_b(backup_id=None).status_code,200)
        with server.connect() as db:
            self.assertTrue(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0])
            self.assertFalse(failover.reserved(db,self.sid('C')))

    def test_existing_rotation_C_can_be_shared_with_B(self):
        self.assertEqual(self.config(backup_id=None).status_code,200)
        saved=self.save();self.assertEqual(saved.status_code,200,saved.json)
        self.rid=saved.json['rotation']['id']
        self.clock[0]+=31;self.probe()
        sf.tick(server.connect,server.CIPHER);rotation.tick(server.connect,server.CIPHER)
        # Drain both asynchronous inherited profiles, whichever worker owns it.
        for _ in range(4):
            self.probe();sf.tick(server.connect,server.CIPHER);rotation.tick(server.connect,server.CIPHER)
        self.assertEqual(self.records[self.b_binding]['Value'],'9.9.9.9')
        for line in self.bindings:self.assertEqual(self.value(line),'9.9.9.9')
        self.refresh('B');sf.tick(server.connect,server.CIPHER)
        self.clock[0]+=30;self.refresh('B');self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.records[self.b_binding]['Value'],'1.1.1.1')
        self.assertEqual(self.value('telecom'),'9.9.9.9')
        with server.connect() as db:self.assertTrue(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0])

    def test_different_nodes_and_ports_are_verified_independently(self):
        with server.connect() as db:
            db.execute('UPDATE detection_plans SET nodes=? WHERE server_id=?',('["21", "22"]',self.sid('B')))
            db.execute('UPDATE ip_monitors SET port=8443 WHERE server_id=?',(self.sid('B'),))
            db.execute('UPDATE dns_bindings SET port=8443 WHERE id=?',(self.b_binding,))
        self.both_down();self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('B')),0)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT port FROM ip_monitors WHERE server_id=?',(self.sid('C'),)).fetchone()[0],8443)
            self.assertEqual(json.loads(db.execute('SELECT nodes FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0]),['21','22'])
        self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('A')),3)
        self.assertEqual(self.lease_count(self.sid('B')),1)

    def test_real_probe_job_uses_current_parents_budget(self):
        import detectors
        self.both_down()
        with patch('detectors.boce',return_value={'data':{'id':'shared-probe-A'}}):
            rid=detectors.start_run(server.connect,server.CIPHER,self.sid('C'),scheduled=True)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT primary_server_id FROM vps_failover_probe_costs WHERE run_id=?',(rid,)).fetchone()[0],self.sid('A'))
            self.assertEqual(db.execute('SELECT source_id FROM detection_runs WHERE id=?',(rid,)).fetchone()[0],self.sources['A'])

    def test_two_rotation_groups_share_C_and_recover_independently(self):
        self.assertEqual(self.config(backup_id=None).status_code,200)
        self.assertEqual(self.config_b(backup_id=None).status_code,200)
        saved=self.save();self.assertEqual(saved.status_code,200,saved.json)
        self.rid=saved.json['rotation']['id']
        for name,ip in [('D','4.2.2.2'),('E','208.67.222.222')]:
            node=self.post('/api/servers',{'name':name}).json
            self.nodes[name]=node;self.ips[node['id']]=ip;self.health[node['id']]=True
            with server.connect() as db:
                db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,443,1)',(node['id'],))
                source=db.execute("INSERT INTO detection_sources(name,kind,secret,enabled) VALUES(?,'boce',?,1)",(name,server.CIPHER.encrypt(b'test-source').decode())).lastrowid
                action=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES(?,'change_ip','{}',?)",(name,server.CIPHER.encrypt(b'test-action').decode())).lastrowid
                db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,daily_limit,next_at,response_mode,action_connection_id,failure_threshold) VALUES(?,?,?,120,1,1000,?,'change_api',?,2)",(node['id'],source,'["31"]',self.clock[0]+120,action))
            self.refresh(name)
        with server.connect() as db:
            cid=db.execute('SELECT connection_id FROM dns_bindings LIMIT 1').fetchone()[0]
            bid=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic) VALUES(?,?,'example.com','d-record','d-edge','mobile','4.2.2.2',443,1)",(self.sid('D'),cid)).lastrowid
        self.records[bid]={'RecordId':'d-record','RR':'d-edge','Line':'mobile','Type':'A','Value':'4.2.2.2','TTL':60,'Status':'ENABLE'}
        payload=dict(self.payload,other_server_id=self.sid('E'),binding_id=bid,failover_binding_ids=[bid])
        response=self.admin.put(f'/api/admin/servers/{self.sid("D")}/rotation',json=payload,headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(response.status_code,200,response.json)
        self.clock[0]+=31;self.refresh('B');self.refresh('E');self.probe()
        rotation.tick(server.connect,server.CIPHER)
        for _ in range(4):self.probe();rotation.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('telecom'),'9.9.9.9')
        self.assertEqual(self.records[bid]['Value'],'9.9.9.9')
        self.refresh('A');rotation.tick(server.connect,server.CIPHER)
        self.clock[0]+=30;self.refresh('A');self.refresh('B');self.refresh('E');self.probe();rotation.tick(server.connect,server.CIPHER)
        self.assertEqual(self.value('telecom'),'8.8.8.8')
        self.assertEqual(self.records[bid]['Value'],'9.9.9.9')
        with server.connect() as db:self.assertTrue(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone()[0])

    def test_missing_result_does_not_starve_another_profile(self):
        with server.connect() as db:db.execute('INSERT OR REPLACE INTO shared_failover_attempt(kind,parent_id,attempted_at) VALUES(?,?,?)',('server',self.sid('B'),self.clock[0]+10000))
        self.both_down()
        self.clock[0]+=31
        # Keep the standby alive without inventing a successful paid probe.
        with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(self.clock[0],self.sid('C')))
        sf.tick(server.connect,server.CIPHER)
        with server.connect() as db:self.assertEqual(failover.budget_primary(db,self.sid('C')),self.sid('B'))
        self.probe();sf.tick(server.connect,server.CIPHER)
        self.assertEqual(self.lease_count(self.sid('B')),1)
        self.assertEqual(self.lease_count(self.sid('A')),0)

    def test_warm_standby_can_be_shared_without_overwriting_its_plan(self):
        self.assertEqual(self.config(backup_id=None).status_code,200)
        self.assertEqual(self.config_b(backup_id=None).status_code,200)
        with server.connect() as db:
            db.execute("UPDATE detection_plans SET response_mode='reboot',automatic=1,action_enabled=1 WHERE server_id=?",(self.sid('C'),))
            before=dict(db.execute('SELECT * FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone())
        self.assertEqual(self.config().status_code,200)
        self.assertEqual(self.config_b().status_code,200)
        self.both_down()
        self.assertEqual(self.lease_count(self.sid('A')),3)
        self.assertEqual(self.lease_count(self.sid('B')),1)
        with server.connect() as db:
            after=dict(db.execute('SELECT * FROM detection_plans WHERE server_id=?',(self.sid('C'),)).fetchone())
            self.assertEqual(before,after)
            self.assertIn('正接替',sf.before_action(db,self.sid('C'),self.clock[0],server.CIPHER))


class SchemaUpgrade(unittest.TestCase):
    def test_drop_unique_preserves_existing_lease_and_foreign_keys(self):
        db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
        db.executescript('''PRAGMA foreign_keys=ON;
          CREATE TABLE servers(id INTEGER PRIMARY KEY);CREATE TABLE users(id INTEGER PRIMARY KEY);
          CREATE TABLE dns_bindings(id INTEGER PRIMARY KEY);
          INSERT INTO servers VALUES(1),(2),(3);INSERT INTO users VALUES(1);INSERT INTO dns_bindings VALUES(7);
          CREATE TABLE server_failovers(server_id INTEGER PRIMARY KEY REFERENCES servers(id),backup_id INTEGER NOT NULL UNIQUE REFERENCES servers(id),owner_id INTEGER NOT NULL REFERENCES users(id),recovery_s INTEGER DEFAULT 60,offline_s INTEGER DEFAULT 30,cold INTEGER DEFAULT 1,requested_at INTEGER,action_ip TEXT,healthy_since INTEGER,healthy_ip TEXT,active INTEGER DEFAULT 0,signature TEXT,activated_at INTEGER,run_floor INTEGER DEFAULT 0,original_plan TEXT,original_monitor TEXT,status TEXT DEFAULT 'idle');
          CREATE TABLE server_failover_leases(binding_id INTEGER PRIMARY KEY REFERENCES dns_bindings(id),server_id INTEGER REFERENCES server_failovers(server_id),current_ip TEXT,target_ip TEXT,restoring INTEGER DEFAULT 0,updated INTEGER);
          INSERT INTO server_failovers(server_id,backup_id,owner_id) VALUES(1,3,1);
          INSERT INTO server_failover_leases VALUES(7,1,'9.9.9.9',NULL,0,100);''')
        sf.initialize(db)
        db.execute('INSERT INTO server_failovers(server_id,backup_id,owner_id) VALUES(2,3,1)')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM server_failovers').fetchone()[0],2)
        self.assertEqual(db.execute('SELECT current_ip FROM server_failover_leases').fetchone()[0],'9.9.9.9')
        self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0],1)
        self.assertFalse(db.execute('PRAGMA foreign_key_check').fetchall())
        sf.initialize(db)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM server_failovers').fetchone()[0],2)
