"""Frozen per-VPS lifetimes and DNS carrier evidence survive handoff and cleanup."""
import json
import time
import unittest
from unittest.mock import patch
import test_detectors as fixture
import test_detection_recheck as recheck_fixture
import detectors
import incident_history
import rotation
import rotation_timing


class IncidentHistory(unittest.TestCase):
    post=fixture.DetectorTest.post
    source=fixture.DetectorTest.source
    plan=fixture.DetectorTest.plan
    incident_run=fixture.DetectorTest.incident_run

    def setUp(self):
        fixture.DetectorTest.setUp(self)
        self.clock=[int(time.time())]
        p=patch('time.time',side_effect=lambda:self.clock[0]);p.start();self.addCleanup(p.stop)
        rotation.initialize(self.connect)
        with self.connect() as db:
            db.execute('CREATE TABLE ip_events(id INTEGER PRIMARY KEY,server_id INTEGER,addresses TEXT,observed INTEGER)')
            db.execute('INSERT INTO servers VALUES(2,?,?,?)',('standby',json.dumps({'public_ips':['1.1.1.1']}),self.clock[0]))
        self.source_id=self.source()['id'];self.plan(self.source_id,automatic=True,failure_threshold=2)

    def bind(self,pending=False):
        with self.connect() as db:
            cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('DNS','alidns','{}','unused')").lastrowid
            self.bid=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port) VALUES(1,?,'example.com','record','edge','unicom','8.8.8.8',443)",(cid,)).lastrowid
            self.rid=db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,phase,next_switch_at,updated,dns_intent) VALUES(1,1,2,?,1,1,'active',?,?,?)",(self.bid,self.clock[0]+7200,self.clock[0],'{}' if pending else None)).lastrowid

    def ip_history(self,boundary=True):
        with self.connect() as db:
            samples=[(['8.8.8.8'],self.clock[0]-1800),(['8.8.8.8','2606:4700::1111'],self.clock[0]-900),(['2606:4700::2222'],self.clock[0]-500)]
            if boundary:samples.insert(0,(['9.9.9.9'],self.clock[0]-3600))
            for ips,at in samples:db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(1,?,?)',(json.dumps(ips),at))

    def step(self,seconds=10):
        self.clock[0]+=seconds
        with self.connect() as db:db.execute('UPDATE servers SET seen=?',(self.clock[0],))

    def records(self,query=''):
        r=self.client.get('/api/detection/incidents'+query,headers=self.headers)
        self.assertEqual(r.status_code,200,r.json);return r.json

    def test_first_serving_failure_and_post_handoff_confirmation_are_distinct(self):
        self.bind();self.ip_history();first=self.clock[0]
        with self.connect() as db:rotation_timing.change(db,self.rid,1,'8.8.8.8',first-600,'scheduled_switch')
        self.incident_run(self.source_id,['unreachable','unreachable'])
        with self.connect() as db:
            db.execute('UPDATE vps_rotations SET active_server_id=2')
            db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1'")
        self.step();self.incident_run(self.source_id,['unreachable','unreachable'])
        r=self.records()['incidents'][0];e=r['evidence']
        self.assertEqual(r['first_failed'],first);self.assertEqual(r['confirmed_at'],first+10)
        self.assertEqual(e['first']['carrier_state'],'serving');self.assertEqual(e['confirmed']['carrier_state'],'standby')
        self.assertEqual(e['first']['ip_age_s'],1800);self.assertEqual(e['confirmed']['ip_age_s'],1810)
        self.assertFalse(e['first']['ip_start_censored']);self.assertEqual(e['first']['bindings'][0]['binding_id'],self.bid)
        self.assertEqual(e['first']['bindings'][0]['carrier_age_s'],600)
        frozen=json.dumps(e,sort_keys=True)
        self.step();self.incident_run(self.source_id,['unreachable','unreachable'])
        with self.connect() as db:db.execute('DELETE FROM detection_runs');db.execute('DELETE FROM vps_rotations');db.execute('DELETE FROM dns_bindings')
        self.assertEqual(json.dumps(self.records()['incidents'][0]['evidence'],sort_keys=True),frozen)
        self.assertEqual(len(self.records('?server_id=1&carrier_only=1')['incidents']),1)
        self.assertEqual(self.records('?server_id=2')['incidents'],[])

    def test_first_ip_observation_is_lower_bound_and_unbound_carrier_unknown(self):
        self.ip_history(boundary=False)
        for _ in range(2):self.incident_run(self.source_id,['unreachable','unreachable'])
        e=self.records()['incidents'][0]['evidence']['first']
        self.assertEqual(e['ip_age_s'],1800);self.assertTrue(e['ip_start_censored']);self.assertEqual(e['carrier_state'],'unknown')
        self.assertEqual(self.records('?carrier_only=1')['incidents'],[])

    def test_unconfirmed_dns_write_cannot_be_marked_as_serving(self):
        self.bind(pending=True)
        for _ in range(2):self.incident_run(self.source_id,['unreachable','unreachable'])
        e=self.records()['incidents'][0]['evidence']['first']
        self.assertEqual(e['carrier_state'],'unknown');self.assertTrue(e['bindings'][0]['pending'])
        self.assertIsNone(e['ip_age_s'])

    def test_rotation_failover_marks_actual_backup_instead_of_primary(self):
        self.bind()
        with self.connect() as db:
            db.execute('UPDATE vps_rotations SET failover_server_id=2')
            db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1'")
            db.execute("INSERT INTO vps_failover_leases(binding_id,rotation_id,original_ip,current_ip,updated) VALUES(?,?,'8.8.8.8','1.1.1.1',?)",(self.bid,self.rid,self.clock[0]))
            a=incident_history.snapshot(db,1,'8.8.8.8',self.clock[0]);b=incident_history.snapshot(db,2,'1.1.1.1',self.clock[0])
        self.assertEqual(a['carrier_state'],'standby');self.assertEqual(b['carrier_state'],'serving')
        self.assertEqual(b['bindings'][0]['role'],'rotation_failover')

    def test_legacy_events_remain_unknown_and_filtering_precedes_pagination(self):
        self.bind()
        with self.connect() as db:
            for i in range(502):
                sid=2 if i else 1
                db.execute("INSERT INTO detection_incidents(server_id,source_id,source_name,ip,port,nodes,threshold,failures,first_failed,last_failed,confirmed_at,state,last_run,details,response_mode) VALUES(?,?,'probe','8.8.8.8',443,'[]',2,2,100,110,110,'confirmed',1,'[]','none')",(sid,self.source_id))
        first=self.records('?server_id=2');self.assertEqual(len(first['incidents']),500);self.assertTrue(first['has_more'])
        tail=self.records('?server_id=2&before='+str(first['next_cursor']));self.assertEqual(len(tail['incidents']),1)
        one=self.records('?server_id=1')['incidents'];self.assertEqual(len(one),1);self.assertEqual(one[0]['evidence'],{})
        self.assertEqual(self.records('?server_id=1&carrier_only=1')['incidents'],[])
        self.assertEqual(self.client.get('/api/detection/incidents?server_id=bad',headers=self.headers).status_code,400)
        self.assertEqual(self.client.get('/api/detection/incidents?server_id=1').status_code,403)



    execute=recheck_fixture.IndependentRecheck.execute

    def test_second_point_does_not_replace_first_failure_carrier_snapshot(self):
        self.bind();self.ip_history();self.plan(self.source_id,automatic=True,confirm_node='3',failure_threshold=5)
        first=self.clock[0];self.incident_run(self.source_id,['unreachable','unreachable'])
        with self.connect() as db:
            self.parent=db.execute('SELECT MAX(id) FROM detection_runs').fetchone()[0]
            db.execute('UPDATE vps_rotations SET active_server_id=2');db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1'")
        self.step();self.execute()
        r=self.records()['incidents'][0]
        self.assertEqual(r['first_failed'],first);self.assertEqual(r['evidence']['first']['carrier_state'],'serving')
        self.assertEqual(r['evidence']['confirmed']['carrier_state'],'standby')

    def test_upgrade_pending_recheck_cannot_invent_first_failure_carrier_state(self):
        self.bind();self.ip_history();self.plan(self.source_id,automatic=True,confirm_node='3',failure_threshold=5)
        self.incident_run(self.source_id,['unreachable','unreachable'])
        with self.connect() as db:
            self.parent=db.execute('SELECT MAX(id) FROM detection_runs').fetchone()[0]
            db.execute('UPDATE detection_runs SET incident_evidence=NULL')
            db.execute('UPDATE vps_rotations SET active_server_id=2');db.execute("UPDATE dns_bindings SET expected_ip='1.1.1.1'")
        self.step();self.execute()
        e=self.records()['incidents'][0]['evidence']
        self.assertEqual(e['first']['carrier_state'],'unknown');self.assertIsNone(e['first']['ip_age_s'])
        self.assertEqual(e['confirmed']['carrier_state'],'standby')


class CoverageAudit(IncidentHistory):
    def test_gap_deduplicates_and_freezes_carrier(self):
        self.bind()
        with self.connect() as db:
            db.execute("UPDATE ip_monitors SET current_ip='8.8.8.8' WHERE server_id=1")
            incident_history.coverage_gap(db,1,self.clock[0],'每日节点检测次数上限')
            incident_history.coverage_gap(db,1,self.clock[0]+10,'每日节点检测次数上限')
            rows=db.execute('SELECT * FROM detection_coverage_gaps').fetchall()
            self.assertEqual(len(rows),1)
            self.assertEqual(json.loads(rows[0]['evidence'])['carrier_state'],'serving')
        self.assertEqual(self.client.get('/api/detection/coverage-gaps').status_code,403)
        result=self.client.get('/api/detection/coverage-gaps',headers=self.headers)
        self.assertEqual(len(result.json['gaps']),1)

    def test_only_complete_current_target_result_closes_gap(self):
        with self.connect() as db:
            now=self.clock[0]
            db.execute("UPDATE ip_monitors SET current_ip='8.8.8.8' WHERE server_id=1")
            incident_history.coverage_gap(db,1,now,'检测结果缺失或未知，不能判定目标正常或不通')
            run={'server_id':1,'ip':'8.8.8.8','source_id':self.source_id,'created':now+1,'nodes':'["a","b"]'}
            incident_history.coverage_result(db,run,[{'node_id':'a','state':'reachable'}],now+2)
            self.assertIsNone(db.execute('SELECT finished FROM detection_coverage_gaps').fetchone()[0])
            incident_history.coverage_result(db,run,[{'node_id':'a','state':'reachable'},{'node_id':'b','state':'unreachable'}],now+3)
            self.assertEqual(db.execute('SELECT finished FROM detection_coverage_gaps').fetchone()[0],now+3)

    def test_waiting_is_not_a_gap(self):
        with self.connect() as db:
            incident_history.coverage_gap(db,1,self.clock[0],'已有检测任务进行中')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM detection_coverage_gaps').fetchone()[0],0)

    def test_last_pass_is_preserved_with_first_failure(self):
        self.incident_run(self.source_id,['reachable','reachable'])
        passed=self.clock[0]
        self.step()
        self.incident_run(self.source_id,['unreachable','unreachable'])
        self.step()
        self.incident_run(self.source_id,['unreachable','unreachable'])
        e=self.records()['incidents'][0]['evidence']
        self.assertEqual(e['last_pass']['observed_at'],passed)
