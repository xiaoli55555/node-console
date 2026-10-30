import importlib.util
import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path
import rotation_insights as insights

class InsightStatistics(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'data.db'
        with self.connect() as db:
            db.executescript('''CREATE TABLE vps_rotations(id INTEGER PRIMARY KEY,primary_server_id INTEGER,other_server_id INTEGER,interval_s INTEGER,lead_s INTEGER,offline_after_s INTEGER);
            CREATE TABLE ip_events(id INTEGER PRIMARY KEY,server_id INTEGER,addresses TEXT,observed INTEGER);
            CREATE TABLE detection_runs(id INTEGER PRIMARY KEY,server_id INTEGER,ip TEXT,created INTEGER,updated INTEGER,nodes TEXT,details TEXT);
            INSERT INTO vps_rotations VALUES(1,1,2,3000,120,15);''')
        insights.initialize(self.connect)
    def connect(self):
        db=sqlite3.connect(self.path);db.row_factory=sqlite3.Row;return db
    def tearDown(self):self.tmp.cleanup()
    def test_empty_data_is_not_an_optimal_time(self):
        with self.connect() as db:r=insights.summarize(db,1,10000)
        self.assertFalse(r['recommendation']['ready']);self.assertIsNone(r['dns']['observed_stable']['p95_s']);self.assertFalse(r['dns']['national_coverage_claimed'])
    def test_ipv6_only_change_does_not_reset_ipv4_age_unknown_is_not_failure(self):
        with self.connect() as db:
            for addresses,at in [(['8.8.8.8'],100),(['8.8.8.8','2606:4700::1111'],200),(['9.9.9.9'],300)]:db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(1,?,?)',(json.dumps(addresses),at))
            db.execute('INSERT INTO detection_runs(server_id,ip,created,updated,nodes,details) VALUES(1,\'9.9.9.9\',400,410,\'["1"]\',?)',(json.dumps([{'node_id':'1','state':'unknown'}]),))
            r=insights.summarize(db,1,500)
        self.assertEqual(r['ip_lifetimes']['observed_episodes'],2);self.assertEqual(r['ip_lifetimes']['censored'],2)
        self.assertFalse(r['ip_lifetimes']['episodes'][0]['start_observed_after_change'])
    def test_first_retained_ip_excluded_and_failure_is_bracketed(self):
        with self.connect() as db:
            for ip,at in [('8.8.8.8',100),('9.9.9.9',300)]:db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(1,?,?)',(json.dumps([ip]),at))
            for at,state in [(400,'reachable'),(500,'unreachable')]:db.execute('INSERT INTO detection_runs(server_id,ip,created,updated,nodes,details) VALUES(1,\'9.9.9.9\',?,?,\'["1"]\',?)',(at,at+10,json.dumps([{'node_id':'1','state':state}])))
            r=insights.summarize(db,1,600)
        e=r['ip_lifetimes']['episodes'][1];self.assertEqual(e['last_reachable_age_s'],100);self.assertEqual(e['failure_detected_age_s'],210)
    def test_proxied_and_unobserved_trials_are_explicit(self):
        with self.connect() as db:
            binding={'domain':'example.com','rr':'edge','line':'cmcc'}
            insights.record_switch(db,1,binding,'8.8.8.8','9.9.9.9',100,102,60,False)
            insights.record_switch(db,1,binding,'9.9.9.9','1.1.1.1',200,203,300,True)
            r=insights.summarize(db,1,400)
        self.assertEqual(r['dns']['proxied_unobservable'],1);self.assertEqual(r['dns']['trials_without_observations'],1);self.assertEqual(r['dns']['provider_readback']['p95_s'],3)

    def test_recovery_stages_are_separate_from_dns_propagation(self):
        before={'id':1,'action_attempts':0,'drain_server_id':2,'phase':'draining','action_started':None}
        sent=dict(before,action_attempts=1,phase='waiting_ip',action_started=100)
        seen=dict(sent,phase='waiting_probe')
        ready=dict(seen,phase='active',drain_server_id=None)
        with self.connect() as db:
            insights.record_progress(db,before,sent,100);insights.record_progress(db,sent,seen,130);insights.record_progress(db,seen,ready,160)
            r=insights.summarize(db,1,200)
        self.assertEqual(r['recovery']['completed']['p95_s'],60)
        self.assertEqual(r['recovery']['ip_reported']['p95_s'],30)
        self.assertIsNone(r['dns']['observed_stable']['p95_s'])

class DNSWireParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('dns_observer',Path('probe/dns_observer.py'));cls.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.module)
    def test_real_dns_a_response_and_mismatched_id(self):
        question=b'\x04edge\x07example\x03com\0\0\1\0\1'
        packet=struct.pack('!6H',123,0x8180,1,1,0,0)+question+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+bytes([8,8,8,8])
        self.assertEqual(self.module.parse_answer(packet,123),['8.8.8.8'])
        with self.assertRaises(ValueError):self.module.parse_answer(packet,124)
        with self.assertRaises(ValueError):self.module.parse_answer(packet[:-1],123)
    def test_nxdomain_and_short_packets_are_not_new_ip(self):
        for packet in (b'',struct.pack('!6H',1,0x8183,1,0,0,0)):
            with self.assertRaises(ValueError):self.module.parse_answer(packet,1)
