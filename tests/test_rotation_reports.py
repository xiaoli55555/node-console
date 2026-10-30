import json,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from flask import Flask,jsonify
import rotation_insights as insights

class ReportsTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'db'
        with self.connect() as db:
            db.executescript('CREATE TABLE vps_rotations(id INTEGER,enabled INTEGER,phase TEXT,status TEXT,active_server_id INTEGER,next_switch_at INTEGER,updated INTEGER);INSERT INTO vps_rotations VALUES(1,1,"active","ready",3,2000,900);CREATE TABLE rotation_report_samples(id INTEGER PRIMARY KEY,rotation_id INTEGER,created INTEGER,payload TEXT);CREATE TABLE vps_rotation_events(rotation_id INTEGER,server_id INTEGER,message TEXT,created INTEGER);')
    def connect(self):
        db=sqlite3.connect(self.path);db.row_factory=sqlite3.Row;return db
    def tearDown(self):self.tmp.cleanup()
    @patch('rotation_insights.summarize',return_value={'rotation_id':1,'dns':{'trials':0}})
    def test_cadence_retention_and_execution(self,summary):
        insights.collect_reports(self.connect,1000);insights.collect_reports(self.connect,1005)
        with self.connect() as db:
            rows=db.execute('SELECT * FROM rotation_report_samples').fetchall();self.assertEqual(len(rows),1)
            self.assertEqual(json.loads(rows[0]['payload'])['execution']['phase'],'active')
        insights.collect_reports(self.connect,1600)
        with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM rotation_report_samples').fetchone()[0],2)
        insights.collect_reports(self.connect,700000)
        with self.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM rotation_report_samples').fetchone()[0],1)
    @patch('rotation_insights.summarize',return_value={'rotation_id':1})
    def test_download_requires_admin_decorator_and_has_no_secrets(self,summary):
        app=Flask(__name__);decorated=[]
        def auth(**kwargs):
            def wrap(fn):decorated.append((fn.__name__,kwargs));return fn
            return wrap
        insights.register(app,self.connect,auth,lambda:{},lambda m,c:(jsonify(error=m),c),lambda *a:None)
        client=app.test_client();r=client.get('/api/admin/rotation-insights/1/report')
        self.assertEqual(r.status_code,200);self.assertIn('attachment',r.headers['Content-Disposition'])
        self.assertIn(('download_rotation_report',{'admin':True}),decorated)
        self.assertIn('execution',r.json['current']);self.assertNotIn('token',r.get_data(as_text=True))
        self.assertEqual(client.get('/api/admin/rotation-insights/999/report').status_code,404)
