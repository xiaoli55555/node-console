import json
import time
import unittest
from unittest.mock import patch
from test_hkt_dhcp import HKTAPI
import server,tcp_history

class TCPHistory(unittest.TestCase):
    setUp=HKTAPI.setUp
    post=HKTAPI.post
    report=HKTAPI.report
    def node(self):return self.post('/api/servers',{'name':'history node'}).json
    def test_ip_filter_keeps_raw_counts_and_stale_is_not_zero(self):
        n=self.node();clock=[int(time.time())]
        with patch('time.time',side_effect=lambda:clock[0]):
            for ip,count,age in [('36.232.68.71',140,0),('36.232.68.71',4,0),('36.232.67.208',8,46)]:
                r=self.report(n,public_ips=[ip],tcp=count,connections_sampled=clock[0]-age,tcp_by_port={'443':count})
                self.assertEqual(r.status_code,200,r.json);clock[0]+=5
            path=f'/api/admin/servers/{n["id"]}/tcp-history'
            d=self.admin.get(path+'?ip=36.232.68.71').json
            self.assertEqual([p['tcp'] for p in d['points']],[4,140])
            all_rows=self.admin.get(path).json['points']
            self.assertEqual(all_rows[0]['tcp'],8);self.assertFalse(all_rows[0]['valid'])
            self.assertEqual(all_rows[0]['ports'],{'443':8})
            self.assertEqual(all_rows[0]['sampled_at'],clock[0]-5-46)
            page=self.admin.get(path+'?limit=1').json
            next_page=self.admin.get(path+'?limit=1&before_id='+str(page['next_before_id'])).json
            self.assertNotEqual(page['points'][0]['id'],next_page['points'][0]['id'])
            self.assertEqual(self.alice.get(path).status_code,403)
            for query in ['limit=0','limit=2001','ip=bad','before_id=-1','from=9&until=1']:
                self.assertEqual(self.admin.get(path+'?'+query).status_code,400)
    def test_missing_sample_duplicate_report_and_unknown_ip(self):
        n=self.node();now=int(time.time())
        with patch('time.time',return_value=now):
            self.report(n,public_ips=[],tcp=7)
            self.report(n,public_ips=[],tcp=7)
            d=self.admin.get(f'/api/admin/servers/{n["id"]}/tcp-history').json
            self.assertEqual(len(d['points']),1)
            p=d['points'][0];self.assertFalse(p['valid']);self.assertIsNone(p['sampled_at'])
            self.assertEqual(p['addresses'],[]);self.assertEqual(p['address_source'],'unknown')
            self.assertEqual(p['tcp'],7)
    def test_retention_and_server_delete_cascade(self):
        n=self.node();now=int(time.time())
        with server.connect() as db:
            for stamp in [now-tcp_history.RETENTION_S-1,now]:
                tcp_history.record(db,n['id'],{'tcp':4,'connections_sampled':stamp,'public_ips':['36.232.68.71']},stamp)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM tcp_samples WHERE server_id=?',(n['id'],)).fetchone()[0],1)
            last_id=db.execute('SELECT MAX(id) FROM tcp_samples').fetchone()[0]
            db.execute('DELETE FROM servers WHERE id=?',(n['id'],))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM tcp_samples WHERE server_id=?',(n['id'],)).fetchone()[0],0)
        other=self.node()
        with server.connect() as db:
            tcp_history.record(db,other['id'],{'tcp':4,'connections_sampled':now},now)
            self.assertGreater(db.execute('SELECT MAX(id) FROM tcp_samples').fetchone()[0],last_id)
    def test_ipv6_and_ipv4_are_one_host_sample(self):
        n=self.node();now=int(time.time())
        self.report(n,public_ips=['36.232.68.71','2606:4700:4700::1111'],tcp=20,connections_sampled=now)
        for address in ['36.232.68.71','2606:4700:4700::1111']:
            d=self.admin.get(f'/api/admin/servers/{n["id"]}/tcp-history?ip='+address).json
            self.assertEqual(len(d['points']),1);self.assertEqual(d['points'][0]['tcp'],20)

class TCPAuditEvidence(unittest.TestCase):
    def setUp(self):
        from test_ip_change_connections import ConnectionGate
        self.case=ConnectionGate(methodName='runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.f=self.case.f
    def test_action_event_records_sample_link_exact_threshold_and_age(self):
        f=self.f;self.case.sample(80)
        with server.connect() as db:
            m=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('A'),)).fetchone()[0])
            tcp_history.record(db,f.sid('A'),m,f.clock[0])
            rotation=__import__('rotation')
            rotation._event(db,f.rid,f.sid('A'),'test evidence',f.clock[0],kind='ip_change_prepared',trigger='test')
            evidence=json.loads(db.execute('SELECT evidence FROM rotation_audit WHERE rotation_id=? ORDER BY event_id DESC LIMIT 1',(f.rid,)).fetchone()[0])
            node=next(n for n in evidence['servers'] if n['server_id']==f.sid('A'))
            self.assertIsNotNone(node['tcp_sample_id']);self.assertEqual(node['tcp'],80)
            self.assertFalse(node['tcp_gate']['passes_tcp_gate'])
            self.assertEqual(node['tcp_gate']['plans'][0]['threshold'],80)
            self.assertEqual(node['tcp_gate']['sample_age_s'],0)
            self.assertFalse(tcp_history.gate(db,f.sid('A'),m,f.clock[0],seen=f.clock[0]-46)['passes_tcp_gate'])
