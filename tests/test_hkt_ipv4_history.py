"""HKT history counts IPv4 transitions, preserving raw legacy and other VPS history."""
import json
import time
import unittest
import test_panel as fixture
import server


class HktIPv4History(unittest.TestCase):
    setUp=fixture.PanelTest.setUp
    post=fixture.PanelTest.post

    def node(self,hkt=True):
        n=self.post('/api/servers',{'name':'renamed-node'}).json
        self.sid=n['id'];self.headers={'Authorization':'Bearer '+n['token']}
        self.report(['8.8.8.8','2606:4700::1111'],hkt=hkt)
        return n

    def report(self,ips,hkt=True,**extra):
        data={'public_ips':ips,'capabilities':['hkt_dhcp'] if hkt else []}
        data.update(extra)
        r=self.admin.post('/api/agent/report',json=data,headers=self.headers)
        self.assertEqual(r.status_code,200,r.json)

    def history(self,query=''):
        r=self.admin.get(f'/api/servers/{self.sid}/ip-history'+query)
        self.assertEqual(r.status_code,200,r.json)
        return r.json

    def test_ipv6_only_changes_and_loss_do_not_add_hkt_changes(self):
        self.node()
        for ips in [['8.8.8.8','2606:4700::2222'],['8.8.8.8'],['2606:4700::3333'],[]]:self.report(ips)
        h=self.history();self.assertEqual(h['address_family'],'ipv4')
        self.assertEqual(h['total'],1);self.assertEqual(h['change_count'],0)
        self.assertEqual(h['current_addresses'],['8.8.8.8'])
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM ip_events WHERE server_id=?',(self.sid,)).fetchone()[0],1)
        self.report(['9.9.9.9','2606:4700::4444'])
        h=self.history();self.assertEqual(h['change_count'],1)
        self.assertEqual(h['events'][0]['previous_addresses'],['8.8.8.8'])
        self.assertEqual(h['events'][0]['addresses'],['9.9.9.9'])

    def test_legacy_ipv6_churn_is_collapsed_without_deleting_raw_records(self):
        self.node()
        samples=[['8.8.8.8','2606:4700::1111'],['8.8.8.8','2606:4700::2222'],['2606:4700::3333'],['8.8.8.8'],['9.9.9.9','2606:4700::4444'],['9.9.9.9','2606:4700::5555'],['8.8.8.8']]
        with server.connect() as db:
            db.execute('DELETE FROM ip_events WHERE server_id=?',(self.sid,))
            for i,ips in enumerate(samples):db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(?,?,?)',(self.sid,json.dumps(ips),100+i))
        h=self.history();self.assertEqual(h['total'],3);self.assertEqual(h['change_count'],2)
        self.assertEqual([e['observed'] for e in h['events']],[106,104,100])
        self.assertEqual(h['events'][0]['previous_addresses'],['9.9.9.9'])
        self.report(['8.8.8.8','2606:4700::6666'])
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM ip_events WHERE server_id=?',(self.sid,)).fetchone()[0],len(samples))

    def test_ipv4_changes_paginate_across_legacy_ipv6_events(self):
        self.node()
        with server.connect() as db:
            db.execute('DELETE FROM ip_events WHERE server_id=?',(self.sid,))
            for i in range(60):
                ip='8.8.8.8' if i%2 else '9.9.9.9'
                for suffix in ['1111','2222']:
                    db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(?,?,?)',(self.sid,json.dumps([ip,'2606:4700::'+suffix]),100+i))
        first=self.history();self.assertEqual(first['total'],60);self.assertEqual(first['change_count'],59)
        self.assertEqual(len(first['events']),50);self.assertTrue(first['has_more'])
        second=self.history('?before='+str(first['next_cursor']))
        self.assertEqual(len(second['events']),10);self.assertFalse(second['has_more'])
        self.assertEqual(len({e['id'] for e in first['events']+second['events']}),60)
        self.assertEqual(self.bob.get(f'/api/servers/{self.sid}/ip-history').status_code,404)

    def test_other_vps_still_record_ipv6_history(self):
        self.node(hkt=False);self.report(['8.8.8.8','2606:4700::2222'],hkt=False)
        h=self.history();self.assertEqual(h['address_family'],'all');self.assertEqual(h['total'],2)
        self.assertIn('2606:4700::2222',h['current_addresses'])

    def test_hkt_api_identifies_node_even_when_capability_is_temporarily_absent(self):
        n=self.node();r=self.post(f'/api/admin/servers/{self.sid}/hkt-dhcp/api');self.assertEqual(r.status_code,200,r.json)
        self.report(['8.8.8.8','2606:4700::2222'],hkt=False)
        self.assertEqual(self.history()['total'],1);self.assertEqual(self.history()['address_family'],'ipv4')

    def test_ipv6_only_egress_does_not_hide_interface_ipv4_or_create_change(self):
        self.node()
        self.report(['8.8.8.8','2606:4700::2222'],egress_ips=['2606:4700::3333'],egress_checked=int(time.time()))
        self.assertEqual(self.history()['total'],1)
        self.report(['9.9.9.9','2606:4700::4444'],egress_ips=['2606:4700::5555'],egress_checked=int(time.time()))
        self.assertEqual(self.history()['current_addresses'],['9.9.9.9'])
        self.assertEqual(self.history()['change_count'],1)
