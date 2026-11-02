"""Deleted groups release provider records; re-selection refreshes local binding."""
import unittest
from unittest.mock import patch
import test_rotation_multi as fixture
import server


class RecreateDNS(unittest.TestCase):
    setUp=fixture.MultiPlan.setUp
    tearDown=fixture.MultiPlan.tearDown
    post=fixture.MultiPlan.post
    sid=fixture.MultiPlan.sid
    refresh=fixture.MultiPlan.refresh
    save=fixture.MultiPlan.save
    row=fixture.MultiPlan.row
    put=fixture.MultiPlan.put
    drop_first=fixture.MultiPlan.drop_first
    multi=fixture.MultiPlan.multi

    def remove(self):
        result=self.put(enabled=False,rotation_id=self.rid,mode=self.row()['mode'])
        self.assertEqual(result.status_code,200,result.json)
        result=self.admin.delete(f'/api/admin/servers/{self.sid("A")}/rotation?rotation_id={self.rid}',headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(result.status_code,200,result.json)

    def choose(self,name,lines):
        with server.connect() as db:cid=db.execute('SELECT connection_id FROM dns_bindings LIMIT 1').fetchone()[0]
        rows=list(self.records.values())
        with patch('rotation_dns.records',return_value=(rows,False)),patch('rotation_dns.dns.get_dns_record',side_effect=lambda c,b:next(r for r in rows if r['RecordId']==b['record_id'])),patch('rotation_dns.dns.update_dns_record') as write:
            result=self.post(f'/api/admin/servers/{self.sid(name)}/rotation/dns-binding',{'connection_id':cid,'domain':'example.com','record_ids':lines})
            write.assert_not_called()
        return result

    def test_three_rounds_delete_and_recreate_same_multi_record_dns(self):
        self.multi();bids=[self.bindings['mobile'],self.bindings['telecom']]
        for cycle in range(3):
            with self.subTest(cycle=cycle):
                self.remove()
                with server.connect() as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_rotations').fetchone()[0],0)
                    self.assertTrue(all('已释放' in r[0] for r in db.execute('SELECT status FROM dns_bindings WHERE id IN (?,?)',bids)))
                chosen=self.choose('A',['mobile','telecom']);self.assertEqual(chosen.status_code,200,chosen.json)
                self.assertEqual({b['id'] for b in chosen.json['bindings']},set(bids))
                result=self.put(bindings=bids,mode='alternating');self.assertEqual(result.status_code,200,result.json)
                self.rid=result.json['rotation']['id']
        self.change.assert_not_called()

    def test_deleted_record_can_move_to_new_primary_matching_real_dns(self):
        self.remove();self.records[self.bindings['mobile']]['Value']='1.1.1.1'
        chosen=self.choose('B',['mobile']);self.assertEqual(chosen.status_code,200,chosen.json)
        bid=chosen.json['binding']['id'];self.assertEqual(bid,self.bindings['mobile'])
        with server.connect() as db:
            b=db.execute('SELECT * FROM dns_bindings WHERE id=?',(bid,)).fetchone()
            self.assertEqual(b['server_id'],self.sid('B'));self.assertEqual(b['expected_ip'],'1.1.1.1')
        d=dict(self.payload,other_server_id=self.sid('A'),binding_id=bid,mode='alternating',failover_server_id=None,failover_binding_ids=[])
        result=self.admin.put(f'/api/admin/servers/{self.sid("B")}/rotation',json=d,headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(result.status_code,200,result.json);self.change.assert_not_called()

    def test_pause_alone_does_not_release_an_existing_plan_record(self):
        self.assertEqual(self.put(enabled=False,rotation_id=self.rid).status_code,200)
        result=self.choose('A',['mobile']);self.assertEqual(result.status_code,409)
        self.assertIn('仍由轮换计划 #',result.json['error'])

    def test_unmanaged_stale_ip_refreshes_but_other_live_auto_dns_is_not_stolen(self):
        self.remove();self.records[self.bindings['mobile']]['Value']='1.1.1.1'
        with server.connect() as db:db.execute('UPDATE dns_bindings SET automatic=1 WHERE id=?',(self.bindings['mobile'],))
        result=self.choose('B',['mobile']);self.assertEqual(result.status_code,409)
        with server.connect() as db:db.execute('UPDATE dns_bindings SET automatic=0 WHERE id=?',(self.bindings['mobile'],))
        result=self.choose('B',['mobile']);self.assertEqual(result.status_code,200,result.json)

    def test_deleted_plan_does_not_allow_overlapping_an_issued_machine_action(self):
        uid=self.admin.get('/api/me').json['id']
        with server.connect() as db:
            db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot','issued',?,?)",(self.sid('B'),uid,self.clock[0],self.clock[0]))
        self.remove()
        chosen=self.choose('A',['mobile']);self.assertEqual(chosen.status_code,200,chosen.json)
        result=self.put(bindings=[self.bindings['mobile']],mode='alternating')
        self.assertEqual(result.status_code,409,result.json);self.assertIn('未完成',result.json['error'])
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_rotations').fetchone()[0],0)
