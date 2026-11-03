"""One dedicated cold C serves two independent alternating rotation groups."""
import unittest
import test_rotation_emergency as fixture
import server
import rotation
import failover


class SharedRotationC(unittest.TestCase):
    def setUp(self):
        fixture.OriginalEmergencyProbe.setUp(self)
        f=self.f
        self.addCleanup(self.clear_probe_states)
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        res=f.save(failover_server_id=f.sid('C'),failover_binding_ids=list(f.bindings.values()))
        self.assertEqual(res.status_code,200,res.json)
        for name,address in [('D','4.2.2.2'),('E','208.67.222.222')]:
            n=f.post('/api/servers',{'name':name}).json
            f.nodes[name]=n;f.ips[n['id']]=address;f.health[n['id']]=True
            with server.connect() as db:
                source=db.execute("INSERT INTO detection_sources(name,kind,secret,enabled) VALUES(?,'boce',?,1)",(name,server.CIPHER.encrypt(b'fixture-source').decode())).lastrowid
                action=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES(?,'change_ip','{}',?)",(name,server.CIPHER.encrypt(b'fixture-action').decode())).lastrowid
                db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,443,1)',(n['id'],))
                db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,daily_limit,next_at,response_mode,action_connection_id,failure_threshold) VALUES(?,?,?,120,1,1000,?,'change_api',?,2)",(n['id'],source,'["31"]',f.clock[0]+120,action))
            f.refresh(name)
        with server.connect() as db:
            cid=db.execute("SELECT id FROM ip_connections WHERE kind='alidns' LIMIT 1").fetchone()[0]
            self.other_binding=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic) VALUES(?,?,'example.com','d-record','d-edge','mobile','4.2.2.2',443,1)",(f.sid('D'),cid)).lastrowid
            f.records[self.other_binding]={'RecordId':'d-record','RR':'d-edge','Line':'mobile','Type':'A','Value':'4.2.2.2','TTL':60,'Status':'ENABLE'}
        payload=dict(f.payload,other_server_id=f.sid('E'),binding_id=self.other_binding,failover_server_id=f.sid('C'),failover_binding_ids=[self.other_binding])
        res=f.admin.put(f'/api/admin/servers/{f.sid("D")}/rotation',json=payload,headers={'X-CSRF-Token':f.tokens['admin']})
        self.assertEqual(res.status_code,200,res.json)
        self.other_rid=res.json['rotation']['id']

    def clear_probe_states(self):
        with server.connect() as db:
            db.execute('DELETE FROM vps_failover_leases')
            db.execute('DELETE FROM vps_failover_probe_state')

    def leases(self,rid):
        with server.connect() as db:return db.execute('SELECT COUNT(*) FROM vps_failover_leases WHERE rotation_id=?',(rid,)).fetchone()[0]

    def fail_both_groups(self):
        f=self.f
        for n in ('A','B','D','E'):f.down(n)
        for _ in range(4):f.advance(2,online=('C',));f.tick()

    def test_same_dedicated_C_can_be_selected_by_both_plans(self):
        f=self.f
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM vps_rotations WHERE failover_server_id=?',(f.sid('C'),)).fetchone()[0],2)
            self.assertIsNone(db.execute('SELECT 1 FROM vps_rotations WHERE primary_server_id=? OR other_server_id=?',(f.sid('C'),f.sid('C'))).fetchone())
            self.assertEqual(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(f.sid('C'),)).fetchone()[0],0)
        self.assertEqual(self.leases(f.rid),0);self.assertEqual(self.leases(self.other_rid),0)

    def test_both_plans_take_over_with_distinct_profiles_and_recover_independently(self):
        f=self.f;self.fail_both_groups()
        self.assertEqual(f.value('mobile'),'9.9.9.9')
        self.assertEqual(f.records[self.other_binding]['Value'],'9.9.9.9')
        self.assertEqual(self.leases(f.rid),3);self.assertEqual(self.leases(self.other_rid),1)
        f.advance(2,online=('A','C'));f.tick();f.advance(30,online=('A','C'));f.tick()
        self.assertEqual(f.value('mobile'),'8.8.8.8');self.assertEqual(self.leases(f.rid),0)
        self.assertEqual(f.records[self.other_binding]['Value'],'9.9.9.9');self.assertEqual(self.leases(self.other_rid),1)
        with server.connect() as db:self.assertEqual(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(f.sid('C'),)).fetchone()[0],1)
        f.advance(2,online=('A','D','C'));f.tick();f.advance(30,online=('A','D','C'));f.tick()
        self.assertEqual(f.records[self.other_binding]['Value'],'4.2.2.2');self.assertEqual(self.leases(self.other_rid),0)
        with server.connect() as db:self.assertEqual(db.execute('SELECT automatic FROM detection_plans WHERE server_id=?',(f.sid('C'),)).fetchone()[0],0)
        f.change.assert_not_called()

    def test_another_plans_success_cannot_replace_its_own_probe(self):
        f=self.f
        for n in ('A','B','D','E'):f.down(n)
        # Only A/B's source profile is completed. D/E's node #31 is not tested.
        rotation.tick(server.connect,server.CIPHER)
        with server.connect() as db:
            source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(f.sid('A'),)).fetchone()[0]
            db.execute('UPDATE detection_plans SET source_id=?,nodes=? WHERE server_id=?',(source,'["13"]',f.sid('C')))
        f.refresh('C');rotation.tick(server.connect,server.CIPHER)
        self.assertEqual(self.leases(f.rid),3);self.assertEqual(self.leases(self.other_rid),0)
        self.assertEqual(f.records[self.other_binding]['Value'],'4.2.2.2')

    def test_one_healthy_partner_in_each_plan_keeps_shared_C_idle(self):
        f=self.f;f.down('A');f.down('D')
        for _ in range(3):f.advance(2,online=('B','E','C'));f.tick()
        self.assertEqual(self.leases(f.rid),0);self.assertEqual(self.leases(self.other_rid),0)
        self.assertNotEqual(f.value('mobile'),'9.9.9.9')
        self.assertNotEqual(f.records[self.other_binding]['Value'],'9.9.9.9')

    def test_overview_counts_groups_not_each_DNS_member(self):
        f=self.f
        with server.connect() as db:
            member=dict(db.execute('SELECT * FROM vps_rotations WHERE id=?',(f.rid,)).fetchone())
            member.pop('id');member['binding_id']=f.bindings['telecom']
            columns=list(member)
            db.execute('INSERT INTO vps_rotations('+','.join(columns)+') VALUES('+','.join('?' for _ in columns)+')',[member[k] for k in columns])
        res=f.admin.get('/api/admin/rotations')
        self.assertEqual(res.status_code,200,res.json)
        for item in res.json['rotations']:self.assertEqual(item['failover_plan_count'],2)

    def test_only_failed_group_uses_shared_C_while_other_pair_remains_normal(self):
        f=self.f;f.down('D');f.down('E')
        for _ in range(4):f.advance(2,online=('A','B','C'));f.tick()
        self.assertEqual(self.leases(f.rid),0);self.assertEqual(self.leases(self.other_rid),1)
        self.assertEqual(f.value('mobile'),'8.8.8.8')
        self.assertEqual(f.records[self.other_binding]['Value'],'9.9.9.9')
