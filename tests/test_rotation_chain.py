"""API/agent/worker integration with virtual time and simulated external providers."""
import json
import unittest
import test_failover as fixture
import server


class RotationChain(unittest.TestCase):
    def test_two_modes_four_lines_complete_cycle_pause_and_delete(self):
        for mode in ('fixed_primary','alternating'):
            for line in ('mobile','telecom','unicom','default'):
                with self.subTest(mode=mode,line=line):
                    f=fixture.PrimaryFailover(methodName='runTest');f.setUp()
                    try:
                        a,b=f.sid('A'),f.sid('B')
                        url=f'/api/admin/servers/{a}/rotation'
                        headers={'X-CSRF-Token':f.tokens['admin']}
                        self.assertEqual(f.save(enabled=False).status_code,200)
                        self.assertEqual(f.admin.delete(url,headers=headers).status_code,200)
                        if line=='default':
                            bid=f.bindings['mobile']
                            with server.connect() as db:db.execute("UPDATE dns_bindings SET line='default' WHERE id=?",(bid,))
                            f.records[bid]['Line']='default'
                        else:bid=f.bindings[line]
                        original={key:record['Value'] for key,record in f.records.items()}
                        # Use actual persisted connection kinds, with no real provider requests.
                        def connection(db,cipher,cid):
                            return {'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
                        f.mocks[0].side_effect=connection
                        f.payload.update(mode=mode,binding_id=bid,interval_s=600,first_switch_at=f.clock[0]+60,
                                         failover_server_id=None,failover_binding_ids=[],lead_s=0)
                        result=f.save();self.assertEqual(result.status_code,200,result.json)
                        f.rid=result.json['rotation']['id']
                        ready=f.admin.post(url+'/readiness',json=f.payload,headers=headers)
                        self.assertEqual(ready.status_code,200,ready.json)
                        self.assertTrue(ready.json['ok'],ready.json)
                        f.advance(f.row()['next_switch_at']-f.clock[0],online=('A','B'));f.tick()
                        self.assertEqual(f.records[bid]['Value'],'1.1.1.1')
                        if mode=='fixed_primary':
                            f.advance(600,online=('A','B'))
                            with server.connect() as db:
                                metrics=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(a,)).fetchone()[0]);metrics['tcp']=50000
                                db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(metrics),a))
                            f.tick();self.assertEqual(f.records[bid]['Value'],'8.8.8.8')
                        old=b if mode=='fixed_primary' else a
                        old_name='B' if old==b else 'A'
                        f.advance(121,online=('A','B'));f.tick()
                        self.assertEqual(f.change.call_count,0)
                        f.advance(15,online=('A','B'));f.tick()
                        self.assertEqual(f.change.call_count,1)
                        self.assertEqual(f.change.call_args.args[1],old)
                        self.assertEqual(f.row()['phase'],'waiting_ip')
                        f.advance(15,online=('A','B'));f.refresh(old_name,ip='8.8.4.4');f.tick()
                        self.assertEqual(f.row()['phase'],'waiting_probe')
                        f.advance(15,online=('A','B'));f.tick()
                        self.assertEqual(f.row()['phase'],'active')
                        self.assertEqual(f.row()['active_server_id'],b)
                        self.assertEqual(f.records[bid]['Value'],'8.8.4.4' if mode=='fixed_primary' else '1.1.1.1')
                        for key,value in original.items():
                            if key!=bid:self.assertEqual(f.records[key]['Value'],value)
                        paused=f.save(enabled=False);self.assertEqual(paused.status_code,200,paused.json)
                        f.advance(1200,online=('A','B'));f.tick()
                        self.assertEqual(f.change.call_count,1)
                        deleted=f.admin.delete(url,headers=headers);self.assertEqual(deleted.status_code,200,deleted.json)
                        listing=f.admin.get('/api/admin/rotations').json
                        self.assertFalse(any(r['id']==f.rid for r in listing['rotations']))
                    finally:f.tearDown()
