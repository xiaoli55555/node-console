"""Original-mode fault handoff must use a new standby probe round."""
import unittest
import test_failover as fixture
import server
import rotation
from ip_dns import IntegrationError

class OriginalEmergencyProbe(unittest.TestCase):
    def setUp(self):
        self.f=fixture.PrimaryFailover(methodName='runTest');self.f.setUp()
        self.addCleanup(self.f.tearDown)
        f=self.f;url=f'/api/admin/servers/{f.sid("A")}/rotation'
        self.assertEqual(f.save(enabled=False).status_code,200)
        self.assertEqual(f.admin.delete(url,headers={'X-CSRF-Token':f.tokens['admin']}).status_code,200)
        f.payload.update(mode='alternating',failover_server_id=None,failover_binding_ids=[])
        result=f.save();self.assertEqual(result.status_code,200,result.json)
        f.rid=result.json['rotation']['id']
    def test_fault_requests_fresh_round_then_switches_before_deadline(self):
        f=self.f;deadline=f.row()['next_switch_at'];f.health[f.sid('A')]=False;f.refresh('A')
        f.tick()
        self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()
        after=f.row()['emergency_probe_after'];self.assertEqual(after,f.clock[0]+1)
        with server.connect() as db:self.assertLessEqual(db.execute('SELECT next_at FROM detection_plans WHERE server_id=?',(f.sid('B'),)).fetchone()[0],after)
        # Worker retries cannot accept the old successful probe.
        f.tick();self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.advance(2,online=('A','B'));f.tick()
        self.assertLess(f.clock[0],deadline)
        self.assertEqual(f.value('mobile'),'1.1.1.1');self.assertIsNone(f.row()['emergency_probe_after'])
    def test_fresh_failed_round_does_not_publish_standby(self):
        f=self.f
        with self.assertRaises(IntegrationError):rotation._dns_switch(server.connect,server.CIPHER,f.rid,f.clock[0],emergency=True)
        f.health[f.sid('B')]=False;f.advance(2,online=('A','B'))
        with self.assertRaises(IntegrationError):rotation._dns_switch(server.connect,server.CIPHER,f.rid,f.clock[0],emergency=True)
        self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()
    def test_standby_mid_ip_change_cannot_be_published(self):
        f=self.f
        with server.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=? WHERE id=?",(f.sid('B'),f.rid))
        with self.assertRaisesRegex(IntegrationError,'换 IP 或复检'):rotation._dns_switch(server.connect,server.CIPHER,f.rid,f.clock[0],emergency=True)
        self.assertEqual(f.value('mobile'),'8.8.8.8')

    def test_twenty_recoveries_then_new_fault_require_new_probe(self):
        f=self.f
        for cycle in range(20):
            with self.subTest(cycle=cycle):
                f.health[f.sid('A')]=False;f.advance(5,online=('A','B'));f.tick()
                self.assertIsNotNone(f.row()['emergency_probe_after'])
                f.health[f.sid('A')]=True;f.advance(5,online=('A','B'));f.tick()
                self.assertIsNone(f.row()['emergency_probe_after'])
                self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.health[f.sid('A')]=False;f.refresh('A');f.tick()
        self.assertEqual(f.value('mobile'),'8.8.8.8')
        self.assertEqual(f.row()['emergency_probe_after'],f.clock[0]+1)
        f.advance(2,online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1')
