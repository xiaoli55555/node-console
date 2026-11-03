"""Provider errors are unknown; high TCP alone cannot invalidate target failures."""
import json
import unittest
from unittest.mock import patch
from ip_dns import IntegrationError
import detectors
import rotation
import test_rotation_emergency as fixture
import server


class ProviderOutage(unittest.TestCase):
    def setUp(self):
        fixture.OriginalEmergencyProbe.setUp(self)

    def evidence(self, state, tcp=500):
        f=self.f
        with server.connect() as db:
            for name in ('A','B'):
                sid=f.sid(name)
                metrics=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(sid,)).fetchone()[0])
                metrics.update(tcp=tcp,connections_sampled=f.clock[0])
                db.execute('UPDATE servers SET metrics=?,seen=? WHERE id=?',(json.dumps(metrics),f.clock[0],sid))
                p=db.execute('SELECT p.*,m.port FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(sid,)).fetchone()
                for _ in range(p['failure_threshold']):
                    rows=[{'node_id':str(n),'state':state,'name':'provider test'} for n in json.loads(p['nodes'])]
                    rid=db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,details,scheduled) VALUES(?,?,?,?,?,'completed',?,?,?,1)",(sid,p['source_id'],f.ips[sid],p['port'],p['nodes'],f.clock[0],f.clock[0],json.dumps(rows))).lastrowid
                    run=db.execute('SELECT * FROM detection_runs WHERE id=?',(rid,)).fetchone()
                    detectors.finish(db,run,'检测异常或结果不完整' if state=='unknown' else '所选检测点 TCP 均不通（待复核）',rows)

    def test_all_nodes_provider_timeout_classified_unknown(self):
        for failure in ('API timeout','node timeout','TLS error','invalid response'):
            rows=[{'node_id':str(n),'error_code':500,'error':failure,'packets_transmitted':3,'packets_received':0} for n in (13,43)]
            status,details=detectors.summarize(rows,['13','43'])
            self.assertTrue(all(x['state']=='unknown' for x in details));self.assertIn('异常',status)

    def test_normal_tcp_and_ten_provider_outages_do_not_trigger_mutation_or_incident(self):
        f=self.f;deadline=f.row()['next_switch_at']
        for cycle in range(10):
            f.advance(15,online=('A','B'));self.evidence('unknown');f.tick()
            self.assertEqual(f.value('mobile'),'8.8.8.8');self.assertEqual(f.row()['next_switch_at'],deadline)
            self.assertEqual(f.row()['phase'],'active');f.change.assert_not_called()
            with server.connect() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM detection_incidents').fetchone()[0],0)
                self.assertFalse(rotation._fixed_failure(db,f.sid('A'),f.clock[0]))
                self.assertFalse(rotation._fixed_failure(db,f.sid('B'),f.clock[0]))
                self.assertEqual(db.execute('SELECT MAX(failure_streak) FROM detection_plans').fetchone()[0],0)

    def test_due_rotation_does_not_publish_unknown_standby(self):
        f=self.f;self.evidence('unknown')
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(f.clock[0],f.rid))
        with patch('rotation.boce_dns_gate',side_effect=detectors.boce_dns_gate):
            with self.assertRaises(IntegrationError):rotation._dns_switch(server.connect,server.CIPHER,f.rid,f.clock[0])
        self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()

    def test_provider_recovers_without_forcing_ip_repair(self):
        f=self.f;self.evidence('unknown');f.tick()
        f.advance(15,online=('A','B'));self.evidence('reachable');f.tick()
        self.assertEqual(f.value('mobile'),'8.8.8.8');self.assertEqual(f.row()['phase'],'active');f.change.assert_not_called()

    def test_target_timeout_despite_high_connections_waits_for_reference(self):
        # Existing TCP can survive partial blocking; a provider which falsely reports
        # valid zero-reply results is indistinguishable without independent evidence.
        status,rows=detectors.summarize([{'node_id':'13','packets_transmitted':3,'packets_received':0,'error_code':0}],['13'])
        self.assertEqual(rows[0]['state'],'unreachable')
        self.evidence('unreachable',tcp=500)
        with server.connect() as db:
            self.assertFalse(rotation._fixed_failure(db,self.f.sid('A'),self.f.clock[0]))
            self.assertFalse(rotation._fixed_failure(db,self.f.sid('B'),self.f.clock[0]))
