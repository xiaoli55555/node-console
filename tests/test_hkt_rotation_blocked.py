"""Offline regression: unconfirmed agent jobs must never overlap; terminal retry coverage is in test_hkt_retry_integration."""
import json
import unittest
from unittest.mock import patch
import server
import rotation
import hkt_dhcp
import ip_dns
import test_rotation_emergency as fixture


class HKTBlockedRotation(unittest.TestCase):
    setUp = fixture.OriginalEmergencyProbe.setUp

    def prepare(self, status='expired', emergency=False):
        f=self.f;sid=f.sid('B');now=f.clock[0]
        self.old_ip='42.98.248.3';f.refresh('B',self.old_ip)
        with server.connect() as db:
            metrics=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(sid,)).fetchone()[0])
            metrics.update(capabilities=['reboot','hkt_dhcp'],tcp=1,connections_sampled=now)
            db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(metrics),sid))
        cfg=f.post(f'/api/admin/servers/{sid}/hkt-dhcp/api').json
        with server.connect() as db:
            db.execute('UPDATE detection_plans SET action_connection_id=? WHERE server_id=?',(cfg['connection_id'],sid))
            uid=db.execute("SELECT id FROM users WHERE role='admin'").fetchone()[0]
            self.job=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp',?,?,?)",(sid,uid,status,now-124,now-1)).lastrowid
            db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip=?,new_ip=NULL,drain_started=?,drain_grace_s=0,low_samples=2,last_sample_at=?,emergency=?,action_started=NULL,action_attempts=0,repair_check_required=0 WHERE id=?",(sid,self.old_ip,now-300,now,int(emergency),f.rid))
        real_load=ip_dns.load_connection
        loader=patch('rotation.load_connection',side_effect=lambda db,cipher,cid: real_load(db,cipher,cid))
        loader.start();self.addCleanup(loader.stop)
        f.change.side_effect=ip_dns.invoke_change_ip_api
        return cfg

    def run_ticks(self, count=5):
        f=self.f
        for _ in range(count):
            f.clock[0]+=1
            rotation._run_rotation(server.connect,server.CIPHER,f.rid,f.clock[0])








    def test_reset_does_not_clear_unconfirmed_inflight_job(self):
        self.prepare(status='unconfirmed');f=self.f
        f.post(f'/api/admin/servers/{f.sid("B")}/hkt-dhcp/api')
        with self.assertRaises(ip_dns.ChangeIPBlocked) as caught:
            hkt_dhcp.queue(f.sid('B'),managed=True)
        self.assertEqual(caught.exception.code,'dhcp_unconfirmed')
        self.run_ticks();self.assertEqual(f.change.call_count,0)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commands WHERE server_id=?',(f.sid('B'),)).fetchone()[0],1)

