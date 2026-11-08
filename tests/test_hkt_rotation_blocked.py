"""Offline regression: terminal agent jobs must not become provider retry storms."""
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

    def test_expired_job_stops_retry_and_deduplicates_audit(self):
        self.prepare();self.run_ticks()
        f=self.f;f.change.assert_not_called()
        self.assertEqual(f.row()['action_attempts'],0)
        self.assertIn('本地 DHCP',f.row()['status'])
        from monitor_api import category
        self.assertEqual(category(f.row()['status']),'action_blocked')
        with server.connect() as db:
            events=db.execute('SELECT kind,evidence FROM rotation_audit WHERE rotation_id=?',(f.rid,)).fetchall()
            self.assertEqual(sum(e['kind']=='ip_change_blocked' for e in events),1)
            self.assertFalse(any(e['kind']=='ip_change_rejected' for e in events))
            evidence=json.loads(next(e['evidence'] for e in events if e['kind']=='ip_change_blocked'))
            self.assertEqual(evidence['trigger'],'local_dhcp_guard')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commands WHERE server_id=?',(f.sid('B'),)).fetchone()[0],1)
        self.assertEqual(f.value('mobile'),'8.8.8.8')

    def test_failed_job_also_blocks_emergency_retry(self):
        self.prepare(status='failed',emergency=True)
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='waiting_ip',action_started=? WHERE id=?",(self.f.clock[0]-61,self.f.rid))
        self.run_ticks();self.f.change.assert_not_called()
        self.assertEqual(self.f.row()['action_attempts'],0)

    def test_new_ip_progresses_despite_expired_job(self):
        self.prepare();self.run_ticks()
        f=self.f;f.refresh('B','42.98.248.4');self.run_ticks(1)
        self.assertEqual(f.row()['phase'],'waiting_probe')
        self.assertEqual(f.row()['new_ip'],'42.98.248.4')
        self.assertEqual(f.value('mobile'),'8.8.8.8')
        f.change.assert_not_called()

    def test_explicit_reset_allows_one_new_job(self):
        self.prepare();self.run_ticks()
        f=self.f
        f.post(f'/api/admin/servers/{f.sid("B")}/hkt-dhcp/api')
        self.run_ticks()
        with server.connect() as db:
            rows=db.execute('SELECT status FROM commands WHERE server_id=? ORDER BY id',(f.sid('B'),)).fetchall()
        self.assertEqual([r[0] for r in rows],['expired','queued'])
        self.assertEqual(f.change.call_count,1)

    def test_queue_rechecks_guard_with_structured_error(self):
        self.prepare()
        with self.assertRaises(ip_dns.ChangeIPBlocked) as caught:
            hkt_dhcp.queue(self.f.sid('B'),managed=True)
        self.assertEqual(caught.exception.command_id,self.job)
        self.assertEqual(caught.exception.code,'dhcp_expired')

    def test_guard_race_is_local_block_not_provider_rejection(self):
        self.prepare();f=self.f
        # A terminal result can arrive after preflight but before queue's lock.
        with patch('rotation._dhcp_action_blocked',return_value=False):
            self.run_ticks(1)
        self.run_ticks()
        self.assertEqual(f.change.call_count,1)
        self.assertEqual(f.row()['action_attempts'],1)
        with server.connect() as db:
            kinds=[r[0] for r in db.execute('SELECT kind FROM rotation_audit WHERE rotation_id=?',(f.rid,))]
        self.assertEqual(kinds.count('ip_change_blocked'),1)
        self.assertNotIn('ip_change_rejected',kinds)

    def test_late_expired_result_cannot_clear_interlock(self):
        self.prepare();f=self.f
        with server.connect() as db:
            hkt_dhcp.apply_result(db,f.sid('B'),dict(id=self.job,state='changed',new_ip='42.98.248.4'),f.clock[0])
            self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(self.job,)).fetchone()[0],'expired')
        self.run_ticks();self.assertEqual(f.change.call_count,0)

    def test_reset_does_not_clear_unconfirmed_inflight_job(self):
        self.prepare(status='unconfirmed');f=self.f
        f.post(f'/api/admin/servers/{f.sid("B")}/hkt-dhcp/api')
        with self.assertRaises(ip_dns.ChangeIPBlocked) as caught:
            hkt_dhcp.queue(f.sid('B'),managed=True)
        self.assertEqual(caught.exception.code,'dhcp_unconfirmed')
        self.run_ticks();self.assertEqual(f.change.call_count,0)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM commands WHERE server_id=?',(f.sid('B'),)).fetchone()[0],1)

    def test_long_polling_keeps_one_block_event_and_zero_attempts(self):
        self.prepare();f=self.f
        for _ in range(120):
            with server.connect() as db:
                for node in db.execute('SELECT id,metrics FROM servers').fetchall():
                    metrics=json.loads(node['metrics'] or '{}')
                    metrics['connections_sampled']=f.clock[0]
                    db.execute('UPDATE servers SET seen=?,metrics=? WHERE id=?',(f.clock[0],json.dumps(metrics),node['id']))
                # Other status writers must not defeat event deduplication.
                db.execute("UPDATE vps_rotations SET status='检查排空采样' WHERE id=?",(f.rid,))
            self.run_ticks(1)
        self.assertEqual(f.change.call_count,0)
        self.assertEqual(f.row()['action_attempts'],0)
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rotation_audit WHERE rotation_id=? AND kind='ip_change_blocked'",(f.rid,)).fetchone()[0],1)
