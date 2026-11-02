"""Recovered carrier alerts must reflect current health without altering rotation work."""
import unittest
import test_rotation_emergency as fixture
import server


class CarrierAlertRecovery(unittest.TestCase):
    setUp=fixture.OriginalEmergencyProbe.setUp

    def events(self):
        with server.connect() as db:
            return [x[0] for x in db.execute('SELECT message FROM vps_rotation_events WHERE rotation_id=? ORDER BY id',(self.f.rid,))]

    def test_heartbeat_recovery_clears_alert_without_dns_or_timer_changes(self):
        f=self.f;before=f.row();f.down();f.tick()
        self.assertIn('心跳超时',f.row()['status'])
        self.assertTrue(any('已 30 秒未收到上报，阈值 15 秒' in x for x in self.events()))
        f.advance(5,online=('A','B'));f.tick()
        after=f.row()
        self.assertIsNone(after['emergency_probe_after'])
        self.assertIn('已恢复正常',after['status'])
        self.assertEqual(after['next_switch_at'],before['next_switch_at'])
        self.assertEqual(after['active_server_id'],before['active_server_id'])
        self.assertEqual(after['action_attempts'],before['action_attempts'])
        self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()
        count=len(self.events());f.tick();self.assertEqual(len(self.events()),count)

    def test_domestic_failure_has_distinct_diagnostic_and_recovers(self):
        f=self.f;f.health[f.sid('A')]=False;f.refresh('A');f.tick()
        self.assertIn('国内 TCP 检测不通：8.8.8.8:443',f.row()['status'])
        self.assertNotIn('心跳超时',f.row()['status'])
        f.health[f.sid('A')]=True;f.advance(5,online=('A','B'));f.tick()
        self.assertIn('已恢复正常',f.row()['status']);self.assertIsNone(f.row()['emergency_probe_after'])

    def test_upgrade_repairs_legacy_stale_text_even_when_marker_already_cleared(self):
        f=self.f;deadline=f.row()['next_switch_at']
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET status='轮换暂缓：当前承载异常，已请求刚换下 VPS #2 加测一轮；通过后立即接替',emergency_probe_after=NULL WHERE id=?",(f.rid,))
        f.tick();self.assertIn('已恢复正常',f.row()['status'])
        self.assertEqual(f.row()['next_switch_at'],deadline);self.assertEqual(f.value('mobile'),'8.8.8.8')

    def test_unrelated_dns_blocker_is_preserved_after_health_recovery(self):
        f=self.f
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET emergency_probe_after=?,status='轮换暂缓：DNS 记录和当前承载 VPS IP 不一致，已停止轮换' WHERE id=?",(f.clock[0]-2,f.rid))
        f.tick();self.assertIsNone(f.row()['emergency_probe_after'])
        self.assertIn('DNS 记录和当前承载',f.row()['status'])

    def test_healthy_carrier_does_not_erase_standby_inflight_task(self):
        f=self.f;started=f.clock[0]
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=?,old_ip='1.1.1.1',action_started=?,emergency_probe_after=?,status='HKT 换 IP 请求已下发，等待新 IP' WHERE id=?",(f.sid('B'),started,started-1,f.rid))
        f.tick();r=f.row()
        self.assertEqual(r['phase'],'waiting_ip');self.assertEqual(r['action_started'],started)
        self.assertEqual(r['drain_server_id'],f.sid('B'));self.assertIsNone(r['emergency_probe_after'])
        self.assertNotIn('已恢复正常',r['status']);self.assertEqual(f.value('mobile'),'8.8.8.8')

    def test_missing_current_success_cannot_clear_fault_alert(self):
        f=self.f;f.health[f.sid('A')]=False;f.refresh('A');f.tick()
        f.advance(1,online=('A',));f.tick()
        self.assertNotIn('已恢复正常',f.row()['status'])
        self.assertIsNotNone(f.row()['emergency_probe_after'])
