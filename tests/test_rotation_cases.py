import json, sqlite3, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import rotation
from ip_dns import IntegrationError

class RotationConditions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'test.db'
        rotation.initialize(self.connect)
        with self.connect() as db:
            db.executescript('CREATE TABLE servers(id INTEGER,seen INTEGER);INSERT INTO servers VALUES(1,990);INSERT INTO servers VALUES(2,990);CREATE TABLE detection_runs(server_id INTEGER,created INTEGER);CREATE TABLE detection_plans(server_id INTEGER,next_at INTEGER);')
            db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,phase,next_switch_at,updated,interval_s,lead_s) VALUES(1,1,2,1,1,1,'active',1000,900,120,20)")
            db.execute('INSERT INTO detection_runs VALUES(1,990)');db.execute('INSERT INTO detection_runs VALUES(2,990)')
    def tearDown(self):self.tmp.cleanup()
    def connect(self):
        db=sqlite3.connect(self.path);db.row_factory=sqlite3.Row;return db
    def row(self):
        with self.connect() as db:return dict(db.execute('SELECT * FROM vps_rotations').fetchone())
    def test_paused_never_probes_or_switches(self):
        with self.connect() as db:db.execute('UPDATE vps_rotations SET enabled=0')
        with patch('rotation._failed_ip') as failed,patch('rotation._dns_switch') as switch:
            rotation._run_rotation(self.connect,None,1,1000);failed.assert_not_called();switch.assert_not_called()
    def test_current_failure_before_deadline_attempts_emergency_switch(self):
        with patch('rotation._failed_ip',side_effect=[True,False]),patch('rotation._dns_switch',side_effect=IntegrationError('standby not ready')) as switch:
            with self.assertRaises(IntegrationError):rotation._run_rotation(self.connect,None,1,950)
            switch.assert_called_once_with(self.connect,None,1,950,emergency=True)
        self.assertEqual(self.row()['active_server_id'],1)
    def test_failed_standby_repairs_without_changing_current_dns(self):
        with patch('rotation._failed_ip',side_effect=[False,True]),patch('rotation._fresh_ip',return_value=('8.8.8.8',443,{})),patch('rotation._dns_switch') as switch:
            rotation._run_rotation(self.connect,None,1,950);switch.assert_not_called()
        r=self.row();self.assertEqual(r['active_server_id'],1);self.assertEqual(r['drain_server_id'],2);self.assertEqual(r['emergency'],1)
    def test_normal_deadline_calls_dns_switch(self):
        with patch('rotation._failed_ip',return_value=False),patch('rotation._dns_switch') as switch:
            rotation._run_rotation(self.connect,None,1,1000);switch.assert_called_once_with(self.connect,None,1,1000)
    def test_new_active_fails_during_drain_attempts_return(self):
        with self.connect() as db:db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=2")
        with patch('rotation._failed_ip',side_effect=[True,False]),patch('rotation._dns_switch',side_effect=IntegrationError('simulated')) as switch:
            with self.assertRaises(IntegrationError):rotation._run_rotation(self.connect,None,1,950)
            self.assertTrue(switch.call_args.kwargs['emergency'])
    def test_failure_during_standby_ip_change_does_not_deadlock_recovery(self):
        with self.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=2,old_ip='8.8.8.8',action_started=940")
        with patch('rotation._failed_ip',return_value=True),patch('rotation._fresh_ip',return_value=('9.9.9.9',443,{})),patch('rotation._dns_switch') as switch:
            rotation._run_rotation(self.connect,None,1,950);switch.assert_not_called()
        self.assertEqual(self.row()['phase'],'waiting_probe')
    def test_old_machine_failure_skips_drain_grace(self):
        with self.connect() as db:db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=2,drain_started=940,drain_grace_s=600")
        with patch('rotation._failed_ip',side_effect=[False,True]),patch('rotation._validated_plan'),patch('rotation._fresh_ip',side_effect=IntegrationError('no report')):
            rotation._run_rotation(self.connect,None,1,950)
        self.assertEqual(self.row()['emergency'],1);self.assertEqual(self.row()['drain_grace_s'],0)
    def test_failed_new_ip_reenters_immediate_replacement(self):
        with self.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_probe',drain_server_id=2,new_ip='9.9.9.9',action_started=940")
        with self.connect() as db:db.execute('CREATE TABLE ip_monitors(server_id INTEGER,port INTEGER)');db.execute('INSERT INTO ip_monitors VALUES(2,443)')
        with patch('rotation._fresh_ip',return_value=('9.9.9.9',443,{})),patch('rotation.boce_dns_gate',return_value='unreachable'),patch('rotation._failed_ip',return_value=True):
            rotation._run_rotation(self.connect,None,1,950)
        self.assertEqual(self.row()['phase'],'draining');self.assertEqual(self.row()['low_samples'],2)

    def test_both_ips_fail_prioritizes_standby_repair_without_blind_dns_write(self):
        with patch('rotation._failed_ip',return_value=True),patch('rotation._fresh_ip',return_value=('8.8.8.8',443,{})),patch('rotation._dns_switch') as switch:
            rotation._run_rotation(self.connect,None,1,950);switch.assert_not_called()
        self.assertEqual(self.row()['drain_server_id'],2);self.assertEqual(self.row()['emergency'],1)

    def test_active_offline_uses_healthy_standby(self):
        with self.connect() as db:db.execute('UPDATE servers SET seen=800 WHERE id=1')
        with patch('rotation._dns_switch',side_effect=IntegrationError('simulated')) as switch:
            with self.assertRaises(IntegrationError):rotation._run_rotation(self.connect,None,1,1000)
            switch.assert_called_once_with(self.connect,None,1,1000,emergency=True,offline=True)
    def test_both_offline_preserves_dns(self):
        with self.connect() as db:db.execute('UPDATE servers SET seen=800')
        with patch('rotation._dns_switch') as switch:
            with self.assertRaisesRegex(IntegrationError,'均离线'):rotation._run_rotation(self.connect,None,1,1000)
            switch.assert_not_called()

    def test_offline_threshold_is_short_and_configurable(self):
        with self.connect() as db:
            db.execute('UPDATE servers SET seen=985 WHERE id=1')
            self.assertTrue(rotation._offline(db,1,1000,15))
            self.assertFalse(rotation._offline(db,1,1000,20))
            self.assertFalse(rotation._offline(db,2,1000,15))

    def test_reboot_wait_does_not_call_api_or_repeat_reboot(self):
        with self.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',drain_server_id=2,old_ip='8.8.8.8',action_started=800,next_switch_at=2000")
        with patch('rotation._failed_ip',return_value=False),patch('rotation._fresh_ip',return_value=('8.8.8.8',443,{})),patch('rotation._validated_plan',return_value={'rotation_action':'reboot','action_connection_id':None}),patch('rotation.queue_reboot') as reboot,patch('rotation.invoke_change_ip_api') as api:
            rotation._run_rotation(self.connect,None,1,1000)
            rotation._run_rotation(self.connect,None,1,1010)
            reboot.assert_not_called();api.assert_not_called()
        self.assertEqual(self.row()['phase'],'waiting_ip')
        self.assertIn('不重复重启',self.row()['status'])
