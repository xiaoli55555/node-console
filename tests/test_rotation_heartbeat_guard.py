"""Heartbeat loss requires fresh business evidence before emergency mutation."""
import json
import unittest
from unittest.mock import patch,MagicMock
import test_rotation_emergency as fixture
import server
import detectors


class HeartbeatGuard(unittest.TestCase):
    def setUp(self):
        fixture.OriginalEmergencyProbe.setUp(self)
        self.f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}

    def suspect(self,age=30):
        f=self.f;deadline=f.row()['next_switch_at']
        with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(f.clock[0]-age,f.sid('A')))
        f.tick();return deadline

    def takeover(self,age=30):
        f=self.f;deadline=self.suspect(age)
        self.assertIsNotNone(f.row()['emergency_probe_after'])
        self.assertIsNone(f.row()['repair_check'])
        f.advance(2,online=('B',));f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1')
        f.change.assert_not_called()
        self.assertEqual(f.row()['repair_check_required'],1)
        return deadline

    def test_timeout_tests_B_before_switching_and_never_changes_B_ip(self):
        f=self.f;deadline=self.suspect()
        self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()
        self.assertIsNotNone(f.row()['emergency_probe_after'])
        self.assertIsNone(f.row()['repair_check'])
        self.assertEqual(f.row()['next_switch_at'],deadline)
        f.advance(2,online=('B',));f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()

    def test_fresh_domestic_and_port_success_preserve_A_ip_then_return(self):
        f=self.f;self.takeover(age=100)
        f.advance(2,online=('B',));f.offline_probe(reachable=True);f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()
        self.assertIn('保留原 IP',f.row()['status'])
        f.advance(1,online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()
        self.assertEqual(f.row()['phase'],'draining')
        self.assertEqual(f.row()['drain_server_id'],f.sid('B'))
        self.assertEqual(f.row()['emergency'],0)

    def test_unknown_or_pending_results_hold_B_without_A_ip_change(self):
        f=self.f;self.takeover();f.advance(2,online=('B',));f.offline_probe(reachable=True)
        with server.connect() as db:
            db.execute("UPDATE detection_runs SET details=? WHERE id=(SELECT MAX(id) FROM detection_runs WHERE server_id=?)",(json.dumps([{'node_id':'13','state':'unknown'}]),f.sid('A')))
        f.tick();self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()

    def test_one_failure_cannot_bypass_two_round_confirmation(self):
        f=self.f;self.takeover();f.advance(2,online=('B',));f.offline_probe()
        with server.connect() as db:db.execute('DELETE FROM detection_runs WHERE id=(SELECT MAX(id) FROM detection_runs WHERE server_id=?)',(f.sid('A'),))
        f.tick();f.advance(2,online=('B',));f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()

    def test_heartbeat_takeover_keeps_selected_record_on_B_with_C_configured(self):
        f=self.f
        response=f.save(failover_server_id=f.sid('C'),failover_binding_ids=list(f.bindings.values()))
        self.assertEqual(response.status_code,200,response.json)
        self.takeover();f.advance(2,online=('B','C'));f.offline_probe(reachable=True);f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()
        # Other A-bound records may independently use configured C; this
        # rotation's selected record stays on verified B.
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))

    def test_confirmed_domestic_failure_repairs_A_only_after_B_takeover(self):
        f=self.f;self.takeover();f.advance(2,online=('B',));f.offline_probe();f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1')
        self.assertEqual(f.change.call_count,1);self.assertEqual(f.change.call_args.args[1],f.sid('A'))
        self.assertEqual(f.row()['phase'],'waiting_ip')

    def test_domestic_success_never_confirms_fault_from_panel_tcp_failures(self):
        f=self.f;self.takeover();f.advance(2,online=('B',));f.offline_probe(reachable=True)
        attempts=[]
        def port(address,**kwargs):
            if address[0]=='8.8.8.8':
                attempts.append((address,kwargs['timeout']))
                raise OSError('original business port failed')
            return MagicMock()
        deadline=f.row()['next_switch_at']
        with patch('rotation.socket.create_connection',side_effect=port):
            for _ in range(3):
                f.tick();f.advance(2,online=('B',))
        self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()
        self.assertEqual(attempts[:2],[(('8.8.8.8',443),4)]*2)
        self.assertFalse(json.loads(f.row()['repair_check'])['confirmed'])
        self.assertEqual(f.row()['next_switch_at'],deadline)
        f.refresh('A');f.tick()
        self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()

    def test_urgent_tcp_retry_success_preserves_ip_and_deadline(self):
        f=self.f;self.takeover(age=100);f.advance(2,online=('B',));f.offline_probe(reachable=True)
        deadline=f.row()['next_switch_at'];attempts=[]
        def port(address,**kwargs):
            if address[0]=='8.8.8.8':
                attempts.append(address)
                if len(attempts)==1:raise OSError('transient panel network failure')
            return MagicMock()
        with patch('rotation.socket.create_connection',side_effect=port):f.tick()
        f.change.assert_not_called()
        self.assertEqual(len(attempts),2)
        self.assertEqual(f.row()['next_switch_at'],deadline)
        proof=json.loads(f.row()['repair_check'])
        self.assertFalse(proof['confirmed']);self.assertTrue(proof['panel_tcp_ok'])
        self.assertEqual(proof['panel_tcp_attempts'],2)

    def test_legacy_single_failure_cache_must_get_fresh_tcp_check(self):
        f=self.f;self.takeover(age=100);f.advance(2,online=('B',));f.offline_probe(reachable=True)
        with server.connect() as db:
            state=json.loads(f.row()['repair_check'])
            state.update(run=db.execute('SELECT MAX(id) FROM detection_runs WHERE server_id=?',(f.sid('A'),)).fetchone()[0],confirmed=True,checked=f.clock[0])
            state['tcp_policy']='retry_once'
            db.execute('UPDATE vps_rotations SET repair_check=? WHERE id=?',(json.dumps(state),f.rid))
        f.tick();f.change.assert_not_called()
        self.assertFalse(json.loads(f.row()['repair_check'])['confirmed'])

    def test_scheduled_probe_uses_frozen_A_ip_after_agent_is_stale(self):
        f=self.f;self.takeover(age=100);f.advance(2,online=('B',))
        with patch('detectors.boce',return_value={'data':{'id':'heartbeat-check'}}) as provider:
            detectors.start_run(server.connect,server.CIPHER,f.sid('A'),scheduled=True)
        self.assertEqual(provider.call_args.args[2]['host'],'8.8.8.8:443')

    def test_heartbeat_recovery_before_takeover_keeps_deadline(self):
        f=self.f;deadline=self.suspect();f.advance(2,online=('A','B'));f.tick()
        self.assertIsNone(f.row()['emergency_probe_after']);self.assertEqual(f.row()['next_switch_at'],deadline)
        self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()

    def test_mismatched_or_old_A_results_cannot_authorize_repair(self):
        f=self.f;self.takeover();f.advance(2,online=('B',));f.offline_probe()
        with server.connect() as db:
            rows=db.execute('SELECT id,created,updated,ip,port,source_id,nodes FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 2',(f.sid('A'),)).fetchall()
            saved=[dict(x) for x in rows]
            wrong_source=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(f.sid('B'),)).fetchone()[0]
        for field,value in [('ip','9.9.9.10'),('port',444),('source_id',wrong_source),('nodes','["19"]'),('created',f.clock[0]-60),('updated',f.clock[0]-100)]:
            with self.subTest(field=field):
                with server.connect() as db:
                    for row in saved:
                        db.execute('UPDATE detection_runs SET created=?,updated=?,ip=?,port=?,source_id=?,nodes=? WHERE id=?',(row['created'],row['updated'],row['ip'],row['port'],row['source_id'],row['nodes'],row['id']))
                        db.execute('UPDATE detection_runs SET '+field+'=? WHERE id=?',(value,row['id']))
                f.tick();f.change.assert_not_called();self.assertEqual(f.value('mobile'),'1.1.1.1')

    def test_complete_fault_return_B_drain_change_and_wait_next_cycle(self):
        f=self.f;self.takeover();f.advance(2,online=('B',));f.offline_probe();f.tick()
        self.assertEqual(f.change.call_count,1);self.assertEqual(f.change.call_args.args[1],f.sid('A'))
        f.refresh('A',ip='8.8.4.4');f.tick();f.advance(2,online=('A','B'));f.tick()
        self.assertEqual(f.value('mobile'),'8.8.4.4')
        self.assertEqual(f.row()['drain_server_id'],f.sid('B'));self.assertEqual(f.row()['emergency'],0)
        deadline=f.row()['next_switch_at']
        f.advance(f.row()['drain_grace_s']+1,online=('A','B'));f.tick()
        self.assertEqual(f.change.call_count,1)
        f.advance(15,online=('A','B'));f.tick()
        self.assertEqual(f.change.call_count,2);self.assertEqual(f.change.call_args.args[1],f.sid('B'))
        f.refresh('B',ip='1.0.0.1');f.tick();f.advance(2,online=('A','B'));f.tick()
        self.assertEqual(f.row()['phase'],'active');self.assertEqual(f.row()['standby_ready_server'],f.sid('B'))
        self.assertEqual(f.value('mobile'),'8.8.4.4');self.assertEqual(f.row()['next_switch_at'],deadline)
        f.tick();self.assertEqual(f.change.call_count,2)
