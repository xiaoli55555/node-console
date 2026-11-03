"""Stage-by-stage fault injection with real API, SQLite and worker transitions.

DNS, the IP provider and probe transport are simulated; no live nodes are changed.
"""
import json
import unittest
from unittest.mock import patch

import test_rotation_emergency as fixture
import server


class RotationFaultMatrix(unittest.TestCase):
    def case(self):
        case=fixture.OriginalEmergencyProbe(methodName='runTest')
        case.setUp()
        f=case.f
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        return case,f

    def stage(self,f,stage):
        now=f.clock[0]
        if stage in ('active','ready'):
            if stage=='ready':
                with server.connect() as db:db.execute('UPDATE vps_rotations SET standby_ready_server=?,standby_ready_at=? WHERE id=?',(f.sid('B'),now-10,f.rid))
            return
        phase='waiting_ip' if stage in ('changing','preload_issued') else 'waiting_probe' if stage=='rechecking' else 'draining'
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET phase=?,drain_server_id=?,old_ip='1.1.1.1',drain_started=?,drain_grace_s=?,low_samples=0,action_started=?,new_ip=? WHERE id=?",
                       (phase,f.sid('B'),now,660 if stage=='ttl' else 0,now if phase in ('waiting_ip','waiting_probe') else None,'8.8.4.4' if phase=='waiting_probe' else None,f.rid))
            if stage in ('preload_unissued','preload_issued'):
                db.execute('UPDATE vps_rotations SET standby_ready_server=?,standby_ready_at=?,preload_base_attempt=action_attempts,preload_refresh_deadline=next_switch_at WHERE id=?',(f.sid('B'),now-10,f.rid))
            m=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('B'),)).fetchone()[0]);m['tcp']=999
            db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(m),f.sid('B')))
        if phase=='waiting_probe':f.refresh('B',ip='8.8.4.4')

    def fault(self,f,kind,node='A'):
        if kind=='tcp':f.health[f.sid(node)]=False;f.refresh(node)
        else:f.down(node);f.health[f.sid(node)]=False

    def confirm_retired_A(self,f,online=('B',)):
        # Confirmation must be newer than B's successful DNS takeover.
        f.tick()
        self.assertIsNotNone(f.row()['repair_check'])
        f.advance(2,online=online);f.offline_probe();f.tick()

    def test_both_fault_types_at_eight_stages_then_repair_return_and_resume(self):
        for stage in ('active','ttl','connections','changing','rechecking','ready','preload_unissued','preload_issued'):
            for kind in ('tcp','heartbeat'):
                with self.subTest(stage=stage,fault=kind):
                    case,f=self.case()
                    try:
                        self.stage(f,stage);deadline=f.row()['next_switch_at'];self.fault(f,kind)
                        f.tick()
                        self.assertEqual(f.value('mobile'),'8.8.8.8')
                        self.assertEqual(f.row()['next_switch_at'],deadline)
                        f.change.assert_not_called()
                        inflight=stage in ('changing','preload_issued','rechecking')
                        for step in range(6):
                            if f.row()['active_server_id']==f.sid('B'):break
                            f.advance(2,online=('B',) if kind=='heartbeat' else ('A','B'))
                            if kind=='heartbeat':f.offline_probe()
                            if stage in ('changing','preload_issued'):f.refresh('B',ip='8.8.4.4')
                            f.tick()
                        self.assertEqual(f.row()['active_server_id'],f.sid('B'))
                        self.assertEqual(f.value('mobile'),'8.8.4.4' if inflight else '1.1.1.1')
                        # Every alternating emergency handoff repairs A without
                        # waiting for TTL, a new sample, or a low connection count.
                        self.assertEqual(f.row()['drain_grace_s'],0)
                        self.assertEqual(f.row()['emergency'],1)
                        f.change.assert_not_called()
                        self.confirm_retired_A(f,online=('B',) if kind=='heartbeat' else ('A','B'))
                        self.assertTrue(all(c.args[1]==f.sid('A') for c in f.change.call_args_list))
                        self.assertEqual(f.change.call_count,1)
                        f.health[f.sid('A')]=True;f.refresh('A',ip='9.9.9.10');f.tick()
                        f.advance(2,online=('A','B'));f.tick()
                        self.assertEqual(f.row()['active_server_id'],f.sid('A'))
                        self.assertEqual(f.value('mobile'),'9.9.9.10')
                        self.assertEqual(f.row()['enabled'],1)
                        self.assertEqual(f.row()['next_switch_at'],f.clock[0]+f.row()['interval_s']-f.row()['lead_s'])
                        self.assertEqual(f.change.call_count,1)
                    finally:case.doCleanups()

    def test_three_normal_cycles_still_change_each_retired_carriers_ip(self):
        case,f=self.case()
        try:
            for i,new_ip in enumerate(('8.8.4.4','1.0.0.1','9.9.9.10')):
                old='A' if f.row()['active_server_id']==f.sid('A') else 'B'
                target='B' if old=='A' else 'A'
                f.advance(f.row()['next_switch_at']-f.clock[0],online=('A','B'));f.tick()
                self.assertEqual(f.row()['active_server_id'],f.sid(target))
                self.assertEqual(f.change.call_count,i)
                deadline=f.row()['next_switch_at']
                f.advance(f.row()['drain_grace_s']+1,online=('A','B'));f.tick()
                self.assertEqual(f.change.call_count,i)
                f.advance(15,online=('A','B'));f.tick()
                self.assertEqual(f.change.call_count,i+1);self.assertEqual(f.change.call_args.args[1],f.sid(old))
                f.refresh(old,ip=new_ip);f.tick();f.advance(2,online=('A','B'));f.tick()
                self.assertEqual(f.row()['phase'],'active')
                self.assertEqual(f.row()['active_server_id'],f.sid(target))
                self.assertEqual(f.row()['next_switch_at'],deadline)
                self.assertEqual(f.row()['standby_ready_server'],f.sid(old))
        finally:case.doCleanups()

    def test_heartbeat_handoff_repairs_old_carrier_despite_high_connections(self):
        case,f=self.case()
        try:
            with server.connect() as db:
                m=json.loads(db.execute('SELECT metrics FROM servers WHERE id=?',(f.sid('A'),)).fetchone()[0]);m['tcp']=50000
                db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps(m),f.sid('A')))
            self.fault(f,'heartbeat');f.tick();f.advance(2,online=('B',));f.offline_probe();f.tick();f.advance(2,online=('B',));f.tick()
            self.assertEqual(f.value('mobile'),'1.1.1.1')
            f.change.assert_not_called();self.confirm_retired_A(f)
            self.assertEqual(f.row()['drain_grace_s'],0);self.assertEqual(f.row()['emergency'],1)
            self.assertEqual(f.change.call_count,1);self.assertEqual(f.change.call_args.args[1],f.sid('A'))
            self.assertEqual(f.row()['phase'],'waiting_ip')
        finally:case.doCleanups()

    def test_confirmed_failure_uses_provider_despite_missing_agent_report(self):
        case,f=self.case()
        try:
            self.fault(f,'heartbeat');f.tick();f.advance(100,online=('B',));f.offline_probe();f.tick();f.advance(2,online=('B',));f.tick()
            self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()
            self.assertEqual(f.row()['drain_grace_s'],0);self.assertEqual(f.row()['emergency'],1)
            self.confirm_retired_A(f)
            self.assertEqual(f.change.call_count,1);self.assertEqual(f.row()['phase'],'waiting_ip')
        finally:case.doCleanups()

    def test_dns_failure_before_takeover_keeps_original_ip_and_no_ip_action(self):
        case,f=self.case()
        try:
            self.stage(f,'connections');self.fault(f,'tcp');f.tick();f.advance(2,online=('A','B'))
            with patch('rotation.update_dns_record',side_effect=OSError('DNS unavailable')):f.tick()
            self.assertEqual(f.value('mobile'),'8.8.8.8');f.change.assert_not_called()
            f.tick();self.assertEqual(f.value('mobile'),'1.1.1.1')
            f.change.assert_not_called();self.confirm_retired_A(f,online=('A','B'))
            self.assertEqual(f.change.call_count,1);self.assertEqual(f.change.call_args.args[1],f.sid('A'))
        finally:case.doCleanups()

    def test_new_original_carrier_ip_unreachable_stays_off_dns(self):
        case,f=self.case()
        try:
            self.stage(f,'connections');self.fault(f,'tcp');f.tick();f.advance(2,online=('A','B'));f.tick()
            self.assertEqual(f.value('mobile'),'1.1.1.1')
            f.refresh('A',ip='9.9.9.10');f.tick();f.advance(2,online=('A','B'));f.tick()
            self.assertEqual(f.value('mobile'),'1.1.1.1')
            self.assertNotEqual(f.row()['active_server_id'],f.sid('A'))
        finally:case.doCleanups()

    def test_temporary_carrier_faults_during_original_repair_and_recheck(self):
        for phase in ('changing','rechecking'):
            for kind in ('tcp','heartbeat'):
                with self.subTest(repair_phase=phase,fault=kind):
                    case,f=self.case()
                    try:
                        self.stage(f,'connections');self.fault(f,'tcp');f.tick();f.advance(2,online=('A','B'));f.tick()
                        self.assertEqual(f.value('mobile'),'1.1.1.1');f.change.assert_not_called()
                        self.confirm_retired_A(f,online=('A','B'))
                        self.assertEqual(f.row()['phase'],'waiting_ip')
                        f.health[f.sid('A')]=True
                        if phase=='rechecking':f.refresh('A',ip='9.9.9.10');f.tick()
                        self.fault(f,kind,'B');f.tick()
                        self.assertEqual(f.value('mobile'),'1.1.1.1')
                        for step in range(5):
                            if f.row()['active_server_id']==f.sid('A'):break
                            f.advance(2,online=('A',) if kind=='heartbeat' else ('A','B'))
                            f.refresh('A',ip='9.9.9.10');
                            if kind=='heartbeat':f.offline_probe('B')
                            f.tick()
                        self.assertEqual(f.value('mobile'),'9.9.9.10')
                        self.assertEqual(f.row()['active_server_id'],f.sid('A'))
                        self.assertEqual(f.row()['enabled'],1)
                    finally:case.doCleanups()
