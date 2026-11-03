"""C is a last resort for alternating A/B, including mixed fault types."""
import json
import unittest
from unittest.mock import patch

import test_rotation_emergency as fixture
import server
import failover
from ip_dns import IntegrationError


class LastResort(unittest.TestCase):
    def setUp(self):
        fixture.OriginalEmergencyProbe.setUp(self)
        f=self.f
        f.mocks[0].side_effect=lambda db,cipher,cid:{'kind':db.execute('SELECT kind FROM ip_connections WHERE id=?',(cid,)).fetchone()[0]}
        self.assertEqual(f.save(failover_server_id=f.sid('C'),failover_binding_ids=list(f.bindings.values())).status_code,200)

    def fault(self,name,kind):
        f=self.f
        if kind=='offline':f.down(name)
        else:
            f.health[f.sid(name)]=False
            f.refresh(name);f.refresh(name)

    def leases(self):
        with server.connect() as db:return db.execute('SELECT COUNT(*) FROM vps_failover_leases WHERE rotation_id=?',(self.f.rid,)).fetchone()[0]

    def test_either_normal_machine_prevents_C(self):
        for bad in ('A','B'):
            for kind in ('offline','tcp'):
                with self.subTest(bad=bad,kind=kind):
                    c=LastResort(methodName='runTest');c.setUp();f=c.f
                    try:
                        c.fault(bad,kind);f.tick()
                        f.advance(2,online=tuple(x for x in ('A','B','C') if not (x==bad and kind=='offline')));f.tick()
                        self.assertEqual(c.leases(),0)
                        self.assertNotEqual(f.value('mobile'),'9.9.9.9')
                    finally:c.doCleanups()

    def test_all_four_confirmed_double_failure_combinations_activate_C(self):
        for a in ('offline','tcp'):
            for b in ('offline','tcp'):
                with self.subTest(A=a,B=b):
                    c=LastResort(methodName='runTest');c.setUp();f=c.f
                    try:
                        c.fault('A',a);c.fault('B',b);f.tick()
                        self.assertEqual(f.value('mobile'),'9.9.9.9')
                        self.assertEqual(c.leases(),3);f.change.assert_not_called()
                    finally:c.doCleanups()

    def test_one_failure_round_or_unknown_B_is_not_a_second_confirmed_fault(self):
        f=self.f;self.fault('A','offline');f.health[f.sid('B')]=False;f.refresh('B')
        f.tick();self.assertEqual(self.leases(),0)
        with server.connect() as db:
            db.execute("UPDATE detection_runs SET details=? WHERE id=(SELECT MAX(id) FROM detection_runs WHERE server_id=?)",(json.dumps([{'node_id':'13','state':'unknown'}]),f.sid('B')))
        f.tick();self.assertEqual(self.leases(),0)

    def test_pausing_a_healthy_plan_does_not_activate_C(self):
        self.assertEqual(self.f.save(enabled=False).status_code,200)
        self.f.tick();self.assertEqual(self.leases(),0)

    def test_B_can_recover_first_and_release_C_after_existing_stability_window(self):
        f=self.f;self.fault('A','offline');self.fault('B','offline');f.tick()
        self.assertEqual(f.value('mobile'),'9.9.9.9')
        f.advance(2,online=('B','C'));f.tick()
        f.advance(30,online=('B','C'));f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1');self.assertEqual(self.leases(),0)
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))

    def test_recovery_is_rechecked_before_each_C_dns_write(self):
        f=self.f;self.fault('A','offline');self.fault('B','offline');f.tick()
        # Release existing leases to exercise the guarded writer directly.
        with server.connect() as db:db.execute('DELETE FROM vps_failover_leases WHERE rotation_id=?',(f.rid,))
        f.refresh('B')
        with self.assertRaisesRegex(IntegrationError,'取消启用 C'):
            failover._move(server.connect,server.CIPHER,f.rid,f.bindings['mobile'],'9.9.9.9',f.clock[0])

    def test_B_restore_timeout_is_reconciled_with_correct_server_identity(self):
        f=self.f;self.fault('A','offline');self.fault('B','offline');f.tick()
        f.advance(2,online=('B','C'));f.tick();f.advance(30,online=('B','C'))
        def apply_then_timeout(c,b,r,ip):
            f.records[b['id']]['Value']=ip
            raise IntegrationError('timeout after apply')
        with patch('failover.update_dns_record',side_effect=apply_then_timeout):f.tick()
        f.tick();f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1');self.assertEqual(self.leases(),0)
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))

    def test_regular_rotation_never_selects_C_as_a_partner(self):
        f=self.f
        with server.connect() as db:db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(f.clock[0],f.rid))
        f.tick()
        self.assertEqual(f.value('mobile'),'1.1.1.1');self.assertEqual(self.leases(),0)
        self.assertEqual(f.row()['active_server_id'],f.sid('B'))
        self.assertEqual({f.row()['primary_server_id'],f.row()['other_server_id']},{f.sid('A'),f.sid('B')})

    def test_C_takeover_does_not_run_A_B_schedule_or_assign_rotation_actions_to_C(self):
        f=self.f;self.fault('A','offline');self.fault('B','offline');f.tick()
        f.advance(f.row()['interval_s']+60,online=('C',));f.tick()
        self.assertEqual(f.value('mobile'),'9.9.9.9')
        self.assertIn(f.row()['active_server_id'],(f.sid('A'),f.sid('B')))
        self.assertNotIn(f.sid('C'),(f.row()['primary_server_id'],f.row()['other_server_id']))
        f.change.assert_not_called()
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM commands WHERE server_id=? AND action IN ('reboot','hkt_dhcp')",(f.sid('C'),)).fetchone()[0],0)

    def test_recovery_during_provider_read_cancels_C_without_leaving_a_lease(self):
        f=self.f;self.fault('A','offline');self.fault('B','offline')
        def read_and_recover(connection,binding):
            f.refresh('B')
            return dict(f.records[binding['id']])
        with patch('failover.get_dns_record',side_effect=read_and_recover):
            with self.assertRaisesRegex(IntegrationError,'DNS 核对期间已恢复'):
                failover._move(server.connect,server.CIPHER,f.rid,f.bindings['mobile'],'9.9.9.9',f.clock[0])
        self.assertEqual(self.leases(),0);self.assertEqual(f.value('mobile'),'8.8.8.8')

    def test_switching_recovery_target_restarts_the_stability_window(self):
        f=self.f;self.fault('A','offline');self.fault('B','offline');f.tick()
        f.advance(2,online=('B','C'));f.tick()
        with server.connect() as db:first=db.execute('SELECT failover_healthy_since FROM vps_rotations WHERE id=?',(f.rid,)).fetchone()[0]
        f.advance(20,online=('A','B','C'));f.tick()
        with server.connect() as db:
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(f.rid,)).fetchone()
            self.assertEqual(r['failover_recovery_server'],f.sid('A'))
            self.assertGreater(r['failover_healthy_since'],first)
        f.advance(15,online=('A','B','C'));f.tick()
        self.assertEqual(f.value('mobile'),'9.9.9.9')
        f.advance(15,online=('A','B','C'));f.tick()
        self.assertEqual(f.value('mobile'),'8.8.8.8');self.assertEqual(self.leases(),0)
