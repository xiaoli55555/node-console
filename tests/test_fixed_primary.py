import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import rotation
from ip_dns import IntegrationError
from agent.agent import tcp_port_counts


class FixedPrimary(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'test.db'
        rotation.initialize(self.connect)
        with self.connect() as db:
            db.executescript('''CREATE TABLE servers(id INTEGER,seen INTEGER,name TEXT);
            INSERT INTO servers VALUES(1,1000,'A');INSERT INTO servers VALUES(2,1000,'B');
            CREATE TABLE dns_bindings(id INTEGER,connection_id INTEGER,expected_ip TEXT,port INTEGER,status TEXT,updated INTEGER);
            INSERT INTO dns_bindings VALUES(1,1,'8.8.8.8',443,'',0);
            INSERT INTO dns_bindings VALUES(2,1,'8.8.8.8',443,'untouched telecom',0);
            CREATE TABLE detection_runs(id INTEGER PRIMARY KEY,server_id INTEGER,created INTEGER,updated INTEGER,action_status TEXT,status TEXT DEFAULT 'complete');
            INSERT INTO detection_runs(id,server_id,created,updated,action_status) VALUES(1,1,1000,1000,'');INSERT INTO detection_runs(id,server_id,created,updated,action_status) VALUES(2,2,1000,1000,'');
            CREATE TABLE detection_plans(server_id INTEGER,next_at INTEGER);
            CREATE TABLE ip_monitors(server_id INTEGER,port INTEGER);
            INSERT INTO ip_monitors VALUES(1,443);INSERT INTO ip_monitors VALUES(2,443);''')
            db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,phase,next_switch_at,updated,interval_s,mode,takeover_s,mobile_only_ack) VALUES(1,1,2,1,1,1,'active',1000,900,7200,'fixed_primary',600,1)")
        self.ips={1:'8.8.8.8',2:'1.1.1.1'};self.count=80;self.now=1000;self.failed=set()
        self.record={'content':self.ips[1],'ttl':60}
        def fresh(db,sid,now,cipher):return self.ips[sid],443,{'connections_sampled':now,'tcp':self.count,'tcp_by_port':{'443':999}}
        self.patches=[patch('rotation._validated_plan',return_value={'action_connection_id':1}),patch('rotation._fresh_ip',side_effect=fresh),patch('rotation._failed_ip',side_effect=lambda db,sid,now:sid in self.failed),patch('rotation._fixed_failure',side_effect=lambda db,sid,now:sid in self.failed),patch('rotation._offline',return_value=False),patch('rotation.load_connection',return_value={'kind':'change_ip'}),patch('rotation.get_dns_record',side_effect=lambda *_:dict(self.record)),patch('rotation.validate_dns_record'),patch('rotation.update_dns_record',side_effect=lambda c,b,r,ip:self.record.update(content=ip)),patch('rotation.boce_dns_gate',side_effect=lambda db,sid,*args,**kwargs:'所选检测点不通' if sid in self.failed else None),patch('rotation.socket.create_connection',return_value=MagicMock()),patch('rotation.record_switch'),patch('rotation.invoke_change_ip_api',return_value='accepted')]
        self.mocks=[p.start() for p in self.patches];self.change=self.mocks[-1]
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()
    def connect(self):
        db=sqlite3.connect(self.path);db.row_factory=sqlite3.Row;return db
    def row(self):
        with self.connect() as db:return dict(db.execute('SELECT * FROM vps_rotations').fetchone())
    def switch(self,now):
        with self.connect() as db:db.execute('UPDATE detection_runs SET updated=?,created=?',(now,now))
        rotation._dns_switch(self.connect,None,1,now)
    def test_takeover_return_drain_refresh_and_rejoin(self):
        self.switch(1000)
        r=self.row();self.assertEqual(r['active_server_id'],2);self.assertEqual(r['phase'],'active');self.assertIsNone(r['drain_server_id']);self.assertEqual(r['next_switch_at'],1600)
        self.change.assert_not_called()
        self.switch(1600)
        r=self.row();self.assertEqual(r['active_server_id'],1);self.assertEqual(r['drain_server_id'],2);self.assertEqual(r['phase'],'draining');self.assertEqual(r['next_switch_at'],8200)
        rotation._run_rotation(self.connect,None,1,1700);self.change.assert_not_called() # TTL grace
        rotation._run_rotation(self.connect,None,1,1721);self.assertEqual(self.row()['low_samples'],0) # 80 not <80
        self.count=79
        rotation._run_rotation(self.connect,None,1,1736);self.change.assert_not_called()
        rotation._run_rotation(self.connect,None,1,1736);self.change.assert_not_called() # same sample not reused
        with self.connect() as db:db.execute('UPDATE detection_runs SET updated=1750,created=1750')
        rotation._run_rotation(self.connect,None,1,1751);self.change.assert_called_once();self.assertEqual(self.change.call_args.args[1],2)
        self.ips[2]='9.9.9.9'
        rotation._run_rotation(self.connect,None,1,1760)
        rotation._run_rotation(self.connect,None,1,1770)
        self.assertEqual(self.row()['phase'],'active');self.assertEqual(self.row()['next_switch_at'],8200)
        self.assertEqual(self.record['content'],'8.8.8.8');self.assertEqual(self.ips[1],'8.8.8.8')
        with self.connect() as db:self.assertEqual(db.execute('SELECT status FROM dns_bindings WHERE id=2').fetchone()[0],'untouched telecom')
    def test_failed_primary_does_not_force_scheduled_return(self):
        self.switch(1000)
        with patch('rotation.boce_dns_gate',return_value='unreachable'):
            with self.assertRaises(IntegrationError):self.switch(1600)
        self.assertEqual(self.row()['active_server_id'],2);self.assertEqual(self.record['content'],'1.1.1.1');self.change.assert_not_called()
    def test_failed_rotation_vps_still_waits_for_threshold(self):
        self.switch(1000);self.switch(1600);self.failed={2};self.count=100
        rotation._run_rotation(self.connect,None,1,1751)
        self.assertEqual(self.row()['low_samples'],0);self.change.assert_not_called()
    def test_missing_or_stale_TCP_sample_never_treated_as_zero(self):
        self.switch(1000);self.switch(1600)
        with patch('rotation._fresh_ip',return_value=('1.1.1.1',443,{'connections_sampled':1750})):
            rotation._run_rotation(self.connect,None,1,1751)
        self.change.assert_not_called();self.assertIn('TCP',self.row()['status'])
        for stamp in (1,2000):
            with self.assertRaises(IntegrationError):rotation._rotation_tcp_count({'connections_sampled':stamp,'tcp':0},1751)
    def test_primary_refresh_only_after_confirmed_failure(self):
        self.failed={1}
        rotation._run_rotation(self.connect,None,1,1000)
        self.assertEqual(self.row()['active_server_id'],2)
        self.change.assert_called_once();self.assertEqual(self.change.call_args.args[1],1)
    def test_offline_primary_does_not_refresh_ip(self):
        with patch('rotation._offline',side_effect=lambda db,sid,now,*args:sid==1):
            rotation._run_rotation(self.connect,None,1,1000)
            rotation._run_rotation(self.connect,None,1,1010)
        self.assertEqual(self.row()['active_server_id'],2)
        self.change.assert_not_called()
    def test_api_retry_rechecks_connection_threshold(self):
        self.switch(1000);self.switch(1600)
        with self.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',action_started=1600,old_ip='1.1.1.1'")
        self.count=100
        with self.connect() as db:db.execute('UPDATE detection_runs SET updated=1750,created=1750')
        rotation._run_rotation(self.connect,None,1,1751)
        self.assertEqual(self.row()['phase'],'draining');self.assertEqual(self.row()['low_samples'],0)
        rotation._run_rotation(self.connect,None,1,1766);self.change.assert_not_called()
    def refresh(self,now):
        with self.connect() as db:db.execute('UPDATE detection_runs SET updated=?,created=?',(now,now))
    def test_A_failure_reclaims_B_before_B_action_is_submitted(self):
        self.switch(1000);self.switch(1600);self.failed={1};self.count=200
        self.refresh(1650)
        rotation._run_rotation(self.connect,None,1,1650)
        self.assertEqual(self.row()['active_server_id'],2)
        self.assertEqual(self.row()['drain_server_id'],1)
        self.change.assert_called_once();self.assertEqual(self.change.call_args.args[1],1)
    def test_B_failure_cuts_back_without_waiting_for_takeover_deadline(self):
        self.switch(1000);self.failed={2};self.refresh(1100)
        rotation._run_rotation(self.connect,None,1,1100)
        self.assertEqual(self.row()['active_server_id'],1)
        self.assertEqual(self.row()['drain_server_id'],2);self.change.assert_not_called()
    def test_A_failure_during_B_action_finishes_B_before_repairing_A(self):
        self.switch(1000);self.switch(1600)
        with self.connect() as db:db.execute("UPDATE vps_rotations SET phase='waiting_ip',old_ip='1.1.1.1',action_started=1600")
        self.failed={1};self.ips[2]='9.9.9.9';self.refresh(1700)
        rotation._run_rotation(self.connect,None,1,1700)
        self.assertEqual(self.row()['phase'],'waiting_probe');self.change.assert_not_called()
        self.refresh(1710);rotation._run_rotation(self.connect,None,1,1710)
        self.assertEqual(self.row()['phase'],'active');self.change.assert_not_called()
        self.refresh(1711);rotation._run_rotation(self.connect,None,1,1711)
        self.assertEqual(self.record['content'],'9.9.9.9')
        self.change.assert_called_once();self.assertEqual(self.change.call_args.args[1],1)
    def test_no_B_repair_if_A_becomes_unknown_or_stale(self):
        self.switch(1000);self.switch(1600);self.count=0
        rotation._run_rotation(self.connect,None,1,1730)
        rotation._run_rotation(self.connect,None,1,1745)
        self.change.assert_not_called();self.assertIn('暂缓',self.row()['status'])
    def test_both_failed_keeps_threshold_and_repairs_only_one_machine(self):
        self.failed={1,2};self.count=200
        rotation._run_rotation(self.connect,None,1,1000)
        rotation._run_rotation(self.connect,None,1,1010);self.change.assert_not_called()
        self.count=0;self.refresh(1025)
        rotation._run_rotation(self.connect,None,1,1025)
        self.refresh(1040);rotation._run_rotation(self.connect,None,1,1040)
        self.change.assert_called_once();self.assertEqual(self.change.call_args.args[1],2)
    def test_pending_reboot_on_target_blocks_switch_even_if_TCP_works(self):
        with self.connect() as db:
            db.execute('CREATE TABLE commands(server_id INTEGER,action TEXT,status TEXT)')
            db.execute("INSERT INTO commands VALUES(2,'reboot','accepted')")
        rotation._run_rotation(self.connect,None,1,1000)
        self.assertEqual(self.row()['active_server_id'],1);self.change.assert_not_called()
        self.assertIn('未结束',self.row()['status'])
    def test_DNS_write_timeout_after_provider_applied_is_reconciled(self):
        def applied_then_timeout(c,b,r,ip):
            self.record['content']=ip
            raise IntegrationError('provider timeout')
        with patch('rotation.update_dns_record',side_effect=applied_then_timeout) as update:
            with self.assertRaises(IntegrationError):self.switch(1000)
            self.assertEqual(self.row()['active_server_id'],1)
            self.assertIsNotNone(self.row()['dns_intent'])
            rotation._run_rotation(self.connect,None,1,1001)
            self.assertEqual(self.row()['active_server_id'],2)
            self.assertIsNone(self.row()['dns_intent']);update.assert_called_once()
        self.change.assert_not_called()
    def test_DNS_unknown_result_freezes_actions_until_actual_value_matches(self):
        with patch('rotation.update_dns_record',side_effect=IntegrationError('timeout')):
            with self.assertRaises(IntegrationError):self.switch(1000)
        self.failed={1}
        rotation._run_rotation(self.connect,None,1,1001)
        self.assertEqual(self.row()['active_server_id'],1)
        self.assertIsNotNone(self.row()['dns_intent']);self.change.assert_not_called()
        self.record['content']='9.9.9.9'
        rotation._run_rotation(self.connect,None,1,1002)
        self.assertIn('外部',self.row()['status']);self.change.assert_not_called()
    def test_existing_TCP_total_is_used_without_business_port_map(self):
        self.assertEqual(rotation._rotation_tcp_count({'tcp':79,'connections_sampled':1000},1000),(79,1000))
        self.assertEqual(rotation._rotation_tcp_count({'tcp':100,'tcp_by_port':{'443':0},'connections_sampled':1000},1000),(100,1000))
        for invalid in (None,True,-1,1.5,'0'):
            with self.subTest(value=invalid):
                with self.assertRaises(IntegrationError):rotation._rotation_tcp_count({'tcp':invalid,'connections_sampled':1000},1000)
    def test_migration_keeps_old_mode_and_is_repeatable(self):
        rotation.initialize(self.connect)
        with self.connect() as db:
            db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,next_switch_at,updated) VALUES(2,3,4,3,3,1000,900)")
            self.assertEqual(db.execute('SELECT mode FROM vps_rotations WHERE owner_id=2').fetchone()[0],'alternating')
    def test_port_collector_excludes_ssh_and_outbound_ports(self):
        root=Path(self.tmp.name);(root/'net').mkdir()
        (root/'net/tcp').write_text('header\n0: 00000000:01BB 00000000:FFFF 01\n1: 00000000:0016 00000000:FFFF 01\n2: 00000000:EEEE 00000000:01BB 01\n3: 00000000:01BB 00000000:FFFF 0A\n')
        self.assertEqual(tcp_port_counts(root),{'443':1,'22':1,str(0xEEEE):1})
        self.assertIsNone(tcp_port_counts(root/'missing'))


class SelectedNodeFailure(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row
        self.db.executescript('''CREATE TABLE detection_plans(server_id INTEGER,source_id INTEGER,nodes TEXT,failure_threshold INTEGER,interval_s INTEGER,automatic INTEGER);
        CREATE TABLE ip_monitors(server_id INTEGER,port INTEGER,enabled INTEGER);
        CREATE TABLE detection_sources(id INTEGER,enabled INTEGER);
        INSERT INTO detection_sources VALUES(7,1);
        CREATE TABLE detection_runs(id INTEGER PRIMARY KEY,server_id INTEGER,source_id INTEGER,nodes TEXT,ip TEXT,port INTEGER,updated INTEGER,details TEXT);
        INSERT INTO detection_plans VALUES(1,7,'["13","42"]',3,120,1);
        INSERT INTO ip_monitors VALUES(1,443,1);''')
        self.rows=[{'node_id':'13','state':'unreachable'},{'node_id':'42','state':'unreachable'}]
        self.guard=patch('rotation._failed_ip',return_value=True);self.guard.start()
    def tearDown(self):self.guard.stop();self.db.close()
    def add(self,rows=None,ip='8.8.8.8',source=7,port=443,updated=1000):
        self.db.execute('INSERT INTO detection_runs(server_id,source_id,nodes,ip,port,updated,details) VALUES(1,?,?,?,?,?,?)',(source,'["13","42"]',ip,port,updated,json.dumps(self.rows if rows is None else rows)))
    def test_only_selected_nodes_and_configured_failure_threshold_are_required(self):
        self.add();self.add()
        self.assertFalse(rotation._fixed_failure(self.db,1,1000))
        self.add();self.assertTrue(rotation._fixed_failure(self.db,1,1000))
    def test_unknown_partial_missing_and_success_break_failure_confirmation(self):
        for rows in ([{'node_id':'13','state':'unknown'},{'node_id':'42','state':'unreachable'}],self.rows[:1],[{'node_id':'13','state':'reachable'},{'node_id':'42','state':'unreachable'}],[]):
            with self.subTest(rows=rows):
                self.db.execute('DELETE FROM detection_runs');self.add();self.add(rows);self.add()
                self.assertFalse(rotation._fixed_failure(self.db,1,1000))
    def test_old_IP_source_port_or_stale_results_do_not_count(self):
        for kwargs in ({'ip':'1.1.1.1'},{'source':8},{'port':8443},{'updated':1}):
            with self.subTest(kwargs=kwargs):
                self.db.execute('DELETE FROM detection_runs');self.add();self.add(**kwargs);self.add()
                self.assertFalse(rotation._fixed_failure(self.db,1,1000))

    def test_paused_source_monitor_or_plan_does_not_trigger_an_action(self):
        self.add();self.add();self.add()
        for table,column in [('detection_sources','enabled'),('ip_monitors','enabled'),('detection_plans','automatic')]:
            self.db.execute(f'UPDATE {table} SET {column}=0')
            self.assertFalse(rotation._fixed_failure(self.db,1,1000))
            self.db.execute(f'UPDATE {table} SET {column}=1')
