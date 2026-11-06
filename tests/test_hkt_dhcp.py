import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import test_panel as support
import server
import hkt_dhcp
from ip_dns import invoke_change_ip_api, IntegrationError, load_connection
from agent import agent

class HKTAPI(unittest.TestCase):
    setUp=support.PanelTest.setUp
    post=support.PanelTest.post
    def node(self,name='HKT',capabilities=None):
        node=self.post('/api/servers',{'name':name}).json
        self.report(node,capabilities=['reboot','hkt_dhcp'] if capabilities is None else capabilities)
        return node
    def report(self,node,**extra):
        return self.admin.post('/api/agent/report',json=dict({'capabilities':['reboot','hkt_dhcp'],'public_ips':['8.8.8.8'],'uptime':1000},**extra),headers={'Authorization':'Bearer '+node['token']})
    def generate(self,node):return self.post(f'/api/admin/servers/{node["id"]}/hkt-dhcp/api').json
    def trigger(self,node,cfg):return self.admin.post(f'/api/hkt-dhcp/{node["id"]}',json={},headers={'Authorization':'Bearer '+cfg['token']})
    def test_scoped_API_queue_delivery_ack_result_and_duplicate_request(self):
        n=self.node();cfg=self.generate(n)
        first=self.trigger(n,cfg);self.assertEqual(first.status_code,202,first.json)
        cid=first.json['command_id'];self.assertEqual(self.trigger(n,cfg).json['command_id'],cid)
        cmd=self.report(n).json['command'];self.assertEqual(cmd,{'id':cid,'action':'hkt_dhcp'})
        self.assertIsNone(self.report(n).json['command'])
        ack=self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers={'Authorization':'Bearer '+n['token']})
        self.assertEqual(ack.status_code,200)
        other=self.node('other');self.report(other,dhcp_result={'id':cid,'state':'changed'})
        with server.connect() as db:self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(cid,)).fetchone()[0],'accepted')
        self.report(n,dhcp_result={'id':cid,'state':'changed','old_ip':'8.8.8.8','new_ip':'1.1.1.1','attempts':1},public_ips=['1.1.1.1'])
        with server.connect() as db:self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(cid,)).fetchone()[0],'completed')
    def test_admin_can_generate_for_customer_assigned_server_without_exposing_key(self):
        n=self.node();alice_id=self.alice.get('/api/me').json['id']
        assigned=self.admin.patch(f'/api/servers/{n["id"]}',json={'owner_id':alice_id},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(assigned.status_code,200,assigned.json)
        response=self.post(f'/api/admin/servers/{n["id"]}/hkt-dhcp/api')
        self.assertEqual(response.status_code,200,response.json)
        cfg=response.json
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT owner_id FROM servers WHERE id=?',(n['id'],)).fetchone()[0],alice_id)
            conn=db.execute('SELECT * FROM ip_connections WHERE id=?',(cfg['connection_id'],)).fetchone()
            self.assertIsNone(conn['owner_id']);self.assertEqual(conn['server_id'],n['id'])
            self.assertNotEqual(conn['secret'],cfg['token'])
            self.assertFalse(db.execute('SELECT 1 FROM commands WHERE server_id=?',(n['id'],)).fetchone())
        visible=self.alice.get(f'/api/client/servers/{n["id"]}/dns-bindings').json
        self.assertFalse(any(c['id']==cfg['connection_id'] for c in visible['connections']))
        self.assertNotIn(cfg['token'],json.dumps(visible))
        self.assertEqual(self.alice.post(f'/api/admin/servers/{n["id"]}/hkt-dhcp/api',json={},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,403)
        queued=self.trigger(n,cfg);self.assertEqual(queued.status_code,202,queued.json)
        command=self.report(n).json['command'];self.assertEqual(command['action'],'hkt_dhcp')
        ack=self.admin.post(f'/api/agent/commands/{command["id"]}/ack',json={},headers={'Authorization':'Bearer '+n['token']})
        self.assertEqual(ack.status_code,200,ack.json)

    def test_unchanged_result_stops_further_automatic_jobs_until_reset(self):
        n=self.node();cfg=self.generate(n);cid=self.trigger(n,cfg).json['command_id'];self.report(n)
        self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers={'Authorization':'Bearer '+n['token']})
        self.report(n,dhcp_result={'id':cid,'state':'unchanged','attempts':3})
        self.assertEqual(self.trigger(n,cfg).status_code,409)
        new=self.generate(n);self.assertEqual(self.trigger(n,cfg).status_code,401)
        self.assertEqual(self.trigger(n,new).status_code,202)
    def test_key_cannot_target_other_VPS_or_bypass_active_rotation(self):
        n=self.node();other=self.node('B');cfg=self.generate(n);cfg2=self.generate(other)
        self.report(n,public_ips=['42.98.100.156'])
        self.report(other,public_ips=['42.98.100.157'])
        self.assertEqual(self.trigger(other,cfg).status_code,401)
        with server.connect() as db:
            conn=load_connection(db,server.CIPHER,cfg['connection_id'])
            with self.assertRaises(IntegrationError):invoke_change_ip_api(conn,other['id'],'B','1.1.1.1')
            dns=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('dns','alidns','{}','test')").lastrowid
            binding=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port) VALUES(?,?,'example.com','r','edge','default','8.8.8.8',443)",(n['id'],dns)).lastrowid
            uid=self.admin.get('/api/me').json['id']
            db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,mode,phase,next_switch_at,updated) VALUES(?,?,?,?,?,1,'fixed_primary','active',?,?)",(uid,n['id'],other['id'],binding,n['id'],int(time.time())+600,int(time.time())))
        self.assertEqual(self.trigger(n,cfg).status_code,409)
        with self.assertRaises(IntegrationError):invoke_change_ip_api(conn,n['id'],'A','8.8.8.8')
        # A is protected even if a stale row says that it is ready to drain.
        with server.connect() as db:db.execute("UPDATE vps_rotations SET active_server_id=?,drain_server_id=?,phase='waiting_ip',low_samples=2 WHERE primary_server_id=?",(other['id'],n['id'],n['id']))
        with patch('rotation._fixed_failure',return_value=False):
            with self.assertRaises(IntegrationError):invoke_change_ip_api(conn,n['id'],'A','8.8.8.8')
        # The healthy A remains serving while B can perform its normal DHCP action.
        with server.connect() as db:
            db.execute("UPDATE vps_rotations SET active_server_id=?,drain_server_id=?,phase='waiting_ip',low_samples=2 WHERE primary_server_id=?",(n['id'],other['id'],n['id']))
            bconn=load_connection(db,server.CIPHER,cfg2['connection_id'])
        with self.assertRaisesRegex(IntegrationError,'采样缺失或过期'):
            invoke_change_ip_api(bconn,other['id'],'B','8.8.8.8')
        self.report(other,public_ips=['42.98.100.157'],tcp=25,connections_sampled=int(time.time()))
        self.assertIn('已排队',invoke_change_ip_api(bconn,other['id'],'B','8.8.8.8'))

    def test_requires_local_capability_admin_and_no_concurrent_reboot(self):
        n=self.node(capabilities=['reboot'])
        self.assertEqual(self.post(f'/api/admin/servers/{n["id"]}/hkt-dhcp/api').status_code,409)
        self.report(n);cfg=self.generate(n);self.trigger(n,cfg)
        self.assertEqual(self.post(f'/api/servers/{n["id"]}/reboot',{'confirm':True}).status_code,409)
        self.assertEqual(self.alice.post(f'/api/admin/servers/{n["id"]}/hkt-dhcp/api',json={},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,403)
    def test_reboot_uptime_does_not_complete_DHCP_job(self):
        n=self.node();cfg=self.generate(n);cid=self.trigger(n,cfg).json['command_id'];self.report(n)
        self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers={'Authorization':'Bearer '+n['token']})
        self.report(n,uptime=1)
        with server.connect() as db:self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(cid,)).fetchone()[0],'accepted')

    def test_admin_single_test_preserves_key_and_verifies_real_report(self):
        n=self.node();cfg=self.generate(n);path=f'/api/admin/servers/{n["id"]}/hkt-dhcp/test'
        with server.connect() as db:before=tuple(db.execute('SELECT * FROM hkt_dhcp_apis WHERE server_id=?',(n['id'],)).fetchone())
        self.assertEqual(self.post(path).status_code,400)
        response=self.post(path,{'confirm':True});self.assertEqual(response.status_code,202,response.json)
        cid=response.json['command_id']
        self.assertEqual(self.post(path,{'confirm':True}).json['command_id'],cid)
        status=self.admin.get(f'/api/admin/servers/{n["id"]}/hkt-dhcp/status').json
        self.assertFalse(status['verified_ip_change']);self.assertEqual(status['current_ip'],'8.8.8.8')
        self.report(n)
        self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers={'Authorization':'Bearer '+n['token']})
        self.report(n,dhcp_result={'id':cid,'state':'changed','old_ip':'8.8.8.8','new_ip':'1.1.1.1','attempts':1},public_ips=['1.1.1.1'])
        status=self.admin.get(f'/api/admin/servers/{n["id"]}/hkt-dhcp/status').json
        self.assertTrue(status['verified_ip_change']);self.assertEqual(status['current_ip'],'1.1.1.1')
        self.assertNotIn(cfg['token'],json.dumps(status));self.assertNotIn(cfg['token'],json.dumps(response.json))
        with server.connect() as db:self.assertEqual(tuple(db.execute('SELECT * FROM hkt_dhcp_apis WHERE server_id=?',(n['id'],)).fetchone()),before)

    def test_admin_single_test_requires_admin_CSRF_and_honors_standby_guard(self):
        n=self.node();cfg=self.generate(n);path=f'/api/admin/servers/{n["id"]}/hkt-dhcp/test'
        self.assertEqual(self.alice.post(path,json={'confirm':True},headers={'X-CSRF-Token':self.tokens['alice']}).status_code,403)
        self.assertEqual(self.admin.post(path,json={'confirm':True}).status_code,403)
        a=self.node('A');b=self.node('B')
        with server.connect() as db:
            dns=db.execute("INSERT INTO ip_connections(name,kind,config,secret) VALUES('dns','alidns','{}','test')").lastrowid
            bid=db.execute("INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port) VALUES(?,?,'example.com','manual-test','edge','mobile','8.8.8.8',443)",(a['id'],dns)).lastrowid
            uid=db.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()[0]
            rid=db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,next_switch_at,updated,failover_server_id) VALUES(?,?,?,?,?,?,?,?)",(uid,a['id'],b['id'],bid,a['id'],int(time.time())+600,int(time.time()),n['id'])).lastrowid
        blocked=self.post(path,{'confirm':True});self.assertEqual(blocked.status_code,409,blocked.json)
        self.assertIn('冷备用',blocked.json['error'])
        with server.connect() as db:
            self.assertFalse(db.execute('SELECT 1 FROM commands WHERE server_id=?',(n['id'],)).fetchone())
            db.execute('DELETE FROM vps_rotations WHERE id=?',(rid,))

    def test_status_does_not_trust_changed_label_when_IPs_do_not_match(self):
        n=self.node();cfg=self.generate(n);cid=self.trigger(n,cfg).json['command_id'];self.report(n)
        self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers={'Authorization':'Bearer '+n['token']})
        for old,new in [('8.8.8.8','8.8.8.8'),('8.8.8.8','1.1.1.1')]:
            with server.connect() as db:db.execute("UPDATE commands SET status='accepted' WHERE id=?",(cid,))
            self.report(n,dhcp_result={'id':cid,'state':'changed','old_ip':old,'new_ip':new,'attempts':1})
            status=self.admin.get(f'/api/admin/servers/{n["id"]}/hkt-dhcp/status').json
            self.assertFalse(status['verified_ip_change'])

class DHCPExecutor(unittest.TestCase):
    def test_process_selection_never_kills_IPv6_other_interfaces_or_other_programs(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            rows={1:['/sbin/dhclient','-4','-v','ens18'],2:['dhclient','-v'],3:['dhclient','-6','ens18'],4:['dhclient','-4','eth1'],5:['echo','dhclient','ens18']}
            for pid,args in rows.items():
                path=root/str(pid);path.mkdir();(path/'cmdline').write_bytes(b'\0'.join(x.encode() for x in args)+b'\0')
            self.assertEqual([p for p,_ in agent.dhcp_clients('ens18',False,root)],[1])
            self.assertEqual({p for p,_ in agent.dhcp_clients('ens18',True,root)},{1,2})
    def run_task(self,addresses):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        state=Path(folder.name);lease=state/'ens18.leases';lease.write_text('old lease')
        patches=[patch.object(agent,'DHCP_STATE',state),patch.object(agent,'dhcp_config',return_value={'enabled':True,'interface':'ens18','cleanup_unscoped':True}),patch.object(agent,'dhcp_address',side_effect=addresses if isinstance(addresses,list) else None,return_value=addresses if isinstance(addresses,str) else None),patch.object(agent,'dhcp_clients',return_value=[]),patch.object(agent,'dhcp_lease_path',return_value=lease),patch.object(agent,'dhcp_run',return_value=True),patch.object(agent.time,'sleep'),patch.object(agent.shutil,'which',return_value='/sbin/dhclient'),patch.object(agent,'dhcp_background'),patch.object(agent,'dhcp_stable',return_value=True),patch.object(agent.subprocess,'run')]
        mocks=[p.start() for p in patches]
        for p in patches:self.addCleanup(p.stop)
        return state,mocks[5]
    def test_changed_IP_stops_and_same_command_is_never_executed_twice(self):
        state,run=self.run_task(['8.8.8.8','42.98.100.156','42.98.100.156'])
        agent.dhcp_task(10);result=json.loads((state/'dhcp-result.json').read_text())
        self.assertEqual(result['state'],'changed');self.assertEqual(result['attempts'],1)
        count=run.call_count;agent.dhcp_task(10);self.assertEqual(run.call_count,count)
        self.assertEqual((state/'dhcp-lease.backup').read_text(),'old lease')
    def test_nonpreferred_addresses_retry_past_three_until_42(self):
        addresses=['8.8.8.8']+['1.36.96.112']*8+['42.98.100.156']*2
        state,run=self.run_task(addresses)
        agent.dhcp_task(55)
        result=json.loads((state/'dhcp-result.json').read_text())
        self.assertEqual(result['state'],'changed')
        self.assertEqual(result['attempts'],5)
        self.assertEqual(result['new_ip'],'42.98.100.156')
    def test_rotation_gate_applies_only_to_registered_hkt(self):
        import sqlite3
        from rotation import _preferred_rotation_ip
        db=sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE hkt_dhcp_apis(server_id INTEGER)')
        db.execute('INSERT INTO hkt_dhcp_apis VALUES(1)')
        _preferred_rotation_ip(db,1,'42.98.100.156')
        _preferred_rotation_ip(db,2,'1.36.96.112')
        with self.assertRaises(IntegrationError):_preferred_rotation_ip(db,1,'1.36.96.112')

    def test_same_ip_retries_until_preferred_new_address(self):
        state,run=self.run_task(['8.8.8.8']+['8.8.8.8']*6+['42.98.100.156']*2)
        agent.dhcp_task(11)
        result=json.loads((state/'dhcp-result.json').read_text())
        self.assertEqual(result['state'],'changed');self.assertEqual(result['attempts'],4)
        self.assertFalse(any('-6' in c.args[0] for c in run.call_args_list))
    def test_watchdog_is_scheduled_before_network_task_and_existing_client_is_not_duplicated(self):
        with patch.object(agent,'dhcp_config',return_value={'enabled':True,'interface':'ens18'}),patch.object(agent.subprocess,'run') as run:
            agent.dispatch_dhcp(12)
            self.assertIn('--on-active=300s',run.call_args_list[0].args[0])
            self.assertFalse(any('RuntimeMaxSec' in x for x in run.call_args_list[1].args[0]))
            self.assertEqual(run.call_args_list[1].args[0][-2:],['--dhcp-task','12'])
        with patch.object(agent,'dhcp_clients',return_value=[(437,['dhclient','ens18'])]),patch.object(agent,'dhcp_run') as run:
            agent.dhcp_background('ens18',{'cleanup_unscoped':True});run.assert_not_called()

    def test_lease_client_is_foreground_in_independent_restartable_unit(self):
        with patch.object(agent,'dhcp_clients',return_value=[]),patch.object(agent.shutil,'which',return_value='/sbin/dhclient'),patch.object(agent.subprocess,'run') as run:
            agent.dhcp_background('ens18',{})
            args=run.call_args_list[-1].args[0]
            self.assertIn('--unit=hksdan-dhcp-client-ens18',args)
            self.assertIn('--property=Restart=always',args)
            self.assertIn('-d',args)
            self.assertNotIn('--property=RuntimeMaxSec=240',args)
    def test_unstable_preferred_address_retries_until_stable(self):
        state,run=self.run_task(['8.8.8.8']+['42.98.100.156']*4)
        with patch.object(agent,'dhcp_stable',side_effect=[False,True]):agent.dhcp_task(99)
        result=json.loads((state/'dhcp-result.json').read_text())
        self.assertEqual(result['state'],'changed');self.assertEqual(result['attempts'],2)
    def test_recovery_checks_client_even_when_address_exists(self):
        with patch.object(agent,'dhcp_config',return_value={'interface':'ens18'}),patch.object(agent,'dhcp_background') as background,tempfile.TemporaryDirectory() as folder,patch.object(agent,'DHCP_STATE',Path(folder)):
            agent.dhcp_recover();background.assert_called_once_with('ens18',{'interface':'ens18'})
    def test_stability_requires_live_client_and_default_route(self):
        from types import SimpleNamespace
        with patch.object(agent,'dhcp_address',return_value='1.1.1.1'),patch.object(agent,'dhcp_clients',return_value=[(1,[])]),patch.object(agent.subprocess,'run',return_value=SimpleNamespace(stdout='')),patch.object(agent.time,'sleep'):
            self.assertFalse(agent.dhcp_stable('ens18','1.1.1.1'))

    def test_dhcpcd_selects_only_verified_interface_master(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);binary=root/'dhcpcd';binary.write_text('')
            titles={1:'dhcpcd: ens18 [ip4] [ip6]',2:'dhcpcd: [privileged proxy] ens18 [ip4] [ip6]',3:'dhcpcd: [DHCP6 proxy] fe80::1',4:'dhcpcd: eth0 [ip4] [ip6]',5:'dhcpcd: [BOOTP proxy] 1.1.1.1',6:'dhcpcd: ens18 [ip4] [ip6]'}
            other=root/'echo';other.write_text('')
            for pid,title in titles.items():
                path=root/str(pid);path.mkdir();(path/'cmdline').write_bytes(title.encode()+b'\0');(path/'exe').symlink_to(other if pid==6 else binary)
            self.assertEqual(agent.dhcpcd_clients('ens18',root),[(1,titles[1])])
    def test_dhcpcd_ipv4_release_keeps_dual_stack_rebind_and_never_kills(self):
        master=[(690,'dhcpcd: ens18 [ip4] [ip6]')]
        with patch.object(agent,'dhcpcd_clients',return_value=master),patch.object(agent,'dhcp_clients',return_value=[]),patch.object(agent,'dhcp_run',return_value=True) as run,patch.object(agent.shutil,'which',return_value='/usr/sbin/dhcpcd'),patch.object(agent.time,'sleep'),patch.object(agent.os,'kill') as kill:
            agent.dhcpcd_cycle('ens18')
            self.assertEqual(run.call_args_list[0].args[0],['/usr/sbin/dhcpcd','-4','-k','ens18'])
            rebind=run.call_args_list[1].args[0]
            self.assertIn('-n',rebind);self.assertIn('-I',rebind);self.assertNotIn('-4',rebind);self.assertNotIn('-6',rebind)
            self.assertEqual(rebind[-1],'ens18');kill.assert_not_called()
    def test_dhcpcd_mixed_managers_are_rejected_before_release(self):
        with patch.object(agent,'dhcpcd_clients',return_value=[(690,'dhcpcd: ens18 [ip4] [ip6]')]),patch.object(agent,'dhcp_clients',return_value=[(9,['dhclient','ens18'])]),patch.object(agent,'dhcp_run') as run:
            with self.assertRaises(ValueError):agent.dhcpcd_cycle('ens18')
            with self.assertRaises(ValueError):agent.dhcp_manager('ens18')
            run.assert_not_called()
    def test_dhcpcd_missing_manager_does_not_start_new_daemon(self):
        with patch.object(agent,'dhcpcd_clients',return_value=[]),patch.object(agent,'dhcp_run') as run:
            with self.assertRaises(ValueError):agent.dhcpcd_rebind('ens18')
            run.assert_not_called()
    def test_dhcpcd_task_preserves_classic_leases_and_obeys_42_policy(self):
        state,run=self.run_task(['112.118.57.212','119.236.115.55','119.236.115.55','42.98.100.156','42.98.100.156'])
        with patch.object(agent,'dhcp_config',return_value={'interface':'ens18','manager':'dhcpcd'}),patch.object(agent,'dhcpcd_cycle') as cycle:
            agent.dhcp_task(101)
        result=json.loads((state/'dhcp-result.json').read_text())
        self.assertEqual(result['state'],'changed');self.assertEqual(cycle.call_count,2)
        self.assertTrue((state/'ens18.leases').exists());run.assert_not_called()
    def test_dhcpcd_detection_requires_v10(self):
        from types import SimpleNamespace
        with patch.object(agent,'dhcpcd_clients',return_value=[(690,'dhcpcd: ens18 [ip4] [ip6]')]),patch.object(agent,'dhcp_clients',return_value=[]),patch.object(agent.shutil,'which',return_value='/usr/sbin/dhcpcd'),patch.object(agent.subprocess,'run',return_value=SimpleNamespace(stdout='dhcpcd 10.1.0\n')) as run:
            self.assertEqual(agent.dhcp_manager('ens18'),'dhcpcd')
            run.return_value.stdout='dhcpcd 9.4.1'
            with self.assertRaises(ValueError):agent.dhcp_manager('ens18')

    def test_local_opt_in_required_before_launching_any_task(self):
        with patch.object(agent,'dhcp_config',side_effect=ValueError('disabled')),patch.object(agent.subprocess,'run') as run:
            with self.assertRaises(ValueError):agent.dispatch_dhcp(1)
            run.assert_not_called()
