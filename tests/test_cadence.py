import unittest, importlib.util, sqlite3, json
from pathlib import Path
from unittest.mock import patch, MagicMock
from network import record_network
spec=importlib.util.spec_from_file_location('collector',Path(__file__).parents[1]/'agent/agent.py')
collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)

class CadenceTest(unittest.TestCase):
    def test_connections_refresh_every_five_seconds_and_update_timestamp(self):
        sampler=collector.ConnectionSampler()
        with patch.object(collector,'tcp_count',side_effect=[12,90,7]) as tcp,patch.object(collector,'udp_count',return_value=(3,'')) as udp,patch.object(collector,'tcp_port_counts',return_value={'443':12}),patch.object(collector.time,'time',return_value=100) as wall:
            for stamp in (0,1,4.99):self.assertEqual(sampler.sample(lambda:stamp),(12,3,''))
            self.assertEqual(tcp.call_count,1);self.assertEqual(udp.call_count,1)
            self.assertEqual(sampler.sampled_at,100)
            wall.return_value=105
            self.assertEqual(sampler.sample(lambda:5),(90,3,''))
            self.assertEqual(sampler.sampled_at,105)
            self.assertEqual(sampler.sample(lambda:9.99),(90,3,''))
            wall.return_value=110
            self.assertEqual(sampler.sample(lambda:10),(7,3,''))
            self.assertEqual(sampler.sampled_at,110)
            self.assertEqual(tcp.call_count,3);self.assertEqual(udp.call_count,3)
    def test_history_is_limited_but_all_traffic_is_counted(self):
        db=sqlite3.connect(':memory:')
        db.executescript('CREATE TABLE metric_points(server_id INTEGER,stamp INTEGER,cpu REAL,memory REAL,tcp REAL,udp REAL,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));CREATE TABLE traffic_daily(server_id INTEGER,day TEXT,rx INTEGER,tx INTEGER,PRIMARY KEY(server_id,day));CREATE TABLE network_points(server_id INTEGER,stamp INTEGER,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));')
        row={'id':1,'seen':None,'metrics':None}
        for stamp in (100,105,110,115,120):
            m={'rx_bytes':stamp*100,'tx_bytes':stamp*200,'uptime':stamp,'cpu_percent':20}
            record_network(db,row,m,stamp);row={'id':1,'seen':stamp,'metrics':json.dumps(m)}
        self.assertEqual(db.execute('SELECT COUNT(*) FROM metric_points').fetchone()[0],2)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM network_points').fetchone()[0],2)
        self.assertEqual(db.execute('SELECT SUM(rx),SUM(tx) FROM traffic_daily').fetchone(),(2000,4000))
        self.assertEqual(m['rx_bps'],800)
    def test_egress_probe_is_bounded_and_rejects_private_results(self):
        sampler=collector.EgressSampler();response=MagicMock();response.__enter__.return_value.read.return_value=b'127.0.0.1'
        opener=MagicMock();opener.open.return_value=response
        with patch.object(collector.urllib.request,'build_opener',return_value=opener),patch.object(collector.time,'sleep',side_effect=InterruptedError):
            with self.assertRaises(InterruptedError):sampler.run()
        self.assertIsNone(sampler.snapshot()['egress_ips']);self.assertTrue(sampler.snapshot()['egress_error'])
        self.assertEqual(opener.open.call_count,2)
        self.assertEqual(opener.open.call_args.kwargs['timeout'],3)

class UDPSocketTest(unittest.TestCase):
    def test_all_ss_socket_rows_are_counted(self):
        response=MagicMock(returncode=0,stdout='UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n\nESTAB 0 0 [::1]:40 [::1]:50\n')
        with patch.object(collector.shutil,'which',return_value='/usr/bin/ss'),patch.object(collector.subprocess,'run',return_value=response) as run:
            self.assertEqual(collector.udp_count(),(2,''))
            self.assertEqual(run.call_args.args[0],['ss','-u','-a','-n','-H'])
    def test_no_sockets_is_zero_but_command_failure_is_unavailable(self):
        with patch.object(collector.shutil,'which',return_value='/usr/bin/ss'),patch.object(collector.subprocess,'run',return_value=MagicMock(returncode=0,stdout='')) as run:
            self.assertEqual(collector.udp_count(),(0,''))
            run.return_value.returncode=1
            self.assertIsNone(collector.udp_count()[0])
    def test_missing_ss_or_timeout_never_becomes_zero(self):
        with patch.object(collector.shutil,'which',return_value=None):self.assertIsNone(collector.udp_count()[0])
        with patch.object(collector.shutil,'which',return_value='/usr/bin/ss'),patch.object(collector.subprocess,'run',side_effect=collector.subprocess.TimeoutExpired('ss',5)):
            self.assertIsNone(collector.udp_count()[0])

class HardwareInventoryTest(unittest.TestCase):
    def test_cpu_count_uses_process_available_logical_cpus(self):
        with patch.object(collector.os,'sched_getaffinity',return_value={0,2,4,6}):self.assertEqual(collector.logical_cpu_count(),4)
        with patch.object(collector.os,'sched_getaffinity',side_effect=OSError),patch.object(collector.os,'cpu_count',return_value=8):self.assertEqual(collector.logical_cpu_count(),8)
    def test_report_includes_memory_capacity_used_and_cpu_count(self):
        from unittest.mock import patch, mock_open
        stat='cpu  1 2 3 4 5 6 7 8\n'
        mem='MemTotal: 4194304 kB\nMemAvailable: 3145728 kB\nMemFree: 1000 kB\n'
        def read(path,*args,**kwargs):
            if str(path)=='/proc/stat':return stat
            if str(path)=='/proc/meminfo':return mem
            if str(path)=='/proc/uptime':return '100.0 200.0'
            if str(path)=='/etc/os-release':raise OSError()
            if str(path)=='/proc/net/dev':return 'Inter-| Receive | Transmit\n eth0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n'
            raise AssertionError(path)
        with patch.object(collector.Path,'read_text',new=read),patch.object(collector.shutil,'disk_usage',return_value=__import__('shutil')._ntuple_diskusage(50,100,100)),patch.object(collector,'logical_cpu_count',return_value=4),patch.object(collector,'ConnectionSampler') as conn,patch.object(collector,'public_addresses',return_value=([],'')):
            conn.return_value.sample.return_value=(1,0,'')
            metrics,_=collector.collect(None,conn.return_value)
        self.assertEqual((metrics['cpu_count'],metrics['memory_total'],metrics['memory_used']),(4,4294967296,1073741824))
