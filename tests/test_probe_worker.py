import importlib.util
import unittest
import tempfile
import threading
import json
import io
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('tcp_worker', 'probe/probe.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

class ProbeTests(unittest.TestCase):
    def test_saved_results_survive_restart_and_expired_results_are_dropped(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'pending.json'
            pending={'1': {'created':time.time(), 'result':{'reachable':True}},
                     '2': {'created':time.time()-121, 'result':{'reachable':False}}}
            worker.save_pending(path,pending)
            self.assertEqual(set(worker.load_pending(path)),{'1'})
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            worker.save_pending(path,{})
            self.assertEqual(worker.load_pending(path),{})

    def test_parallel_tasks_and_failed_upload_retry_saved_results(self):
        class StopLoop(BaseException):pass
        with tempfile.TemporaryDirectory() as directory:
            cfg=Path(directory)/'config.json'
            cfg.write_text(json.dumps({'panel_url':'https://panel.example', 'token':'test', 'state_dir':directory,'max_workers':2}))
            second_started=threading.Event()
            uploaded=[];attempts={};jobs=iter([{'id':1,'ip':'8.8.8.8','port':443},{'id':2,'ip':'1.1.1.1','port':443}])
            lock=threading.Lock()
            def measure(ip,port):
                if ip=='8.8.8.8':
                    if not second_started.wait(2):raise AssertionError('tasks were serialized')
                else:second_started.set()
                return {'ip':ip,'port':port,'reachable':True,'latency_ms':1}
            def request(req,timeout):
                if req.full_url.endswith('/jobs'):
                    return io.BytesIO(json.dumps({'job':next(jobs,None)}).encode())
                rid=req.full_url.rsplit('/',1)[1]
                # Every upload must have a durable result before the first network attempt.
                files=list(Path(directory).glob('pending-*.json'))
                self.assertTrue(files)
                self.assertIn(rid,json.loads(files[0].read_text()))
                with lock:
                    attempts[rid]=attempts.get(rid,0)+1
                    if attempts[rid]==1:raise worker.urllib.error.URLError('simulated reset')
                    uploaded.append(rid)
                return io.BytesIO(b'{"ok":true}')
            opener=MagicMock();opener.open.side_effect=request
            iterations=[0]
            def step(_):
                time.sleep(.01);iterations[0]+=1
                if len(uploaded)==2 or iterations[0]>100:raise StopLoop()
            # Keep the real sleeper separate from the patched module's time object.
            real_time=worker.time
            fake_time=MagicMock();fake_time.time.side_effect=real_time.time;fake_time.sleep.side_effect=step
            with patch.object(worker.urllib.request,'build_opener',return_value=opener), patch.object(worker,'measure',side_effect=measure), patch.object(worker,'time',fake_time), patch('sys.argv',['probe.py',str(cfg)]):
                with self.assertRaises(StopLoop):worker.main()
            self.assertEqual(set(uploaded),{'1','2'})
            self.assertTrue(all(n==2 for n in attempts.values()))

    def test_success_after_timeout(self):
        with patch.object(worker.socket, 'create_connection', side_effect=[TimeoutError(), MagicMock()]):
            result = worker.measure('8.8.8.8', 443)
        self.assertTrue(result['reachable'])
        self.assertEqual([a['state'] for a in result['attempts']], ['timeout', 'reachable'])

    def test_refused_is_failure(self):
        with patch.object(worker.socket, 'create_connection', side_effect=ConnectionRefusedError()):
            result = worker.measure('8.8.8.8', 443)
        self.assertFalse(result['reachable'])
        self.assertEqual(len(result['attempts']), 2)
        self.assertIsNone(result['latency_ms'])

    def test_private_and_invalid_port_rejected_before_connect(self):
        with patch.object(worker.socket, 'create_connection') as conn:
            for ip, port in [('127.0.0.1', 443), ('8.8.8.8', 0), ('8.8.8.8', True)]:
                with self.assertRaises(ValueError):
                    worker.measure(ip, port)
            conn.assert_not_called()

if __name__ == '__main__':
    unittest.main()
