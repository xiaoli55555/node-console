import importlib.util
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('tcp_worker', 'probe/probe.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

class ProbeTests(unittest.TestCase):
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
