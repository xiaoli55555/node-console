"""Dependency-free tests of the actual DHCP interlock function."""
import ast
import sqlite3
import unittest
from pathlib import Path

class Block(Exception):
    def __init__(self, message, command_id, code):
        self.command_id, self.code = command_id, code

class TerminalRetry(unittest.TestCase):
    def setUp(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'hkt_dhcp.py').read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'action_block')
        scope = {'ChangeIPBlocked': Block}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'hkt_dhcp.py', 'exec'), scope)
        self.guard = scope['action_block']
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript("CREATE TABLE hkt_dhcp_apis(server_id,connection_id,reset_after); CREATE TABLE commands(id,server_id,action,status); INSERT INTO hkt_dhcp_apis VALUES(4,10,0);")

    def test_terminal_states_allow_retry(self):
        for status in ('failed','expired','completed'):
            with self.subTest(status=status):
                self.db.execute('DELETE FROM commands')
                self.db.execute("INSERT INTO commands VALUES(185,4,'hkt_dhcp',?)", (status,))
                self.assertIsNone(self.guard(self.db,4,10,False))

    def test_unconfirmed_still_blocks(self):
        self.db.execute("INSERT INTO commands VALUES(185,4,'hkt_dhcp','unconfirmed')")
        self.assertEqual(self.guard(self.db,4,10).code, 'dhcp_unconfirmed')

    def test_latest_pending_overrides_terminal_history(self):
        self.db.executescript("INSERT INTO commands VALUES(185,4,'hkt_dhcp','expired'); INSERT INTO commands VALUES(186,4,'hkt_dhcp','unconfirmed');")
        self.assertEqual(self.guard(self.db,4,10).command_id,186)

    def test_other_server_failure_is_ignored(self):
        self.db.execute("INSERT INTO commands VALUES(185,6,'hkt_dhcp','expired')")
        self.assertIsNone(self.guard(self.db,4,10))

if __name__ == '__main__':
    unittest.main()
