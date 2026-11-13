"""Exercise the production connection factory without importing app startup."""
import ast
import gc
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ConnectionLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'panel.db'
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'server.py').read_text())
        nodes = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))
                 and n.name in ('ClosingConnection', 'connect')]
        self.scope = {'sqlite3': sqlite3, 'DB': self.path}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'server.py', 'exec'), self.scope)
        self.connect = self.scope['connect']
        with self.connect() as db:
            db.executescript('CREATE TABLE items(id INTEGER PRIMARY KEY);'
                             'CREATE TABLE children(parent INTEGER REFERENCES items(id)'
                             ' DEFERRABLE INITIALLY DEFERRED);')

    def assertClosed(self, db):
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')

    def test_success_commits_then_closes(self):
        with self.connect() as db:
            self.assertIsInstance(db, sqlite3.Connection)
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0], 1)
            db.execute('INSERT INTO items VALUES(1)')
        self.assertClosed(db)
        with self.connect() as check:
            self.assertEqual(check.execute('SELECT id FROM items').fetchone()['id'], 1)

    def test_exception_rolls_back_and_propagates_then_closes(self):
        with self.assertRaisesRegex(ValueError, 'original failure'):
            with self.connect() as db:
                db.execute('INSERT INTO items VALUES(2)')
                raise ValueError('original failure')
        self.assertClosed(db)
        with self.connect() as check:
            self.assertEqual(check.execute('SELECT COUNT(*) FROM items').fetchone()[0], 0)

    def test_commit_failure_rolls_back_then_closes(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.connect() as db:
                db.execute('INSERT INTO children VALUES(999)')
        self.assertClosed(db)
        with self.connect() as check:
            self.assertEqual(check.execute('SELECT COUNT(*) FROM children').fetchone()[0], 0)

    def test_early_return_commits_before_close(self):
        def operation():
            with self.connect() as db:
                db.execute('INSERT INTO items VALUES(3)')
                return db
        db = operation()
        self.assertClosed(db)
        with self.connect() as check:
            self.assertEqual(check.execute('SELECT id FROM items').fetchone()[0], 3)

    def test_manually_managed_connection_and_backup_still_work(self):
        db = self.connect()
        try:
            db.execute('INSERT INTO items VALUES(4)')
            db.commit()
            self.assertEqual(db.execute('SELECT id FROM items').fetchone()[0], 4)
            target = sqlite3.connect(':memory:')
            try:
                with target:
                    db.backup(target)
                    self.assertEqual(target.execute('SELECT id FROM items').fetchone()[0], 4)
            finally:
                target.close()
        finally:
            db.close()

    def test_setup_failure_closes_connection(self):
        real_connect = sqlite3.connect
        opened = []
        def failing_connect(*args, **kwargs):
            db = real_connect(*args, **kwargs)
            db.set_authorizer(lambda *unused: sqlite3.SQLITE_DENY)
            opened.append(db)
            return db
        with patch.object(sqlite3, 'connect', side_effect=failing_connect):
            with self.assertRaises(sqlite3.DatabaseError):
                self.connect()
        self.assertClosed(opened[0])

    def test_retained_connections_release_fds_without_garbage_collection(self):
        held = []
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            for _ in range(300):
                with self.connect() as db:
                    db.execute('SELECT 1').fetchone()
                held.append(db)
            for db in held:
                self.assertClosed(db)
            if Path('/proc/self/fd').exists():
                targets = []
                for fd in Path('/proc/self/fd').iterdir():
                    try:
                        targets.append(str(fd.resolve(strict=True)))
                    except FileNotFoundError:
                        pass
                self.assertNotIn(str(self.path), targets)
        finally:
            if was_enabled:
                gc.enable()


if __name__ == '__main__':
    unittest.main()
