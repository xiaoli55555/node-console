import ast
from contextlib import closing
import sqlite3
import unittest
from pathlib import Path


class ReportExpiryIndexTest(unittest.TestCase):
    def test_index_preserves_rows_and_cleanup_boundary(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'rotation_insights.py').read_text())
        schema = next(ast.literal_eval(n.value) for n in tree.body
                  if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SCHEMA' for t in n.targets))
        with closing(sqlite3.connect(':memory:')) as db:
            db.executescript('CREATE TABLE vps_rotations(id INTEGER PRIMARY KEY);'
                             'CREATE TABLE ip_events(server_id,observed);'
                             'CREATE TABLE detection_runs(server_id,ip,created);')
            db.executescript(schema.replace('CREATE INDEX IF NOT EXISTS rotation_report_expiry ON rotation_report_samples(created);', ''))
            rows = [(1, 999, 'expired'), (1, 1000, 'boundary'), (2, 1001, 'retained')]
            db.executemany('INSERT INTO rotation_report_samples(rotation_id,created,payload) VALUES(?,?,?)', rows)
            before = db.execute('SELECT * FROM rotation_report_samples ORDER BY id').fetchall()
            plan_before = db.execute('EXPLAIN QUERY PLAN DELETE FROM rotation_report_samples WHERE created<?', (1000,)).fetchall()
            self.assertTrue(any('SCAN rotation_report_samples' in r[3] for r in plan_before))
            db.executescript(schema)
            db.executescript(schema)
            self.assertEqual(before, db.execute('SELECT * FROM rotation_report_samples ORDER BY id').fetchall())
            plan_after = db.execute('EXPLAIN QUERY PLAN DELETE FROM rotation_report_samples WHERE created<?', (1000,)).fetchall()
            self.assertTrue(any('rotation_report_expiry' in r[3] and 'SEARCH' in r[3] for r in plan_after))
            db.execute('DELETE FROM rotation_report_samples WHERE created<?', (1000,))
            self.assertEqual(db.execute('SELECT rotation_id,created,payload FROM rotation_report_samples ORDER BY id').fetchall(), rows[1:])
