import importlib.util
import sqlite3
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('offline_db_benchmark', Path(__file__).resolve().parents[1] / 'scripts/benchmark_db_access.py')
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class AccessPathTest(unittest.TestCase):
    def test_hot_access_paths_preserve_results_and_reduce_scans(self):
        report = benchmark.run_benchmark()
        self.assertTrue(report['results_identical'])
        before, after = [s['measurements'] for s in report['stages']]
        for label in ('latest_probe', 'latest_tcp', 'latest_created', 'expired_probe_cleanup', 'daily_quota'):
            with self.subTest(label=label):
                old = before[label]['vm_steps_rounded_down_to_100']
                new = after[label]['vm_steps_rounded_down_to_100']
                self.assertGreater(old, 1000)
                self.assertLess(new, old // 10)

    def test_indexes_are_additive_and_idempotent(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.executescript(benchmark.SCHEMA)
        old_schema = db.execute('SELECT type,name,sql FROM sqlite_master ORDER BY type,name').fetchall()
        for _ in range(2):
            for statement in benchmark.index_sql():
                db.execute(statement)
        new_schema = db.execute('SELECT type,name,sql FROM sqlite_master ORDER BY type,name').fetchall()
        self.assertTrue(set(old_schema).issubset(set(new_schema)))
        self.assertEqual(len(new_schema), len(old_schema) + 5)


if __name__ == '__main__':
    unittest.main()
