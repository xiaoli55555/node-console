"""Offline access-path comparison. Uses synthetic data; never opens panel.db."""
import ast
import json
import re
import sqlite3
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEXES = {
    'detectors.py': ('detection_server_order', 'detection_created', 'detection_server_created'),
    'tcp_history.py': ('tcp_samples_server_latest',),
    'detection_recheck.py': ('guard_cost_parent',),
}
SCHEMA = '''
CREATE TABLE detection_runs(id INTEGER PRIMARY KEY,server_id INTEGER,source_id INTEGER,
 ip TEXT,port INTEGER,nodes TEXT,status TEXT,created INTEGER,updated INTEGER,
 details TEXT,cost INTEGER,action_command_id INTEGER,action_status TEXT,poll_at INTEGER DEFAULT 0);
CREATE INDEX detection_pending ON detection_runs(status,poll_at);
CREATE INDEX detection_server_latest ON detection_runs(server_id,source_id,id);
CREATE INDEX detection_recovery_status ON detection_runs(action_status,id);
CREATE INDEX insight_detection_ip_time ON detection_runs(server_id,ip,created);
CREATE TABLE tcp_samples(id INTEGER PRIMARY KEY,server_id INTEGER,received_at INTEGER,
 sampled_at INTEGER,valid INTEGER,addresses TEXT,address_source TEXT);
CREATE INDEX tcp_samples_server_time ON tcp_samples(server_id,received_at,id);
CREATE INDEX tcp_samples_expiry ON tcp_samples(received_at);
CREATE TABLE detection_guard_costs(id INTEGER PRIMARY KEY,parent_id INTEGER,
 primary_server_id INTEGER,reserved_at INTEGER,cost INTEGER);
CREATE INDEX guard_cost_day ON detection_guard_costs(primary_server_id,reserved_at);
CREATE TABLE vps_failover_probe_costs(run_id INTEGER PRIMARY KEY,primary_server_id INTEGER);
'''
QUERIES = [
    ('latest_probe', 'SELECT id,ip,port,status,created,updated,details FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1', (3,)),
    ('latest_tcp', 'SELECT id,received_at,sampled_at,valid FROM tcp_samples WHERE server_id=? ORDER BY id DESC LIMIT 1', (3,)),
    ('latest_created', 'SELECT MAX(created) FROM detection_runs WHERE server_id=?', (3,)),
    ('expired_probe_cleanup', "DELETE FROM detection_runs WHERE created<? AND status NOT IN ('pending','queued','issued','creating') AND (action_command_id IS NOT NULL OR action_status IS NULL OR action_status NOT IN ('queued','issued','submitted','uncertain','verifying'))", (-1,)),
]


def index_sql():
    statements = []
    for filename, names in INDEXES.items():
        tree = ast.parse((ROOT / filename).read_text())
        literals = [node.value for node in ast.walk(tree)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        for name in names:
            pattern = r'CREATE INDEX IF NOT EXISTS ' + name + r'\s+ON\s+[^;]+(?:;|$)'
            matches = [match.group(0) for text in literals
                       for match in re.finditer(pattern, text)]
            if len(matches) != 1:
                raise AssertionError((filename, name, matches))
            statements.append(matches[0])
    return statements


def daily_usage_function():
    tree = ast.parse((ROOT / 'detection_recheck.py').read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'daily_usage')
    scope = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'detection_recheck.py', 'exec'), scope)
    return scope['daily_usage']


def measure(db, operation):
    # Count actual SQLite VM progress in units of 100, not disk bytes or CPU %.
    progress = [0]
    def step():
        progress[0] += 1
        return 0
    db.set_progress_handler(step, 100)
    started = time.perf_counter()
    try:
        result = operation()
    finally:
        elapsed = time.perf_counter() - started
        db.set_progress_handler(None, 0)
    return result, {'vm_steps_rounded_down_to_100': progress[0] * 100,
                    'elapsed_ms': round(elapsed * 1000, 3)}


def run_benchmark(rows=20000):
    with tempfile.TemporaryDirectory(prefix='hksdan-offline-bench-') as tmp:
        db = sqlite3.connect(str(Path(tmp) / 'synthetic.db'))
        try:
            db.executescript(SCHEMA)
            probes = [(i, i % 7, i % 3, '192.0.2.' + str(i % 200 + 1), 59218,
                       '["one","two"]', 'reachable', i, i + 1, '[]', i % 4, None, None)
                      for i in range(1, rows + 1)]
            insert_probe = 'INSERT INTO detection_runs(id,server_id,source_id,ip,port,nodes,status,created,updated,details,cost,action_command_id,action_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'
            db.executemany(insert_probe, probes)
            db.executemany('INSERT INTO tcp_samples VALUES(?,?,?,?,?,?,?)',
                           ((i, i % 7, i, i, 1, '[]', 'egress') for i in range(1, rows + 1)))
            db.executemany('INSERT INTO detection_guard_costs VALUES(?,?,?,?,?)',
                           ((i, i * 10, (i * 10) % 7, i * 10, i % 2) for i in range(1, rows // 10 + 1)))
            db.executemany('INSERT INTO vps_failover_probe_costs VALUES(?,?)',
                           ((i, 3) for i in range(13, rows + 1, 137)))
            db.commit()
            indexes = index_sql()
            daily = daily_usage_function()
            stages = []
            expected = {}
            for optimized in (False, True):
                if optimized:
                    for statement in indexes:
                        db.execute(statement)
                    db.commit()
                measurements = {}
                for label, sql, params in QUERIES:
                    result, metrics = measure(db, lambda: db.execute(sql, params).fetchall())
                    if label.startswith('expired_'):
                        db.rollback()
                    metrics['plan'] = db.execute('EXPLAIN QUERY PLAN ' + sql, params).fetchall()
                    measurements[label] = metrics
                    if not optimized:
                        expected[label] = result
                    elif result != expected[label]:
                        raise AssertionError('Query result changed: ' + label)
                result, metrics = measure(db, lambda: daily(db, 3, rows // 2))
                measurements['daily_quota'] = metrics
                if not optimized:
                    expected['daily_quota'] = result
                elif result != expected['daily_quota']:
                    raise AssertionError('Daily quota changed')
                size = db.execute('PRAGMA page_count').fetchone()[0] * db.execute('PRAGMA page_size').fetchone()[0]
                # Same batch inserted and rolled back in both variants.
                write_rows = [(rows + i, 3, 1, '192.0.2.250', 59218, '[]',
                               'reachable', rows + i, rows + i + 1, '[]', 0, None, None)
                              for i in range(1, 5001)]
                inserted, metrics = measure(db, lambda: db.executemany(insert_probe, write_rows).rowcount)
                if inserted != 5000:
                    raise AssertionError('Insert count changed')
                measurements['insert_5000_probes'] = metrics
                db.rollback()
                stages.append({'optimized': optimized, 'database_bytes': size,
                               'measurements': measurements})
            return {'dataset': {'probe_rows': rows, 'tcp_rows': rows, 'guard_rows': rows // 10},
                    'results_identical': True, 'quota_value': expected['daily_quota'],
                    'stages': stages}
        finally:
            db.close()


if __name__ == '__main__':
    print(json.dumps(run_benchmark(), ensure_ascii=False, indent=2))
