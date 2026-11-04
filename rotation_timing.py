"""Observed DNS carrier periods, independent of uptime and drain duration."""
def initialize(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS rotation_carrier_periods(
        id INTEGER PRIMARY KEY,
        rotation_id INTEGER NOT NULL REFERENCES vps_rotations(id) ON DELETE CASCADE,
        server_id INTEGER NOT NULL,ip TEXT NOT NULL,started INTEGER NOT NULL,
        finished INTEGER,elapsed_s INTEGER,deadline INTEGER,overdue_s INTEGER,
        reason TEXT NOT NULL,end_reason TEXT,censored INTEGER NOT NULL DEFAULT 0);
        CREATE UNIQUE INDEX IF NOT EXISTS carrier_one_open
        ON rotation_carrier_periods(rotation_id) WHERE finished IS NULL;
        CREATE INDEX IF NOT EXISTS carrier_history ON rotation_carrier_periods(rotation_id,id);
        CREATE INDEX IF NOT EXISTS carrier_ip_usage ON rotation_carrier_periods(rotation_id,server_id,ip);''')


def planned_deadline(r,sid):
    if not r['enabled']:return None
    if sid not in (r['primary_server_id'],r['other_server_id']):return None
    if r['mode']=='fixed_primary' and sid==r['primary_server_id']:return None
    return r['next_switch_at']


def change(db,rid,sid,ip,now,reason,censored=False):
    r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
    if not r:return
    current=db.execute('SELECT * FROM rotation_carrier_periods WHERE rotation_id=? AND finished IS NULL',(rid,)).fetchone()
    if current and current['server_id']==sid and current['ip']==ip:return
    if current:
        deadline=planned_deadline(r,current['server_id'])
        db.execute('UPDATE rotation_carrier_periods SET finished=?,elapsed_s=?,deadline=?,overdue_s=?,end_reason=? WHERE id=?',
                   (now,max(0,now-current['started']),deadline,max(0,now-deadline) if deadline is not None else None,reason,current['id']))
    db.execute('INSERT INTO rotation_carrier_periods(rotation_id,server_id,ip,started,reason,censored) VALUES(?,?,?,?,?,?)',
               (rid,sid,ip,now,reason,int(censored)))
    # Old periods remain the durable usage ledger: a returning IP must never
    # regain its allowance merely because its last period aged out.


def ip_usage(db,rid,sid,ip,now):
    # Use the greatest observed usage across the plan's DNS records. Their
    # confirmations may differ slightly; neither summing nor resetting is safe.
    return db.execute('''SELECT COALESCE(MAX(used),0) FROM (
        SELECT SUM(CASE WHEN p.finished IS NULL THEN MAX(0,?-p.started)
            ELSE MAX(0,p.elapsed_s) END) AS used
        FROM rotation_carrier_periods p JOIN vps_rotations m ON m.id=p.rotation_id
        JOIN vps_rotations r ON r.id=? AND m.primary_server_id=r.primary_server_id
            AND m.other_server_id=r.other_server_id AND m.owner_id=r.owner_id AND m.mode=r.mode
        WHERE p.server_id=? AND p.ip=? GROUP BY p.rotation_id)''',
        (now,rid,sid,ip)).fetchone()[0]


def allowance(db,r,now):
    if r['mode']!='alternating':return None
    current=db.execute('SELECT * FROM rotation_carrier_periods WHERE rotation_id=? AND finished IS NULL',(r['id'],)).fetchone()
    if not current or current['server_id']!=r['active_server_id']:return None
    if db.execute('SELECT 1 FROM vps_failover_leases WHERE binding_id=?',(r['binding_id'],)).fetchone():return None
    used=ip_usage(db,r['id'],current['server_id'],current['ip'],now)
    return {'ip':current['ip'],'used_s':used,'limit_s':r['interval_s'],
            'remaining_s':max(0,r['interval_s']-used),
            'deadline':now+r['interval_s']-used}


def ensure_observed(db,r,now):
    if not r or db.execute('SELECT 1 FROM rotation_carrier_periods WHERE rotation_id=?',(r['id'],)).fetchone():return
    # Minimal state-machine fixtures may not have DNS bindings.
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dns_bindings'").fetchone():return
    binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
    if not binding or r['dns_intent']:return
    lease=db.execute('SELECT l.*,p.failover_server_id FROM vps_failover_leases l JOIN vps_rotations p ON p.id=l.rotation_id WHERE l.binding_id=?',(r['binding_id'],)).fetchone()
    if lease and lease['intent']:return
    sid=lease['failover_server_id'] if lease else r['active_server_id']
    change(db,r['id'],sid,binding['expected_ip'],now,'first_observed',censored=True)


def snapshot(db,r,now):
    rows=[dict(x) for x in db.execute('SELECT p.*,s.name AS server_name FROM rotation_carrier_periods p LEFT JOIN servers s ON s.id=p.server_id WHERE rotation_id=? ORDER BY p.id DESC LIMIT 50',(r['id'],))]
    current=next((x for x in rows if x['finished'] is None),None)
    if current:current=dict(current,elapsed_s=max(0,now-current['started']))
    deadline=planned_deadline(r,current['server_id'] if current else r['active_server_id'])
    return {'server_now':now,'current':current,'history':rows,'allowance':allowance(db,r,now),
            'switch_deadline':deadline,'overdue_s':max(0,now-deadline) if deadline is not None else None,
            'drain_timeout_at':r['drain_started']+3600 if r['phase']=='draining' and r['drain_started'] is not None and r['force_drain_threshold'] else None,
            'force_threshold':r['force_drain_threshold'],
            'action_observe_until':r['action_started']+60 if r['phase']=='waiting_ip' and r['action_started'] is not None else None}
