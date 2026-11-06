"""Raw host TCP samples associated with addresses observed in the same report."""
import ipaddress
import json

RETENTION_S=7*86400

def initialize(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS tcp_samples(
      id INTEGER PRIMARY KEY AUTOINCREMENT,server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      received_at INTEGER NOT NULL,sampled_at INTEGER,tcp INTEGER,valid INTEGER NOT NULL,
      reason TEXT NOT NULL,addresses TEXT NOT NULL,address_source TEXT NOT NULL,
      ports TEXT NOT NULL,context TEXT NOT NULL,UNIQUE(server_id,received_at));
      CREATE INDEX IF NOT EXISTS tcp_samples_server_time ON tcp_samples(server_id,received_at,id);
      CREATE INDEX IF NOT EXISTS tcp_samples_expiry ON tcp_samples(received_at);''')

def gate(db,sid,metrics,now,seen=None):
    import rotation_schedule
    count=metrics.get('tcp');stamp=metrics.get('connections_sampled')
    valid=type(count)is int and count>=0 and type(stamp)is int and 0<=now-stamp<=45
    reason='' if valid else 'TCP 采样缺失、无效或超过 45 秒'
    plans=[]
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='vps_rotations' AND type='table'").fetchone():
        for p in db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? OR other_server_id=?',(sid,sid)):
            limit=rotation_schedule.effective(p,now)['threshold']
            plans.append(dict(plan_id=p['id'],phase=p['phase'],enabled=bool(p['enabled']),threshold=limit,
                              role='carrier' if p['active_server_id']==sid else 'standby',
                              below_threshold=bool(valid and count<limit)))
    heartbeat_fresh=seen is None or (type(seen)is int and 0<=now-seen<=45)
    passed=valid and heartbeat_fresh and all(p['below_threshold'] for p in plans)
    blocked_reason=reason or ('VPS 心跳过期' if not heartbeat_fresh else 'TCP 未低于全部计划阈值' if plans and not passed else '')
    return dict(valid=valid,reason=reason,sample_age_s=now-stamp if type(stamp)is int else None,
                heartbeat_fresh=heartbeat_fresh,blocked_reason=blocked_reason,
                plans=plans,passes_tcp_gate=bool(passed) if plans else None)

def record(db,sid,metrics,now):
    info=gate(db,sid,metrics,now)
    addresses=list(metrics.get('public_ips') or [])
    source='interface' if addresses else 'unknown'
    stamp=metrics.get('egress_checked')
    if not addresses and type(stamp)is int and 0<=now-stamp<=90:
        addresses=list(metrics.get('egress_ips') or []);source='egress' if addresses else 'unknown'
    db.execute('''INSERT OR IGNORE INTO tcp_samples(server_id,received_at,sampled_at,tcp,valid,reason,addresses,address_source,ports,context)
      VALUES(?,?,?,?,?,?,?,?,?,?)''',(sid,now,metrics.get('connections_sampled'),metrics.get('tcp'),int(info['valid']),info['reason'],
      json.dumps(addresses),source,json.dumps(metrics.get('tcp_by_port') or {}),json.dumps(info['plans'])))
    db.execute('DELETE FROM tcp_samples WHERE id IN (SELECT id FROM tcp_samples WHERE received_at<? ORDER BY received_at LIMIT 2000)',(now-RETENTION_S,))

def history(db,sid,args,now):
    try:
        start=int(args.get('from',now-3600));end=int(args.get('until',now))
        limit=int(args.get('limit',200));before=int(args.get('before_id',2**63-1))
        if not 0<=start<=end<=now or end-start>RETENTION_S or not 1<=limit<=2000 or not 0<before<=2**63-1:raise ValueError()
        address=args.get('ip','').strip()
        if address:address=str(ipaddress.ip_address(address))
    except (ValueError,TypeError):raise ValueError('时间范围、IP 或分页参数无效；单次最多查询 7 天、2000 条')
    start=max(start,now-RETENTION_S)
    sql='SELECT * FROM tcp_samples t WHERE server_id=? AND received_at BETWEEN ? AND ? AND id<?'
    params=[sid,start,end,before]
    if address:
        sql+=' AND EXISTS(SELECT 1 FROM json_each(t.addresses) WHERE value=?)';params.append(address)
    rows=db.execute(sql+' ORDER BY id DESC LIMIT ?',(*params,limit+1)).fetchall()
    more=len(rows)>limit;points=[]
    for row in rows[:limit]:
        d=dict(row);d['valid']=bool(d['valid'])
        for key in ('addresses','ports','context'):d[key]=json.loads(d[key])
        points.append(d)
    return dict(points=points,has_more=more,next_before_id=points[-1]['id'] if more else None,
                now=now,retention_s=RETENTION_S,from_time=start,until=end,
                attribution='VPS 整机 TCP 总数，关联上报时观察到的 IP；不是单个 IP 独立连接数。IP 变化与 TCP 采样时间可能存在偏差。',
                recording_started_at=db.execute('SELECT MIN(received_at) FROM tcp_samples WHERE server_id=?',(sid,)).fetchone()[0])
