"""Revocable, expiring, read-only operational snapshots; no provider calls."""
import hashlib
import json
import secrets
import re
import rotation_audit
import tcp_history
import time
from flask import jsonify, request

PATH='/api/monitor/snapshot'
SCHEMA='''CREATE TABLE IF NOT EXISTS monitor_tokens(
 id INTEGER PRIMARY KEY CHECK(id=1),token_hash TEXT NOT NULL,created INTEGER NOT NULL,
 expires INTEGER NOT NULL);'''


def initialize(connect):
    with connect() as db:db.executescript(SCHEMA)


def pick(row,fields):return {key:row[key] for key in fields.split()}


def parsed(value,default):
    try:return json.loads(value or '')
    except (ValueError,TypeError):return default


def category(value):
    # Never expose free-form provider errors or logs: they can contain secrets.
    text=value or ''
    for key,words in [('probe_stale',('结果过期','探测过期')),('heartbeat_stale',('心跳超时','心跳已超时')),
                      ('dns_pending',('DNS 写入','DNS 切换','DNS 自动纠正','解析待核对')),
                      ('group_split',('线路状态不一致',)),('group_coordination',('多记录协调',)),('probe_disabled',('请开启定时探测',)),
                      ('failed',('失败','错误')),('waiting',('等待','暂缓')),('recovered',('恢复正常','恢复完成')),
                      ('dns_corrected',('已纠正 DNS','历史分叉线路已核对')),('dns_switched',('DNS 已从',))]:
        if any(word in text for word in words):return key
    return 'other'


def snapshot(db,now,after_id,dns_after_id,filters=None):
    from rotation_schedule import effective
    db.execute('PRAGMA query_only=ON')
    servers=[]
    for row in db.execute('SELECT id,name,metrics,seen FROM servers ORDER BY id'):
        metrics=parsed(row['metrics'],{})
        if not isinstance(metrics,dict):metrics={}
        last=db.execute('SELECT id,ip,port,status,created,updated,details FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1',(row['id'],)).fetchone()
        probe=pick(last,'id ip port status created updated') if last else None
        if probe is not None:
            details=parsed(last['details'],[])
            probe['nodes']=[{k:d[k] for k in ('node_id','state','latency_ms') if k in d} for d in details if isinstance(d,dict) and d.get('state') in ('reachable','unreachable','unknown')] if isinstance(details,list) else []
        plan=db.execute('SELECT automatic,interval_s,next_at,checked FROM detection_plans WHERE server_id=?',(row['id'],)).fetchone()
        monitor=db.execute('SELECT current_ip,previous_ip,port,checked FROM ip_monitors WHERE server_id=?',(row['id'],)).fetchone()
        sample=db.execute('SELECT id,received_at,sampled_at,valid FROM tcp_samples WHERE server_id=? ORDER BY id DESC LIMIT 1',(row['id'],)).fetchone() if db.execute("SELECT 1 FROM sqlite_master WHERE name='tcp_samples'").fetchone() else None
        servers.append(dict(pick(row,'id name seen'),tcp_gate=tcp_history.gate(db,row['id'],metrics,now,seen=row['seen']),tcp_history_latest=dict(sample) if sample else None,heartbeat_age_s=max(0,now-row['seen']) if row['seen'] else None,
                            metrics={k:metrics.get(k) if type(metrics.get(k)) in (int,float) else None for k in ('cpu_percent','memory_percent','tcp','connections_sampled','uptime')},
                            monitor=dict(monitor) if monitor else None,probe=probe,probe_plan=dict(plan) if plan else None))
    rotations=[]
    for row in db.execute('SELECT * FROM vps_rotations ORDER BY id'):
        data=pick(row,'id primary_server_id other_server_id binding_id active_server_id enabled mode phase next_switch_at drain_server_id drain_started drain_grace_s low_samples action_started action_attempts updated external_dns_check_at external_dns_pending failover_server_id')
        data.update(dns_write_pending=bool(row['dns_intent']),status_category=category(row['status']),drain_effective=effective(row,now))
        rotations.append(data)
    bindings=[]
    for row in db.execute('SELECT * FROM dns_bindings ORDER BY id'):
        bindings.append(dict(pick(row,'id server_id domain rr line expected_ip port automatic candidate candidate_since updated'),status_category=category(row['status'])))
    leases=[dict(pick(row,'binding_id rotation_id current_ip target_ip updated'),write_pending=bool(row['intent'])) for row in db.execute('SELECT * FROM vps_failover_leases ORDER BY binding_id')]
    clauses=[];params=[]
    for key,column,op in [('start_at','created','>='),('end_at','created','<='),('rotation_id','rotation_id','='),('server_id','server_id','=')]:
        if key in (filters or {}):clauses.append(column+op+'?');params.append(filters[key])
    if (filters or {}).get('incident_id'):
        clauses.append('id IN (SELECT event_id FROM rotation_audit WHERE incident_id=?)');params.append(filters['incident_id'])
    where=' WHERE '+' AND '.join(clauses) if clauses else ''
    def events_since(table,fields,cursor):
        columns=','.join(fields.split()+['message'])
        event_where=where if table=='vps_rotation_events' else ''
        event_params=list(params) if table=='vps_rotation_events' else []
        if cursor is None and not event_where:
            rows=list(reversed(db.execute('SELECT '+columns+' FROM '+table+' ORDER BY id DESC LIMIT 200').fetchall()))
        else:
            paged=event_where
            if cursor is not None:
                paged+=(' AND ' if paged else ' WHERE ')+'id>?';event_params.append(cursor)
            rows=db.execute('SELECT '+columns+' FROM '+table+paged+' ORDER BY id LIMIT 200',event_params).fetchall()
        items=[dict(pick(row,fields),kind=category(row['message'])) for row in rows]
        if table=='vps_rotation_events':
            for item in items:item['audit']=rotation_audit.read(db,item['id'])
        latest=db.execute('SELECT COALESCE(MAX(id),0) FROM '+table+event_where,params if table=='vps_rotation_events' else []).fetchone()[0]
        next_id=items[-1]['id'] if items else (cursor or 0)
        return items,next_id,latest,bool(items and next_id<latest)
    # Counts cover the entire selected interval, independent of page/cursor.
    stats_rows=db.execute("SELECT a.kind,json_extract(a.evidence,'$.trigger') AS trigger,COUNT(*) AS count FROM vps_rotation_events e LEFT JOIN rotation_audit a ON a.event_id=e.id WHERE e.id IN (SELECT id FROM vps_rotation_events"+where+") GROUP BY a.kind,trigger",params).fetchall()
    statistics=dict(scope='retained_events_matching_filters',filters=filters or {},unit='per_rotation_record',
                    event_count=sum(x['count'] for x in stats_rows),missing_evidence_count=sum(x['count'] for x in stats_rows if x['kind'] is None),
                    stages=[dict(x) for x in stats_rows if x['kind'] is not None])
    events,next_id,latest,more=events_since('vps_rotation_events','id rotation_id server_id created',after_id)
    dns_events,dns_next,dns_latest,dns_more=events_since('dns_events','id binding_id created',dns_after_id)
    commands=[]
    for row in db.execute("SELECT id,server_id,action,status,created,updated FROM commands WHERE status IN ('queued','issued','running') ORDER BY id"):
        commands.append(dict(pick(row,'id server_id status created updated'),action='reboot' if row['action']=='reboot' else 'other'))
    changes=[dict(row) for row in db.execute('SELECT id,server_id,observed FROM ip_events ORDER BY id DESC LIMIT 100')]
    return dict(schema_version=2,code_version=rotation_audit.code_version(),event_statistics=statistics,events_retained_since=db.execute('SELECT MIN(created) FROM vps_rotation_events').fetchone()[0],observed_at=now,dns_values_source='panel_last_confirmed_not_live_provider',
                servers=servers,rotations=rotations,dns_bindings=bindings,failover_leases=leases,
                pending_commands=commands,recent_ip_changes=changes,
                events=events,next_after_id=next_id,latest_event_id=latest,has_more_events=more,
                dns_events=dns_events,dns_next_after_id=dns_next,dns_latest_event_id=dns_latest,dns_has_more_events=dns_more)


def register(app,connect,auth,body,error,audit):
    @app.after_request
    def monitor_headers(response):
        if request.path in (PATH,'/api/admin/monitor-token'):
            response.headers['Cache-Control']='no-store'
            response.headers['Referrer-Policy']='no-referrer'
        return response

    @app.get('/api/admin/monitor-token')
    @auth(admin=True)
    def monitor_status():
        now=int(time.time())
        with connect() as db:row=db.execute('SELECT created,expires FROM monitor_tokens WHERE id=1').fetchone()
        return jsonify(path=PATH,scope='read_only_operations',enabled=bool(row and row['expires']>now),created=row['created'] if row else None,expires=row['expires'] if row else None)

    @app.post('/api/admin/monitor-token')
    @auth(admin=True)
    def monitor_issue():
        days=body().get('valid_days',90)
        if type(days)is not int or not 1<=days<=365:return error('有效期应为 1～365 天')
        token=secrets.token_urlsafe(40);now=int(time.time());expires=now+days*86400
        with connect() as db:
            db.execute('INSERT INTO monitor_tokens VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash,created=excluded.created,expires=excluded.expires',(hashlib.sha256(token.encode()).hexdigest(),now,expires))
            audit(db,'生成或轮换专用只读巡检密钥；旧密钥立即失效')
        return jsonify(token=token,path=PATH,expires=expires,scope='read_only_operations'),201

    @app.delete('/api/admin/monitor-token')
    @auth(admin=True)
    def monitor_revoke():
        with connect() as db:
            db.execute('DELETE FROM monitor_tokens WHERE id=1');audit(db,'撤销专用只读巡检密钥')
        return jsonify(ok=True)

    @app.get(PATH)
    def monitor_snapshot():
        header=request.headers.get('Authorization','')
        token=header[7:] if header.startswith('Bearer ') else ''
        if not 40<=len(token)<=200:return error('巡检密钥无效或已过期',401)
        now=int(time.time())
        with connect() as db:
            row=db.execute('SELECT token_hash,expires FROM monitor_tokens WHERE id=1').fetchone()
            if not row or row['expires']<=now or not secrets.compare_digest(row['token_hash'],hashlib.sha256(token.encode()).hexdigest()):
                return error('巡检密钥无效或已过期',401)
            cursors=[]
            for name in ('after_id','dns_after_id'):
                raw=request.args.get(name)
                if raw is not None and (not raw.isascii() or not raw.isdigit() or len(raw)>18):return error('事件游标无效')
                cursors.append(int(raw) if raw is not None else None)
            filters={}
            for name in ('start_at','end_at','rotation_id','server_id'):
                raw=request.args.get(name)
                if raw is not None:
                    if not raw.isascii() or not raw.isdigit() or len(raw)>18:return error('事件筛选无效')
                    filters[name]=int(raw)
            incident=request.args.get('incident_id')
            if incident is not None:
                if not re.fullmatch(r'[0-9]{1,18}:[0-9]{1,18}',incident):return error('事件关联编号无效')
                filters['incident_id']=incident
            if filters.get('start_at',0)>filters.get('end_at',2**63-1):return error('事件时间范围无效')
            return jsonify(snapshot(db,now,*cursors,filters=filters))
