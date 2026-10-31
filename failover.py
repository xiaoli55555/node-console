"""Optional primary-host outage failover; DNS leases isolate it from IP sync."""
import json
import time
from ip_dns import IntegrationError, load_connection, get_dns_record, validate_dns_record, update_dns_record

SCHEMA='''
CREATE TABLE IF NOT EXISTS vps_failover_leases(
 binding_id INTEGER PRIMARY KEY REFERENCES dns_bindings(id) ON DELETE RESTRICT,
 rotation_id INTEGER NOT NULL REFERENCES vps_rotations(id) ON DELETE RESTRICT,
 original_ip TEXT NOT NULL,
 current_ip TEXT NOT NULL,
 target_ip TEXT,
 intent TEXT,
 updated INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS failover_rotation ON vps_failover_leases(rotation_id);
CREATE TABLE IF NOT EXISTS vps_failover_probe_state(
 rotation_id INTEGER PRIMARY KEY REFERENCES vps_rotations(id) ON DELETE CASCADE,
 server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE RESTRICT,
 original_plan TEXT,original_monitor TEXT,active INTEGER NOT NULL DEFAULT 0,
 signature TEXT,activated_at INTEGER,run_floor INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vps_failover_probe_costs(
 run_id INTEGER PRIMARY KEY REFERENCES detection_runs(id) ON DELETE CASCADE,
 primary_server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE
);
'''


def initialize(db):
    columns={r[1] for r in db.execute('PRAGMA table_info(vps_rotations)')}
    for name,definition in [('failover_server_id','INTEGER REFERENCES servers(id) ON DELETE RESTRICT'),('failover_binding_ids',"TEXT NOT NULL DEFAULT '[]'"),('failover_recovery_s','INTEGER NOT NULL DEFAULT 60'),('failover_healthy_since','INTEGER'),('failover_status',"TEXT NOT NULL DEFAULT '未配置 A 故障转移'")]:
        if name not in columns:db.execute(f'ALTER TABLE vps_rotations ADD COLUMN {name} {definition}')
    db.executescript(SCHEMA)
    import server_failover
    server_failover.initialize(db)
    for r in db.execute('SELECT * FROM vps_rotations WHERE failover_server_id IS NOT NULL').fetchall():
        state=_remember_probe(db,r['id'],r['failover_server_id'])
        if not state['active']:db.execute("UPDATE detection_plans SET automatic=0,action_enabled=0,status='冷备用待命，不运行拨测' WHERE server_id=?",(r['failover_server_id'],))


def guarded(db,bid):
    exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_failover_leases'").fetchone()
    import server_failover
    return bool(exists and db.execute('SELECT 1 FROM vps_failover_leases WHERE binding_id=?',(bid,)).fetchone()) or bool(server_failover.exists(db) and db.execute('SELECT 1 FROM server_failover_leases WHERE binding_id=?',(bid,)).fetchone())


def reserved(db,sid):
    exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_failover_leases'").fetchone()
    import server_failover
    return bool(exists and db.execute('SELECT 1 FROM vps_rotations r WHERE r.failover_server_id=?',(sid,)).fetchone()) or server_failover.reserved(db,sid)


def probe_active(db,sid):
    import server_failover
    r=server_failover.parent(db,sid,active=True)
    if r:
        p=db.execute('SELECT p.automatic,s.enabled,m.enabled AS monitor_enabled FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(r['server_id'],)).fetchone()
        return bool(p and p['automatic'] and p['enabled'] and p['monitor_enabled'])
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_failover_probe_state'").fetchone():return False
    return bool(db.execute('SELECT 1 FROM vps_failover_probe_state s JOIN vps_rotations r ON r.id=s.rotation_id JOIN detection_plans p ON p.server_id=r.primary_server_id JOIN detection_sources d ON d.id=p.source_id JOIN ip_monitors m ON m.server_id=r.primary_server_id WHERE s.server_id=? AND s.active=1 AND p.automatic=1 AND d.enabled=1 AND m.enabled=1',(sid,)).fetchone())


def probe_blocked(db,sid):
    return reserved(db,sid) and not probe_active(db,sid)


def parent_probe_suspended(db,sid,now):
    import rotation as rot
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_failover_probe_state'").fetchone():return False
    r=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? AND failover_server_id IS NOT NULL',(sid,)).fetchone()
    return bool(r and rot._offline(db,sid,now,r['offline_after_s']))


def budget_primary(db,sid):
    import server_failover
    r=server_failover.parent(db,sid,active=True)
    if r:return r['server_id']
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_failover_probe_state'").fetchone():return sid
    row=db.execute('SELECT r.primary_server_id FROM vps_failover_probe_state s JOIN vps_rotations r ON r.id=s.rotation_id WHERE s.server_id=? AND s.active=1',(sid,)).fetchone()
    return row['primary_server_id'] if row else sid


def _remember_probe(db,rid,sid):
    state=db.execute('SELECT * FROM vps_failover_probe_state WHERE rotation_id=?',(rid,)).fetchone()
    if state:return state
    plan=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
    monitor=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
    db.execute('INSERT INTO vps_failover_probe_state(rotation_id,server_id,original_plan,original_monitor) VALUES(?,?,?,?)',(rid,sid,json.dumps(dict(plan)) if plan else None,json.dumps(dict(monitor)) if monitor else None))
    return db.execute('SELECT * FROM vps_failover_probe_state WHERE rotation_id=?',(rid,)).fetchone()


def _restore_row(db,table,sid,payload,paused):
    if payload is None:
        db.execute('DELETE FROM '+table+' WHERE server_id=?',(sid,));return
    values=json.loads(payload)
    if table=='detection_plans' and paused:values.update(automatic=0,action_enabled=0,status='冷备用待命，不运行拨测')
    # Monitoring observations stay current; only restore the original settings.
    if table=='ip_monitors':values={k:values[k] for k in ('server_id','source_id','port','enabled')}
    keys=list(values)
    db.execute('INSERT INTO '+table+'('+','.join(keys)+') VALUES('+','.join('?' for _ in keys)+') ON CONFLICT(server_id) DO UPDATE SET '+','.join(k+'=excluded.'+k for k in keys if k!='server_id'),[values[k] for k in keys])


def stop_probe(db,rid,remove=False):
    state=db.execute('SELECT * FROM vps_failover_probe_state WHERE rotation_id=?',(rid,)).fetchone()
    if not state:return
    sid=state['server_id']
    if state['active']:
        db.execute("UPDATE detection_runs SET status='接管结束，停止后续拨测' WHERE server_id=? AND id>? AND status IN ('creating','pending','queued','issued')",(sid,state['run_floor']))
        db.execute("UPDATE commands SET status='cancelled',updated=? WHERE server_id=? AND status='queued' AND id IN (SELECT action_command_id FROM detection_runs WHERE server_id=? AND id>?)",(int(time.time()),sid,sid,state['run_floor']))
        db.execute("UPDATE detection_runs SET action_status='cancelled',action_result='已切回 A；停止 C 后续动作和重试，已发出的请求不可撤回' WHERE server_id=? AND id>? AND action_status IN ('queued','issued','submitted','uncertain','verifying')",(sid,state['run_floor']))
    _restore_row(db,'detection_plans',sid,state['original_plan'],not remove)
    _restore_row(db,'ip_monitors',sid,state['original_monitor'],False)
    if remove:db.execute('DELETE FROM vps_failover_probe_state WHERE rotation_id=?',(rid,))
    else:db.execute('UPDATE vps_failover_probe_state SET active=0,signature=NULL,activated_at=NULL WHERE rotation_id=?',(rid,))


def standby_ready(db,cipher,r,sid,now):
    import rotation as rot
    from ip_dns import candidate_ip,public_v4
    if not rot._owned_server(db,sid,r['owner_id']):raise IntegrationError('故障转移 VPS 不属于该计划的客户')
    node=db.execute('SELECT seen FROM servers WHERE id=?',(sid,)).fetchone()
    if not node or not node['seen'] or not 0<=now-node['seen']<r['offline_after_s']:raise IntegrationError('故障转移 VPS 心跳已超时')
    if rot._pending_action(db,sid):raise IntegrationError('故障转移 VPS 有未结束的重启或换 IP 动作')
    address=public_v4(candidate_ip(db,{'server_id':sid,'source_id':None},cipher))
    monitor=db.execute('SELECT port FROM ip_monitors WHERE server_id=?',(r['primary_server_id'],)).fetchone()
    if not monitor:raise IntegrationError('主 VPS A 尚未配置检测端口')
    try:
        with rot.socket.create_connection((address,monitor['port']),timeout=4):pass
    except OSError:raise IntegrationError('冷备用业务端口不可达') from None
    return address,monitor['port']


def _activate_probe(db,cipher,r,now):
    import rotation as rot
    sid=r['failover_server_id']
    if not rot._owned_server(db,sid,r['owner_id']):raise IntegrationError('故障转移 VPS 归属已变化')
    try:a=probe_config(db,r['primary_server_id'],r['owner_id'])
    except IntegrationError:
        db.execute("UPDATE detection_plans SET automatic=0,action_enabled=0,status='A 的检测配置已暂停，继承拨测暂停' WHERE server_id=?",(sid,));raise
    state=_remember_probe(db,r['id'],sid)
    old=json.loads(state['original_plan']) if state['original_plan'] else {}
    response=a['response_mode'];action=None
    if response=='change_api':
        owner=None if rot._admin_user(db,r['owner_id']) else r['owner_id']
        candidates=db.execute("SELECT * FROM ip_connections WHERE kind='change_ip' AND (id=? OR server_id=?) ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END,id DESC",(old.get('action_connection_id'),sid,old.get('action_connection_id'))).fetchall()
        for candidate in candidates:
            if candidate['id']==a['action_connection_id']:continue
            if candidate['owner_id']==owner and (owner is None or candidate['server_id']==sid):action=candidate['id'];break
        if action is None:response='none'
    signature=json.dumps([a['source_id'],a['nodes'],a['interval_s'],a['daily_limit'],a['failure_threshold'],a['monitor_port'],response,action,a['action_enabled']])
    current=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
    monitor=db.execute('SELECT port,enabled FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
    if state['active'] and state['signature']==signature and current and monitor and current['automatic'] and monitor['enabled'] and current['source_id']==a['source_id'] and current['nodes']==a['nodes'] and monitor['port']==a['monitor_port']:return state
    floor=db.execute('SELECT COALESCE(MAX(id),0) FROM detection_runs WHERE server_id=?',(sid,)).fetchone()[0]
    db.execute("INSERT INTO ip_monitors(server_id,port,enabled,source_id) VALUES(?,?,1,?) ON CONFLICT(server_id) DO UPDATE SET port=excluded.port,enabled=1",(sid,a['monitor_port'],json.loads(state['original_monitor']).get('source_id') if state['original_monitor'] else None))
    db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,daily_limit,next_at,response_mode,action_connection_id,failure_threshold,owner_id,action_enabled,status,action_after_run) VALUES(?,?,?,?,1,?,?,?,?,?,?,?,'继承 A 配置，等待首次拨测',?) ON CONFLICT(server_id) DO UPDATE SET source_id=excluded.source_id,nodes=excluded.nodes,interval_s=excluded.interval_s,automatic=1,daily_limit=excluded.daily_limit,next_at=excluded.next_at,response_mode=excluded.response_mode,action_connection_id=excluded.action_connection_id,failure_threshold=excluded.failure_threshold,owner_id=excluded.owner_id,action_enabled=excluded.action_enabled,status=excluded.status,action_after_run=excluded.action_after_run,failure_streak=0,failure_ip=NULL,failure_port=NULL",(sid,a['source_id'],a['nodes'],a['interval_s'],a['daily_limit'],now,response,action,a['failure_threshold'],r['owner_id'],int(bool(a['action_enabled']) and response!='none'),floor))
    db.execute('UPDATE vps_failover_probe_state SET active=1,signature=?,activated_at=?,run_floor=? WHERE rotation_id=?',(signature,now,floor,r['id']))
    return db.execute('SELECT * FROM vps_failover_probe_state WHERE rotation_id=?',(r['id'],)).fetchone()


def backup_ready(db,cipher,r,now):
    import rotation as rot
    sid=r['failover_server_id'];state=db.execute('SELECT * FROM vps_failover_probe_state WHERE rotation_id=?',(r['id'],)).fetchone()
    plan=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
    run=db.execute("SELECT * FROM detection_runs WHERE server_id=? AND status NOT IN ('creating','pending','queued','issued') ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
    if not state or not state['active'] or not plan or not run or run['id']<=state['run_floor'] or run['source_id']!=plan['source_id'] or run['nodes']!=plan['nodes'] or run['created']<state['activated_at']:raise IntegrationError('等待 C 使用 A 的探测点完成本次接管拨测，旧结果不可复用')
    return rot._fixed_ready(db,cipher,r,sid,now,verified_candidate=run['ip'])


def probe_config(db,sid,uid):
    import rotation as rot
    if not rot._owned_server(db,sid,uid):raise IntegrationError('故障转移 VPS 不属于该计划的客户')
    p=db.execute('SELECT p.*,s.owner_id AS source_owner,s.server_id AS source_server,s.enabled AS source_enabled,m.enabled AS monitor_enabled,m.port AS monitor_port FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(sid,)).fetchone()
    if not p or not p['automatic'] or not p['source_enabled'] or not p['monitor_enabled']:raise IntegrationError('故障转移 VPS 需要启用 IP 监控和所选检测点的定时探测')
    if rot._admin_user(db,uid):
        if p['source_owner'] is not None or p['owner_id'] not in (None,uid):raise IntegrationError('后台故障转移必须使用后台探测来源')
    elif p['owner_id']!=uid or p['source_owner']!=uid or p['source_server']!=sid:raise IntegrationError('故障转移 VPS 必须使用该客户、该 VPS 的专属探测来源')
    return p


def configure(db,cipher,rid,body,now):
    import rotation as rot
    r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
    sid=body.get('failover_server_id',r['failover_server_id'])
    ids=[x[0] for x in db.execute('SELECT id FROM dns_bindings WHERE server_id=? ORDER BY id',(r['primary_server_id'],))] if sid is not None else []
    requested=body.get('failover_binding_ids')
    if sid is not None and requested is not None and (not isinstance(requested,list) or any(type(x)is not int for x in requested) or set(requested)!=set(ids)):raise IntegrationError('A 故障转移接替 A 的全部绑定解析，不支持只选择部分记录')
    recovery=body.get('failover_recovery_s',r['failover_recovery_s'])
    if sid is not None and (type(sid)is not int or sid in (r['primary_server_id'],r['other_server_id'])):raise IntegrationError('A 故障转移 VPS 必须是不同于 A、B 的第三台机器')
    if not isinstance(ids,list) or len(ids)>5000 or any(type(x)is not int or x<1 for x in ids) or len(ids)!=len(set(ids)):raise IntegrationError('故障转移解析记录选择无效')
    if type(recovery)is not int or not 15<=recovery<=3600:raise IntegrationError('A 恢复稳定等待时间必须为 15～3600 秒')
    if sid is None:ids=[]
    old_ids=json.loads(r['failover_binding_ids'])
    changed=sid!=r['failover_server_id'] or set(ids)!=set(old_ids) or recovery!=r['failover_recovery_s']
    leases=db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=?',(rid,)).fetchone()
    if leases and changed:raise IntegrationError('故障转移记录尚未切回 A，不能修改或移除故障转移配置')
    if sid is not None:
        import server_failover
        if server_failover.exists(db) and db.execute('SELECT 1 FROM server_failovers WHERE server_id IN (?,?) OR backup_id=? OR (cold=1 AND backup_id IN (?,?))',(sid,r['primary_server_id'],sid,r['primary_server_id'],r['other_server_id'])).fetchone():raise IntegrationError('A/B 或备用机已配置单机故障转移，请先移除冲突配置')
        if not ids:raise IntegrationError('A 尚未绑定解析记录，无法启用故障转移')
        probe_config(db,r['primary_server_id'],r['owner_id'])
        if rot._pending_action(db,sid):raise IntegrationError('故障转移 VPS 有未结束的重启或换 IP 动作')
        conflict=db.execute('SELECT 1 FROM vps_rotations WHERE id<>? AND (enabled=1 OR failover_server_id IS NOT NULL OR phase<>\'active\' OR dns_intent IS NOT NULL OR EXISTS(SELECT 1 FROM vps_failover_leases l WHERE l.rotation_id=vps_rotations.id)) AND (primary_server_id IN (?,?) OR other_server_id IN (?,?) OR failover_server_id IN (?,?,?))',(rid,sid,r['primary_server_id'],sid,r['other_server_id'],sid,r['primary_server_id'],r['other_server_id'])).fetchone()
        if conflict:raise IntegrationError('故障转移 VPS 或 A/B 已被其他活动轮换任务占用')
        ip,port=standby_ready(db,cipher,r,sid,now)
        if ip in {rot._fresh_ip(db,x,now,cipher)[0] for x in (r['primary_server_id'],r['other_server_id'])}:raise IntegrationError('故障转移 VPS 的公网 IP 不能与 A/B 相同')
        owner=None if rot._admin_user(db,r['owner_id']) else r['owner_id']
        for bid in ids:
            row=db.execute('SELECT b.*,c.owner_id AS credential_owner,c.server_id AS credential_server FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE b.id=?',(bid,)).fetchone()
            if not row or row['server_id']!=r['primary_server_id'] or row['credential_owner']!=owner or (owner is not None and row['credential_server']!=r['primary_server_id']):raise IntegrationError('只能选择主 VPS A 在当前管理员/客户范围内的解析绑定')
            try:
                with rot.socket.create_connection((ip,row['port']),timeout=4):pass
            except OSError:raise IntegrationError('故障转移 VPS 未提供 A 解析所需的业务端口：'+str(row['port'])) from None
            other=db.execute('SELECT 1 FROM vps_rotations WHERE id<>? AND binding_id=?',(rid,bid)).fetchone()
            if other:raise IntegrationError('所选记录已由其他轮换任务管理')
    if r['failover_server_id']!=sid:stop_probe(db,rid,remove=True)
    if sid is not None:
        state=_remember_probe(db,rid,sid)
        if not state['active']:db.execute("UPDATE detection_plans SET automatic=0,action_enabled=0,status='冷备用待命，不运行拨测' WHERE server_id=?",(sid,))
    db.execute('UPDATE vps_rotations SET failover_server_id=?,failover_binding_ids=?,failover_recovery_s=?,failover_healthy_since=CASE WHEN ? THEN NULL ELSE failover_healthy_since END,failover_status=CASE WHEN ? THEN ? ELSE failover_status END WHERE id=?',(sid,json.dumps(sorted(ids)),recovery,int(changed),int(changed),'A 故障转移待命' if sid else '未配置 A 故障转移',rid))


def _status(db,rid,message,now):
    import rotation as rot
    old=db.execute('SELECT failover_status FROM vps_rotations WHERE id=?',(rid,)).fetchone()
    db.execute('UPDATE vps_rotations SET failover_status=?,status=?,updated=? WHERE id=?',(message,message,now,rid))
    if old and old['failover_status']!=message:rot._event(db,rid,None,message,now)


def _move(connect,cipher,rid,bid,target,now,restore=False):
    """Hold the same per-binding lock used by ordinary IP sync across the write."""
    import fcntl
    from pathlib import Path
    with connect() as db:path=db.execute('PRAGMA database_list').fetchone()[2]
    with open(str(Path(path).with_suffix('.dns.lock')),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        with connect() as db:
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
            b=db.execute('SELECT * FROM dns_bindings WHERE id=?',(bid,)).fetchone()
            if not b:raise IntegrationError('故障转移解析绑定已不存在')
            import rotation as rot
            try:
                with rot.socket.create_connection((target,b['port']),timeout=4):pass
            except OSError:raise IntegrationError('接替目标业务端口不可达：'+str(b['port'])) from None
            lease=db.execute('SELECT * FROM vps_failover_leases WHERE binding_id=?',(bid,)).fetchone()
            if lease and lease['rotation_id']!=rid:raise IntegrationError('记录已由另一故障转移任务占用')
            if lease and lease['intent']:raise IntegrationError('此前 DNS 动作结果待核对')
            conn=load_connection(db,cipher,b['connection_id']);record=get_dns_record(conn,b)
            validate_dns_record(record,b,conn)
            if lease is None:
                db.execute('INSERT INTO vps_failover_leases(binding_id,rotation_id,original_ip,current_ip,updated) VALUES(?,?,?,?,?)',(bid,rid,b['expected_ip'],b['expected_ip'],now))
            payload={'restore':bool(restore),'target_server':r['primary_server_id'] if restore else r['failover_server_id']}
            db.execute('UPDATE vps_failover_leases SET target_ip=?,intent=?,updated=? WHERE binding_id=?',(target,json.dumps(payload),now,bid))
            db.commit() # Claim before external I/O; crashes are reconciled by readback.
            if b['expected_ip']!=target:update_dns_record(conn,b,record,target)
            updated=get_dns_record(conn,b);validate_dns_record(updated,dict(b,expected_ip=target),conn)
            _finish(db,r,b,target,restore,now)


def _finish(db,r,b,target,restore,now):
    message=('A 恢复，解析已切回 ' if restore else 'A 下线，解析已由故障转移 VPS 接替：')+target
    db.execute('UPDATE dns_bindings SET expected_ip=?,candidate=NULL,candidate_since=NULL,status=?,updated=? WHERE id=?',(target,message,now,b['id']))
    import rotation as rot
    rot._event(db,r['id'],r['primary_server_id'] if restore else r['failover_server_id'],'解析 #'+str(b['id'])+'：'+message,now)
    if restore:
        db.execute('DELETE FROM vps_failover_leases WHERE binding_id=?',(b['id'],))
        if b['id']==r['binding_id']:
            # Preserve a B repair in flight; never relabel it as completed.
            if r['drain_server_id']==r['primary_server_id']:
                db.execute("UPDATE vps_rotations SET active_server_id=?,phase='active',drain_server_id=NULL,old_ip=NULL,new_ip=NULL,action_started=NULL,emergency=0,low_samples=0,next_switch_at=? WHERE id=?",(r['primary_server_id'],now+r['interval_s'],r['id']))
            else:db.execute('UPDATE vps_rotations SET active_server_id=? WHERE id=?',(r['primary_server_id'],r['id']))
    else:db.execute('UPDATE vps_failover_leases SET current_ip=?,target_ip=NULL,intent=NULL,updated=? WHERE binding_id=?',(target,now,b['id']))


def _reconcile(connect,cipher,rid,now):
    with connect() as db:
        leases=db.execute('SELECT binding_id FROM vps_failover_leases WHERE rotation_id=? AND intent IS NOT NULL',(rid,)).fetchall()
    for item in leases:
        with connect() as db:
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
            lease=db.execute('SELECT * FROM vps_failover_leases WHERE binding_id=?',(item['binding_id'],)).fetchone()
            b=db.execute('SELECT * FROM dns_bindings WHERE id=?',(item['binding_id'],)).fetchone()
            conn=load_connection(db,cipher,b['connection_id']);record=get_dns_record(conn,b)
            actual=record.get('content',record.get('Value'))
            validate_dns_record(record,dict(b,expected_ip=actual),conn)
            if actual!=lease['target_ip']:
                _status(db,rid,'故障转移 DNS 结果未确认，保持占用并暂停轮换；需要核对供应商记录',now)
                return False
            intent=json.loads(lease['intent']);_finish(db,r,b,actual,intent['restore'],now)
    return True


def step(connect,cipher,rid,now):
    """True freezes A/B scheduling while primary outage failover is active."""
    import rotation as rot
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not r or not r['failover_server_id']:return False
        leases=db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=?',(rid,)).fetchone()
        if not rot._owned_server(db,r['primary_server_id'],r['owner_id']):raise IntegrationError('主 VPS 归属已变化，故障转移暂停')
        offline=rot._offline(db,r['primary_server_id'],now,r['offline_after_s'])
        protecting_change=(r['active_server_id']==r['other_server_id'] and r['drain_server_id']==r['primary_server_id'] and r['phase'] in ('draining','waiting_ip','waiting_probe'))
        if protecting_change and not offline and r['phase'] in ('waiting_ip','waiting_probe'):
            try:
                address,_,_=rot._fresh_ip(db,r['primary_server_id'],now,cipher)
                if address!=r['old_ip']:
                    rot._fixed_ready(db,cipher,dict(r,phase='active',drain_server_id=None),r['primary_server_id'],now,verified_candidate=address)
                    protecting_change=False
            except IntegrationError:pass
        down=offline or protecting_change
        if not down and not leases:
            stop_probe(db,rid)
            if r['failover_status'].startswith('A 心跳超时'):_status(db,rid,'A 已在线，故障转移待命',now)
            return False
        if r['dns_intent']:
            db.commit();rot._reconcile_fixed_dns(connect,cipher,rid,now)
            return True
    if not _reconcile(connect,cipher,rid,now):return True
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        lease_rows=db.execute('SELECT * FROM vps_failover_leases WHERE rotation_id=?',(rid,)).fetchall()
        ids=[x[0] for x in db.execute('SELECT id FROM dns_bindings WHERE server_id=? ORDER BY id',(r['primary_server_id'],))]
        if not down and not lease_rows:
            db.execute('UPDATE vps_rotations SET failover_healthy_since=NULL WHERE id=?',(rid,))
            stop_probe(db,rid)
            _status(db,rid,'A 已恢复，故障转移解析已切回；恢复 A/B 轮换',now);return True
        if down:
            db.execute('UPDATE vps_rotations SET failover_healthy_since=NULL WHERE id=?',(rid,))
            try:
                _activate_probe(db,cipher,r,now)
                rot._request_probe(db,r['failover_server_id'],now)
                if rot._offline(db,r['failover_server_id'],now,r['offline_after_s']):raise IntegrationError('故障转移 VPS 心跳已超时')
                address,port,_=backup_ready(db,cipher,r,now)
            except IntegrationError as e:
                _status(db,rid,'A 心跳超时；故障转移 VPS 不可接替：'+str(e),now);return True
            if r['active_server_id']==r['primary_server_id']:
                ids=list(set(ids+[r['binding_id']]))
            elif r['binding_id'] in ids:ids.remove(r['binding_id'])
            # A healthy B keeps mobile; a failed/unknown B can hand it to C.
            if r['active_server_id']==r['other_server_id']:
                rot._request_probe(db,r['other_server_id'],now)
                try:
                    if rot._offline(db,r['other_server_id'],now,r['offline_after_s']):raise IntegrationError('B 心跳超时')
                    rot._fixed_ready(db,cipher,r,r['other_server_id'],now)
                except IntegrationError:
                    if rot._offline(db,r['other_server_id'],now,r['offline_after_s']) or rot._fixed_failure(db,r['other_server_id'],now):ids=list(set(ids+[r['binding_id']]))
            work=[]
            for bid in ids:
                lease=next((x for x in lease_rows if x['binding_id']==bid),None)
                if lease and lease['current_ip']==address:continue
                binding=db.execute('SELECT * FROM dns_bindings WHERE id=? AND server_id=?',(bid,r['primary_server_id'])).fetchone()
                if not binding:raise IntegrationError('故障转移记录绑定已变化，请检查配置')
                if not lease and bid!=r['binding_id']:
                    owner=None if rot._admin_user(db,r['owner_id']) else r['owner_id']
                    credential=db.execute('SELECT owner_id,server_id FROM ip_connections WHERE id=?',(binding['connection_id'],)).fetchone()
                    if not credential or credential['owner_id']!=owner or (owner is not None and credential['server_id']!=r['primary_server_id']):raise IntegrationError('故障转移凭据归属不一致')
                work.append(bid)
            db.commit()
            for bid in work:_move(connect,cipher,rid,bid,address,now)
            with connect() as saved:_status(saved,rid,'A 心跳超时，A 的全部解析由故障转移 VPS 接替（健康 B 的所选轮换记录保持 B）；A/B 定时动作暂停' if offline else 'A 换 IP 期间，其他解析由故障转移 VPS 接替；轮换记录保持健康 B',now)
            return bool(offline)
        # A returned: verify selected nodes and current IP, then apply hysteresis.
        rot._request_probe(db,r['primary_server_id'],now)
        try:
            current_ip,_,_=rot._fresh_ip(db,r['primary_server_id'],now,cipher)
            ready_plan=r
            if r['phase'] in ('waiting_ip','waiting_probe') and r['drain_server_id']==r['primary_server_id'] and current_ip!=r['old_ip']:
                ready_plan=dict(r,phase='active',drain_server_id=None)
            address,_,_=rot._fixed_ready(db,cipher,ready_plan,r['primary_server_id'],now,verified_candidate=current_ip)
        except IntegrationError as e:
            db.execute('UPDATE vps_rotations SET failover_healthy_since=NULL WHERE id=?',(rid,))
            _status(db,rid,'A 已上报，仍等待所选检测点和动作状态确认：'+str(e),now);return True
        since=r['failover_healthy_since']
        if since is None:
            db.execute('UPDATE vps_rotations SET failover_healthy_since=? WHERE id=?',(now,rid));since=now
        c_healthy=True
        try:
            if rot._offline(db,r['failover_server_id'],now,r['offline_after_s']):raise IntegrationError('故障转移 VPS 心跳超时')
            backup_ready(db,cipher,r,now)
        except IntegrationError:c_healthy=False
        if c_healthy and now-since<r['failover_recovery_s']:
            _status(db,rid,'A 已通过所选检测点，等待恢复稳定窗口后切回',now);return True
        db.commit()
        for lease in lease_rows:_move(connect,cipher,rid,lease['binding_id'],address,now,restore=True)
        with connect() as saved:
            saved.execute('UPDATE vps_rotations SET failover_healthy_since=NULL WHERE id=?',(rid,))
            stop_probe(saved,rid)
            _status(saved,rid,'A 已恢复，故障转移解析已切回；恢复 A/B 轮换',now)
        return True
