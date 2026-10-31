"""Per-server cold standby, with durable DNS leases and pre-change admission."""
import fcntl
import json
import time
from pathlib import Path
from contextlib import contextmanager
from flask import g, jsonify
from ip_dns import IntegrationError, candidate_ip, public_v4, load_connection, get_dns_record, validate_dns_record, update_dns_record


@contextmanager
def config_lock(connect):
    with connect() as db:path=db.execute('PRAGMA database_list').fetchone()[2]
    with open(str(Path(path).with_suffix('.rotation.lock')),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        yield


def initialize(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS server_failovers(
      server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE RESTRICT,
      backup_id INTEGER NOT NULL UNIQUE REFERENCES servers(id) ON DELETE RESTRICT,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      recovery_s INTEGER NOT NULL DEFAULT 60, offline_s INTEGER NOT NULL DEFAULT 30,
      cold INTEGER NOT NULL DEFAULT 1,
      requested_at INTEGER, action_ip TEXT, healthy_since INTEGER, healthy_ip TEXT,
      active INTEGER NOT NULL DEFAULT 0, signature TEXT, activated_at INTEGER,
      run_floor INTEGER NOT NULL DEFAULT 0, original_plan TEXT, original_monitor TEXT,
      status TEXT NOT NULL DEFAULT '冷备用待命');
    CREATE TABLE IF NOT EXISTS server_failover_leases(
      binding_id INTEGER PRIMARY KEY REFERENCES dns_bindings(id) ON DELETE RESTRICT,
      server_id INTEGER NOT NULL REFERENCES server_failovers(server_id) ON DELETE RESTRICT,
      current_ip TEXT NOT NULL, target_ip TEXT, restoring INTEGER NOT NULL DEFAULT 0,
      updated INTEGER NOT NULL);
    ''')
    columns={r[1] for r in db.execute('PRAGMA table_info(server_failovers)')}
    for column,definition in [('cold','INTEGER NOT NULL DEFAULT 1'),('healthy_ip','TEXT')]:
        if column not in columns:db.execute('ALTER TABLE server_failovers ADD COLUMN '+column+' '+definition)


def exists(db):
    return bool(db.execute("SELECT 1 FROM sqlite_master WHERE name='server_failovers' AND type='table'").fetchone())


def reserved(db,sid):
    return exists(db) and bool(db.execute('SELECT 1 FROM server_failovers WHERE backup_id=? AND cold=1',(sid,)).fetchone())


def parent(db,sid,active=False):
    if not exists(db):return None
    return db.execute('SELECT * FROM server_failovers WHERE backup_id=? AND cold=1'+(' AND active=1' if active else ''),(sid,)).fetchone()


def bindings(db,sid):
    # The A/B scheduler owns its selected record throughout repairs. This engine
    # protects all remaining bindings, including records added after configuration.
    return db.execute('SELECT b.* FROM dns_bindings b WHERE b.server_id=? AND NOT EXISTS(SELECT 1 FROM vps_rotations r WHERE r.binding_id=b.id) ORDER BY b.id',(sid,)).fetchall()


def _pending(db,sid):
    return bool(db.execute("SELECT 1 FROM commands WHERE server_id=? AND action IN ('reboot','hkt_dhcp') AND status IN ('queued','issued','accepted','unconfirmed')",(sid,)).fetchone())


def _activate(db,r,now):
    import failover
    if not r['cold']:
        failover.probe_config(db,r['backup_id'],r['owner_id'])
        db.execute('UPDATE server_failovers SET active=1 WHERE server_id=?',(r['server_id'],))
        return
    p=failover.probe_config(db,r['server_id'],r['owner_id'])
    signature=json.dumps([p['source_id'],p['nodes'],p['interval_s'],p['daily_limit'],p['failure_threshold'],p['monitor_port']])
    current=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(r['backup_id'],)).fetchone()
    monitor=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(r['backup_id'],)).fetchone()
    if r['active'] and signature==r['signature'] and current and monitor and current['automatic'] and monitor['enabled'] and current['source_id']==p['source_id'] and current['nodes']==p['nodes'] and monitor['port']==p['monitor_port']:return
    floor=db.execute('SELECT COALESCE(MAX(id),0) FROM detection_runs WHERE server_id=?',(r['backup_id'],)).fetchone()[0]
    db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,?,1) ON CONFLICT(server_id) DO UPDATE SET port=excluded.port,enabled=1',(r['backup_id'],p['monitor_port']))
    db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,daily_limit,automatic,next_at,response_mode,action_enabled,owner_id,failure_threshold) VALUES(?,?,?,?,?,1,?,'none',0,?,?) ON CONFLICT(server_id) DO UPDATE SET source_id=excluded.source_id,nodes=excluded.nodes,interval_s=excluded.interval_s,daily_limit=excluded.daily_limit,automatic=1,next_at=excluded.next_at,response_mode='none',action_enabled=0,owner_id=excluded.owner_id,failure_threshold=excluded.failure_threshold,failure_streak=0",(r['backup_id'],p['source_id'],p['nodes'],p['interval_s'],p['daily_limit'],now,r['owner_id'],p['failure_threshold']))
    db.execute('UPDATE server_failovers SET active=1,signature=?,activated_at=?,run_floor=? WHERE server_id=?',(signature,now,floor,r['server_id']))


def _stop(db,r,remove=False):
    from failover import _restore_row
    if not r['cold']:
        db.execute('UPDATE server_failovers SET active=0,healthy_since=NULL WHERE server_id=?',(r['server_id'],))
        return
    if r['active']:
        db.execute("UPDATE detection_runs SET status='接管结束，停止拨测' WHERE server_id=? AND id>? AND status IN ('creating','pending','queued','issued')",(r['backup_id'],r['run_floor']))
    _restore_row(db,'detection_plans',r['backup_id'],r['original_plan'],not remove)
    _restore_row(db,'ip_monitors',r['backup_id'],r['original_monitor'],False)
    db.execute('UPDATE server_failovers SET active=0,signature=NULL,activated_at=NULL,healthy_since=NULL WHERE server_id=?',(r['server_id'],))


def _ready(db,cipher,r,sid,now,backup=False):
    import rotation
    from detectors import boce_dns_gate
    if not rotation._owned_server(db,sid,r['owner_id']):raise IntegrationError('服务器归属已变化')
    if rotation._offline(db,sid,now,r['offline_s']):raise IntegrationError('agent 心跳超时')
    if _pending(db,sid):raise IntegrationError('仍有未完成的重启或 DHCP 任务')
    address=public_v4(candidate_ip(db,{'server_id':sid,'source_id':None},cipher))
    p=db.execute('SELECT p.*,m.port,m.enabled FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=? AND s.enabled=1',(sid,)).fetchone()
    if not p or not p['automatic'] or not p['enabled']:raise IntegrationError('定时探测或 IP 监控已暂停')
    if backup and r['cold']:
        if not r['active']:raise IntegrationError('等待启用继承拨测')
        original=db.execute('SELECT p.source_id,p.nodes,m.port FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(r['server_id'],)).fetchone()
        if not original or p['source_id']!=original['source_id'] or p['nodes']!=original['nodes'] or p['port']!=original['port']:raise IntegrationError('等待继承当前探测点')
    reason=boce_dns_gate(db,sid,address,p['port'],require_plan=True,min_created=r['activated_at'] if backup and r['cold'] else None)
    if reason:raise IntegrationError(reason)
    run=db.execute('SELECT id,updated FROM detection_runs WHERE server_id=? AND ip=? AND source_id=? AND nodes=? AND port=? ORDER BY id DESC LIMIT 1',(sid,address,p['source_id'],p['nodes'],p['port'])).fetchone()
    if not run or (backup and r['cold'] and run['id']<=r['run_floor']) or not 0<=now-run['updated']<=90:raise IntegrationError('等待当前 IP 完成本轮探测，旧结果不能复用')
    ports={p['port']}|{b['port'] for b in bindings(db,r['server_id'])}
    for port in ports:
        try:
            with rotation.socket.create_connection((address,port),timeout=4):pass
        except OSError:raise IntegrationError('业务 TCP 端口不可达：'+str(port)) from None
    return address


def before_action(db,sid,now,cipher=None):
    """Called inside the action's write transaction; worker must take over first."""
    if not exists(db):return None
    if reserved(db,sid):return '冷备用不执行自动换 IP，请先解除故障转移配置'
    using=db.execute('SELECT 1 FROM server_failovers f JOIN server_failover_leases l ON l.server_id=f.server_id WHERE f.backup_id=?',(sid,)).fetchone()
    if using:
        import rotation
        if not rotation._fixed_failure(db,sid,now):return '当前 VPS 正接替其他主机的解析，先等待故障主机恢复，暂缓正常换 IP'
    r=db.execute('SELECT * FROM server_failovers WHERE server_id=?',(sid,)).fetchone()
    if not r:
        # Existing A/C plans use their established durable leases. Admit an A
        # repair only after C has taken every non-rotation record, too.
        old=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? AND failover_server_id IS NOT NULL',(sid,)).fetchone()
        if old and bindings(db,sid):
            import failover
            try:address,_,_=failover.backup_ready(db,cipher,old,now)
            except IntegrationError as e:return '等待 A 的故障转移 VPS 验证：'+str(e)
            for b in bindings(db,sid):
                lease=db.execute('SELECT * FROM vps_failover_leases WHERE binding_id=? AND rotation_id=?',(b['id'],old['id'])).fetchone()
                if not lease or lease['intent'] or lease['current_ip']!=address or b['expected_ip']!=address:return '等待 A 的全部非轮换解析由故障转移 VPS 接替后再换 IP'
        return None
    rows=bindings(db,sid)
    if not rows:return None # The A/B pair already protects the selected record.
    if r['requested_at'] is None:
        try:current=public_v4(candidate_ip(db,{'server_id':sid,'source_id':None},cipher))
        except IntegrationError:return '等待主机上报新鲜公网 IP 后再准备故障转移'
        db.execute("UPDATE server_failovers SET requested_at=?,action_ip=?,healthy_since=NULL,status='换 IP 前等待备用机验证并接替解析' WHERE server_id=?",(now,current,sid))
        return '等待故障转移接替解析后再换 IP'
    try:backup_ip=_ready(db,cipher,r,r['backup_id'],now,backup=True)
    except IntegrationError as e:return '故障转移 VPS 尚不可接替：'+str(e)
    for b in rows:
        lease=db.execute('SELECT * FROM server_failover_leases WHERE binding_id=? AND server_id=?',(b['id'],sid)).fetchone()
        if not lease or lease['target_ip'] or lease['restoring'] or now-lease['updated']>45 or b['expected_ip']!=lease['current_ip'] or lease['current_ip']!=backup_ip:return '等待故障转移完成全部解析并重新验证'
    return None


def _write(connect,cipher,sid,bid,target,now,restore=False):
    with connect() as db:path=db.execute('PRAGMA database_list').fetchone()[2]
    with open(str(Path(path).with_suffix('.dns.lock')),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        with connect() as db:
            b=db.execute('SELECT * FROM dns_bindings WHERE id=? AND server_id=?',(bid,sid)).fetchone()
            if not b or db.execute('SELECT 1 FROM vps_rotations WHERE binding_id=?',(bid,)).fetchone():raise IntegrationError('记录管理归属已变化')
            lease=db.execute('SELECT * FROM server_failover_leases WHERE binding_id=?',(bid,)).fetchone()
            if lease and lease['target_ip']:raise IntegrationError('DNS 写入待核对')
            r=db.execute('SELECT * FROM server_failovers WHERE server_id=?',(sid,)).fetchone()
            credential=db.execute('SELECT owner_id,server_id FROM ip_connections WHERE id=?',(b['connection_id'],)).fetchone()
            import rotation
            owner=None if rotation._admin_user(db,r['owner_id']) else r['owner_id']
            if not rotation._owned_server(db,sid,r['owner_id']) or not credential or credential['owner_id']!=owner or owner is not None and credential['server_id']!=sid:raise IntegrationError('解析凭据或主机归属已变化')
            c=load_connection(db,cipher,b['connection_id']);record=get_dns_record(c,b);validate_dns_record(record,b,c)
            db.execute('INSERT OR IGNORE INTO server_failover_leases(binding_id,server_id,current_ip,updated) VALUES(?,?,?,?)',(bid,sid,b['expected_ip'],now))
            db.execute('UPDATE server_failover_leases SET target_ip=?,restoring=?,updated=? WHERE binding_id=?',(target,int(restore),now,bid));db.commit()
            if b['expected_ip']!=target:update_dns_record(c,b,record,target)
            validate_dns_record(get_dns_record(c,b),dict(b,expected_ip=target),c)
            _finish(db,bid,target,restore,now)


def _finish(db,bid,target,restore,now):
    db.execute('UPDATE dns_bindings SET expected_ip=?,candidate=NULL,candidate_since=NULL,status=?,updated=? WHERE id=?',(target,'故障恢复已切回主机' if restore else '故障转移 VPS 正在承载',now,bid))
    if restore:db.execute('DELETE FROM server_failover_leases WHERE binding_id=?',(bid,))
    else:db.execute('UPDATE server_failover_leases SET current_ip=?,target_ip=NULL,updated=? WHERE binding_id=?',(target,now,bid))


def _step(connect,cipher,sid,now):
    import rotation
    with connect() as db:
        r=db.execute('SELECT * FROM server_failovers WHERE server_id=?',(sid,)).fetchone()
        if not r:return
        # Reconcile every ambiguous write before making further DNS decisions.
        for lease in db.execute('SELECT * FROM server_failover_leases WHERE server_id=? AND target_ip IS NOT NULL',(sid,)).fetchall():
            b=db.execute('SELECT * FROM dns_bindings WHERE id=?',(lease['binding_id'],)).fetchone()
            c=load_connection(db,cipher,b['connection_id'])
            validate_dns_record(get_dns_record(c,b),dict(b,expected_ip=lease['target_ip']),c)
            _finish(db,b['id'],lease['target_ip'],bool(lease['restoring']),now)
        leased=bool(db.execute('SELECT 1 FROM server_failover_leases WHERE server_id=?',(sid,)).fetchone())
        down=rotation._offline(db,sid,now,r['offline_s'])
        failed=rotation._fixed_failure(db,sid,now)
        action=db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND action_status IN ('queued','issued','submitted','uncertain')",(sid,)).fetchone()
        repairing=_pending(db,sid) or bool(action)
        rr=db.execute("SELECT 1 FROM vps_rotations WHERE drain_server_id=? AND phase IN ('draining','waiting_ip','waiting_probe')",(sid,)).fetchone()
        repairing=repairing or bool(rr)
        if not (down or failed or repairing or leased or r['requested_at']):
            if r['active']:_stop(db,r)
            return
        _activate(db,r,now)
        for target in (sid,r['backup_id']):
            last=db.execute('SELECT MAX(updated) FROM detection_runs WHERE server_id=?',(target,)).fetchone()[0]
            if last is None or now-last>=80:rotation._request_probe(db,target,now)
        db.commit() # Inherited probes must survive while we wait for their results.
        r=db.execute('SELECT * FROM server_failovers WHERE server_id=?',(sid,)).fetchone()
        requested_hold=False
        plan=db.execute('SELECT action_enabled FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
        if r['requested_at'] and plan and plan['action_enabled']:
            try:requested_hold=public_v4(candidate_ip(db,{'server_id':sid,'source_id':None},cipher))==r['action_ip']
            except IntegrationError:requested_hold=True
        incomplete=any(not db.execute('SELECT 1 FROM server_failover_leases WHERE binding_id=?',(b['id'],)).fetchone() for b in bindings(db,sid))
        if down or failed or repairing or requested_hold or r['requested_at'] and (not leased or incomplete):
            db.execute('UPDATE server_failovers SET healthy_since=NULL WHERE server_id=?',(sid,))
            address=_ready(db,cipher,r,r['backup_id'],now,backup=True)
            work=[]
            for b in bindings(db,sid):
                lease=db.execute('SELECT * FROM server_failover_leases WHERE binding_id=?',(b['id'],)).fetchone()
                if lease and lease['current_ip']==address:
                    db.execute('UPDATE server_failover_leases SET updated=? WHERE binding_id=?',(now,b['id']))
                else:work.append(b['id'])
            db.execute("UPDATE server_failovers SET status='备用机已验证，接替主机绑定解析；轮换记录由 A/B 管理' WHERE server_id=?",(sid,));db.commit()
            for bid in work:_write(connect,cipher,sid,bid,address,now)
            return
        address=_ready(db,cipher,r,sid,now)
        since=r['healthy_since']
        if since is None or r['healthy_ip']!=address:
            db.execute('UPDATE server_failovers SET healthy_since=?,healthy_ip=?,status=? WHERE server_id=?',(now,address,'主机探测已通过，等待恢复稳定窗口',sid));return
        if now-since<r['recovery_s']:return
        leases=db.execute('SELECT binding_id FROM server_failover_leases WHERE server_id=?',(sid,)).fetchall();db.commit()
        for lease in leases:_write(connect,cipher,sid,lease['binding_id'],address,now,True)
        _stop(db,r)
        db.execute("UPDATE server_failovers SET requested_at=NULL,action_ip=NULL,status='主机已恢复，备用机待命' WHERE server_id=?",(sid,))


def tick(connect,cipher):
    with connect() as db:
        if not exists(db):return
        path=db.execute('PRAGMA database_list').fetchone()[2]
        ids=[r[0] for r in db.execute('SELECT server_id FROM server_failovers')]
    with open(str(Path(path).with_suffix('.rotation.lock')),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for sid in ids:
            try:_step(connect,cipher,sid,int(time.time()))
            except IntegrationError as e:
                with connect() as db:db.execute('UPDATE server_failovers SET healthy_since=NULL,status=? WHERE server_id=?',('故障转移等待：'+str(e),sid))


def register(app,connect,cipher,auth,body,error,audit):
    @app.route('/api/servers/<int:sid>/failover',methods=['GET','PUT'])
    @auth()
    def config(sid):
        from flask import request
        if request.method=='PUT':
            with config_lock(connect):return configure(sid)
        return configure(sid)

    def configure(sid):
        import rotation
        import failover
        from flask import request
        with connect() as db:
            if not rotation._owned_server(db,sid,g.user['id']):return error('服务器不存在',404)
            r=db.execute('SELECT * FROM server_failovers WHERE server_id=?',(sid,)).fetchone()
            existing=db.execute('SELECT failover_server_id,failover_status FROM vps_rotations WHERE primary_server_id=? AND failover_server_id IS NOT NULL',(sid,)).fetchone()
            if request.method=='GET':
                servers=[dict(x) for x in db.execute('SELECT id,name FROM servers WHERE id<>? AND (? OR owner_id=?)',(sid,int(g.user['role']=='admin'),g.user['id']))]
                safe={k:r[k] for k in ('backup_id','recovery_s','offline_s','active','cold','status')} if r else None
                return jsonify(config=safe,servers=servers,rotation_failover=dict(existing) if existing else None)
            d=body();backup=d.get('backup_id');recovery=d.get('recovery_s',60);offline=d.get('offline_s',30)
            if backup is not None and (type(backup)is not int or backup==sid or type(recovery)is not int or not 15<=recovery<=3600 or type(offline)is not int or not 10<=offline<=120):return error('备用机、恢复时间或离线阈值无效')
            db.execute('BEGIN IMMEDIATE')
            r=db.execute('SELECT * FROM server_failovers WHERE server_id=?',(sid,)).fetchone()
            if r and r['owner_id']!=g.user['id']:return error('请由原配置账号管理故障转移',403)
            if r and db.execute('SELECT 1 FROM server_failover_leases WHERE server_id=?',(sid,)).fetchone():return error('解析尚由备用机承载或等待核对，恢复切回后才能修改',409)
            if existing:return error('此 A 已配置轮换故障转移，请在轮换设置中管理，不能重复配置',409)
            if backup is not None:
                try:
                    failover.probe_config(db,sid,g.user['id'])
                    if not rotation._owned_server(db,backup,g.user['id']):raise IntegrationError('备用机不属于当前账号')
                    if db.execute('SELECT 1 FROM server_failovers WHERE server_id<>? AND backup_id=?',(sid,backup)).fetchone():raise IntegrationError('备用机已被另一故障转移配置占用，不允许重复分配')
                    node=backup;seen={sid}
                    while node not in seen:
                        seen.add(node)
                        link=db.execute('SELECT backup_id FROM server_failovers WHERE server_id=?',(node,)).fetchone()
                        if not link:break
                        node=link['backup_id']
                    else:raise IntegrationError('不能组成循环故障转移')
                    if failover.reserved(db,backup):raise IntegrationError('此备用机已作为冷备用被占用')
                    if failover.reserved(db,sid):raise IntegrationError('当前服务器是冷备用，不能配置循环故障转移')
                    live=db.execute("SELECT 1 FROM detection_plans WHERE server_id=? AND automatic=1 AND response_mode IN ('reboot','change_api')",(backup,)).fetchone()
                    live=live or db.execute('SELECT 1 FROM vps_rotations WHERE primary_server_id=? OR other_server_id=?',(backup,backup)).fetchone() or db.execute('SELECT 1 FROM server_failovers WHERE server_id=?',(backup,)).fetchone()
                    cold=0 if live else 1
                    if not cold:failover.probe_config(db,backup,g.user['id'])
                    if rotation._pending_action(db,backup):raise IntegrationError('备用机有未完成动作，请先处理')
                    if not bindings(db,sid) and not db.execute('SELECT 1 FROM vps_rotations WHERE primary_server_id=? OR other_server_id=?',(sid,sid)).fetchone():raise IntegrationError('请先给主机绑定解析记录')
                    stub=dict(primary_server_id=sid,owner_id=g.user['id'],offline_after_s=offline)
                    address,_=failover.standby_ready(db,cipher,stub,backup,int(time.time()))
                    own=public_v4(candidate_ip(db,{'server_id':sid,'source_id':None},cipher))
                    if own==address:raise IntegrationError('主机与备用机不能使用相同公网 IP')
                    for b in bindings(db,sid):
                        c=db.execute('SELECT owner_id,server_id FROM ip_connections WHERE id=?',(b['connection_id'],)).fetchone()
                        owner=None if g.user['role']=='admin' else g.user['id']
                        if c['owner_id']!=owner or owner is not None and c['server_id']!=sid:raise IntegrationError('绑定解析的凭据归属不一致')
                except IntegrationError as e:return error(str(e),409)
            if r:
                _stop(db,r,remove=True)
                db.execute('DELETE FROM server_failovers WHERE server_id=?',(sid,))
            if backup is not None:
                plan=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(backup,)).fetchone()
                monitor=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(backup,)).fetchone()
                db.execute('INSERT INTO server_failovers(server_id,backup_id,owner_id,recovery_s,offline_s,cold,original_plan,original_monitor) VALUES(?,?,?,?,?,?,?,?)',(sid,backup,g.user['id'],recovery,offline,cold,json.dumps(dict(plan)) if plan else None,json.dumps(dict(monitor)) if monitor else None))
                db.execute('UPDATE server_failovers SET status=? WHERE server_id=?',('冷备用待命，不运行额外拨测' if cold else '在用备用机待命，保留自身检测配置',sid))
                if cold:db.execute("UPDATE detection_plans SET automatic=0,action_enabled=0,status='冷备用待命，不运行拨测' WHERE server_id=?",(backup,))
            audit(db,'配置单机故障转移 #'+str(sid))
        return jsonify(ok=True)
