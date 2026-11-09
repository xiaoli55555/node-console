"""Scoped, outbound-agent DHCP jobs. No arbitrary remote command text."""
import hashlib
import json
import secrets
import time
from flask import jsonify, request, g
from ip_dns import IntegrationError, ChangeIPBlocked

_connect=None
_cipher=None

def nonpreferred_ip(db,server_id):
    from ip_dns import candidate_ip,public_v4
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='hkt_dhcp_apis'").fetchone():return False
    if not db.execute('SELECT 1 FROM hkt_dhcp_apis WHERE server_id=?',(server_id,)).fetchone():return False
    try:return not public_v4(candidate_ip(db,{'server_id':server_id,'source_id':None},_cipher)).startswith('42.')
    except IntegrationError:return False

def preferred_ip_retry_allowed(db,server_id):
    """Only resume selection after a terminal job; never overlap an agent task."""
    cfg=db.execute('SELECT reset_after FROM hkt_dhcp_apis WHERE server_id=?',(server_id,)).fetchone()
    pending=db.execute("SELECT 1 FROM commands WHERE server_id=? AND status IN ('queued','issued','accepted','unconfirmed')",(server_id,)).fetchone()
    if not cfg or pending or not nonpreferred_ip(db,server_id):return False
    job=db.execute("SELECT id,status FROM commands WHERE server_id=? AND action='hkt_dhcp' ORDER BY id DESC LIMIT 1",(server_id,)).fetchone()
    return bool(job and job['status'] in ('completed','failed','expired'))

def action_block(db,server_id,connection_id=None,selecting=None):
    """Read the same interlock used inside queue's atomic transaction."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='hkt_dhcp_apis'").fetchone():return None
    cfg=db.execute('SELECT * FROM hkt_dhcp_apis WHERE server_id=?',(server_id,)).fetchone()
    if not cfg or (connection_id is not None and connection_id!=cfg['connection_id']):return None
    pending=db.execute("SELECT id,action,status FROM commands WHERE server_id=? AND status IN ('queued','issued','accepted','unconfirmed') ORDER BY id DESC LIMIT 1",(server_id,)).fetchone()
    if pending:
        if pending['action']=='hkt_dhcp' and pending['status']=='unconfirmed':
            return ChangeIPBlocked('上次 DHCP 结果待核对，请检查 agent 后重置 API',pending['id'],'dhcp_unconfirmed')
        return None
    # Terminal failures/expiry do not lock out later rotation attempts.
    # queue() still checks drain/carrier guards and serializes pending jobs.
    return None

def initialize(connect):
    global _connect
    _connect=connect
    with connect() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS hkt_dhcp_apis(
        server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        connection_id INTEGER NOT NULL REFERENCES ip_connections(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL, reset_after INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS dhcp_task_events(
        id INTEGER PRIMARY KEY, command_id INTEGER NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
        server_id INTEGER NOT NULL, stage TEXT NOT NULL, detail TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS dhcp_task_events_job ON dhcp_task_events(command_id,id);
        CREATE TRIGGER IF NOT EXISTS dhcp_task_created AFTER INSERT ON commands WHEN NEW.action='hkt_dhcp'
        BEGIN INSERT INTO dhcp_task_events(command_id,server_id,stage,detail,created)
        VALUES(NEW.id,NEW.server_id,NEW.status,'{}',NEW.created); END;
        CREATE TRIGGER IF NOT EXISTS dhcp_task_transition AFTER UPDATE OF status ON commands
        WHEN NEW.action='hkt_dhcp' AND OLD.status<>NEW.status
        BEGIN INSERT INTO dhcp_task_events(command_id,server_id,stage,detail,created)
        VALUES(NEW.id,NEW.server_id,NEW.status,json_object('previous_status',OLD.status),NEW.updated); END;
        CREATE TABLE IF NOT EXISTS hkt_dhcp_results(
        command_id INTEGER PRIMARY KEY REFERENCES commands(id) ON DELETE CASCADE,
        result TEXT NOT NULL, updated INTEGER NOT NULL);''')

def queue(server_id,connection_id=None,managed=False):
    if _connect is None:raise IntegrationError('DHCP 动作通道未初始化')
    now=int(time.time())
    with _connect() as db:
        db.execute('BEGIN IMMEDIATE')
        cfg=db.execute('SELECT * FROM hkt_dhcp_apis WHERE server_id=?',(server_id,)).fetchone()
        if not cfg or (connection_id is not None and connection_id!=cfg['connection_id']):raise IntegrationError('HKT API 只能作用于绑定的 VPS')
        node=db.execute('SELECT * FROM servers WHERE id=?',(server_id,)).fetchone()
        metrics=json.loads(node['metrics'] or '{}') if node else {}
        if not node or not node['seen'] or now-node['seen']>45 or 'hkt_dhcp' not in metrics.get('capabilities',[]):raise IntegrationError('HKT agent 离线或未在本机启用 DHCP 换 IP')
        # API keys must not bypass the rotation's drain/current-server guards.
        r=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? OR other_server_id=?',(server_id,server_id)).fetchone()
        selecting=bool(r and nonpreferred_ip(db,server_id))
        if r and not managed and not selecting:raise IntegrationError('此 VPS 由轮换管理，请通过轮换流程调用，不能绕过排空条件')
        if r and not r['enabled'] and not r['fault_recovery']:raise IntegrationError('轮换已暂停，未处于故障修复流程')
        if r and r['mode']=='fixed_primary' and server_id==r['primary_server_id']:
            from rotation import _fixed_failure
            if not _fixed_failure(db,server_id,now):raise IntegrationError('固定主机 A 未确认故障，禁止换 IP')
        if r and not selecting and not r['emergency'] and r['drain_started'] and now-r['drain_started']<r['drain_grace_s']:raise IntegrationError('仍在 DNS 排空等待期')
        if r and not selecting and not r['emergency'] and r['low_samples']<2:raise IntegrationError('尚未达到轮换连接阈值')
        if r and (r['active_server_id']==server_id or r['drain_server_id']!=server_id or r['phase'] not in ('draining','waiting_ip','waiting_probe')):
            raise IntegrationError('此机器仍承载轮换解析，或未进入换 IP 阶段')
        if db.execute('SELECT 1 FROM vps_rotations WHERE failover_server_id=?',(server_id,)).fetchone():raise IntegrationError('冷备用 C 不接受此 DHCP API 动作')
        if selecting:
            # The exception skips waiting, never a current DNS carrier or a
            # partial DNS handoff. Read back every associated selected record.
            from ip_dns import load_connection,get_dns_record,validate_dns_record,candidate_ip,public_v4
            address=public_v4(candidate_ip(db,{'server_id':server_id,'source_id':None},_cipher))
            for peer in db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? OR other_server_id=?',(server_id,server_id)):
                if peer['active_server_id']==server_id or peer['dns_intent']:raise IntegrationError('此 VPS 仍承载解析或存在未完成 DNS 切换')
                binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(peer['binding_id'],)).fetchone()
                conn=load_connection(db,_cipher,binding['connection_id'])
                record=get_dns_record(conn,binding);validate_dns_record(record,binding,conn)
                if record.get('content',record.get('Value'))==address:raise IntegrationError('所选 DNS 仍指向当前 IP，不能继续选 IP')
        from server_failover import before_action
        reason=before_action(db,server_id,now,_cipher)
        if reason:
            db.commit() # Persist the takeover request even when the API returns a wait error.
            raise IntegrationError(reason)
        pending=db.execute("SELECT id,action,status FROM commands WHERE server_id=? AND status IN ('queued','issued','accepted','unconfirmed') ORDER BY id DESC LIMIT 1",(server_id,)).fetchone()
        if pending:
            if pending['action']!='hkt_dhcp':raise IntegrationError('服务器另有未完成动作')
            if pending['status']=='unconfirmed':raise action_block(db,server_id,connection_id,selecting)
            return pending['id']
        blocked=action_block(db,server_id,connection_id,selecting)
        if blocked:raise blocked
        admin=db.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
        if not admin:raise IntegrationError('缺少管理员')
        return db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp','queued',?,?)",(server_id,admin['id'],now,now)).lastrowid

def task_event(db,sid,cid,stage,detail,now):
    safe={k:v for k,v in detail.items() if k in ('state','attempts','old_ip','new_ip','previous_status','error_code') and isinstance(v,(str,int,float,bool,type(None)))}
    payload=json.dumps(safe,sort_keys=True,ensure_ascii=False)
    if len(payload)>1024:return
    last=db.execute('SELECT stage,detail FROM dhcp_task_events WHERE command_id=? AND stage=? ORDER BY id DESC LIMIT 1',(cid,stage)).fetchone()
    if last and last['stage']==stage and last['detail']==payload:return
    db.execute('INSERT INTO dhcp_task_events(command_id,server_id,stage,detail,created) VALUES(?,?,?,?,?)',(cid,sid,stage,payload,now))


def reconcile_task(db,sid,status,now):
    """Authenticated agent answers a query about the SAME pending task."""
    if not isinstance(status,dict) or type(status.get('id')) is not int:return
    job=db.execute("SELECT * FROM commands WHERE id=? AND server_id=? AND action='hkt_dhcp'",(status['id'],sid)).fetchone()
    if not job or job['status'] not in ('issued','accepted','unconfirmed'):return
    state=status.get('state')
    if state not in ('not_started','unknown','running','changed','unchanged','failed'):return
    task_event(db,sid,job['id'],'reconciled',{'state':state},now)
    if state in ('not_started','unknown'):
        db.execute('INSERT OR REPLACE INTO hkt_dhcp_results(command_id,result,updated) VALUES(?,?,?)',(job['id'],json.dumps({'state':state,'id':job['id']}),now))
    if state=='not_started':
        # An idle execution lock, no live systemd unit, and no persistent result
        # must ALL be checked by the agent. Redispatch the same id, not a new job.
        if status.get('idle_verified') is not True:return
        db.execute("UPDATE commands SET status='queued',updated=? WHERE id=?",(now,job['id']))
    elif state in ('running','changed','unchanged','failed'):
        db.execute("UPDATE commands SET status='accepted',updated=? WHERE id=?",(now,job['id']))
        apply_result(db,sid,status,now)


def apply_result(db,sid,result,now):
    if not isinstance(result,dict) or type(result.get('id')) is not int or result.get('state') not in ('running','changed','unchanged','failed'):return
    job=db.execute("SELECT status FROM commands WHERE id=? AND server_id=? AND action='hkt_dhcp'",(result['id'],sid)).fetchone()
    if not job or job['status'] not in ('accepted','unconfirmed'):return
    # A reported success is still subject to fresh agent IP + selected probe gates.
    safe={k:result[k] for k in ('id','state','old_ip','new_ip','attempts','error') if k in result}
    if len(json.dumps(safe))>1024:return
    evidence=dict(safe)
    if result.get('error'):
        kind=str(result['error']).split(':',1)[0]
        evidence['error_code']=kind if kind in ('ValueError','OSError','TimeoutExpired','CalledProcessError','RuntimeError','SubprocessError') else 'execution_failed'
    task_event(db,sid,result['id'],'execution',evidence,now)
    if result['state']=='running':
        db.execute("UPDATE commands SET status='accepted',updated=? WHERE id=?",(now,result['id']))
        db.execute('INSERT OR REPLACE INTO hkt_dhcp_results(command_id,result,updated) VALUES(?,?,?)',(result['id'],json.dumps(safe),now))
        return
    db.execute("UPDATE commands SET status=?,updated=? WHERE id=?",('completed' if result['state']=='changed' else 'failed',now,result['id']))
    db.execute('INSERT OR REPLACE INTO hkt_dhcp_results(command_id,result,updated) VALUES(?,?,?)',(result['id'],json.dumps(safe),now))
    db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,sid))

def register(app,connect,cipher,auth,body,error,audit):
    global _cipher
    _cipher=cipher
    initialize(connect)
    @app.post('/api/admin/servers/<int:sid>/hkt-dhcp/api')
    @auth(admin=True)
    def generate(sid):
        name=body().get('name')
        if name is not None and (not isinstance(name,str) or not 1<=len(name.strip())<=80):return error('API 名称需为 1～80 字符')
        token=secrets.token_urlsafe(40)
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            node=db.execute('SELECT * FROM servers WHERE id=?',(sid,)).fetchone()
            if not node:return error('服务器不存在',404)
            # Administrators manage both assigned and unassigned VPS. The generated
            # credential remains admin-owned and pinned to this server.
            if 'hkt_dhcp' not in json.loads(node['metrics'] or '{}').get('capabilities',[]):return error('请先更新 agent，并在 HKT 本机启用 ens18 DHCP 动作',409)
            old=db.execute('SELECT connection_id FROM hkt_dhcp_apis WHERE server_id=?',(sid,)).fetchone()
            config=json.dumps({'provider':'agent_dhcp','server_id':sid})
            if old:
                cid=old['connection_id'];db.execute('UPDATE ip_connections SET config=?,secret=? WHERE id=?',(config,cipher.encrypt(token.encode()).decode(),cid))
                if name is not None:db.execute('UPDATE ip_connections SET name=? WHERE id=?',(name.strip(),cid))
            else:cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret,server_id) VALUES(?,'change_ip',?,?,?)",(name.strip() if name is not None else node['name']+' · HKT 换 IP',config,cipher.encrypt(token.encode()).decode(),sid)).lastrowid
            floor=db.execute('SELECT COALESCE(MAX(id),0) FROM commands WHERE server_id=?',(sid,)).fetchone()[0]
            db.execute('INSERT OR REPLACE INTO hkt_dhcp_apis VALUES(?,?,?,?)',(sid,cid,hashlib.sha256(token.encode()).hexdigest(),floor))
            audit(db,'生成 HKT DHCP 专属 API VPS #'+str(sid))
        return jsonify(ok=True,connection_id=cid,path=f'/api/hkt-dhcp/{sid}',token=token,message='已保存为换 IP API；生成不会执行动作。重新生成会撤销旧令牌并解除失败锁定。')
    @app.post('/api/admin/servers/<int:sid>/hkt-dhcp/test')
    @auth(admin=True)
    def test_once(sid):
        if body().get('confirm') is not True:return error('请确认此测试会实际执行 DHCP 换 IP，并可能短暂中断网络')
        try:cid=queue(sid)
        except IntegrationError as e:return error(str(e),409)
        with connect() as db:audit(db,'单次 HKT DHCP 换 IP 测试 VPS #'+str(sid)+'，命令 #'+str(cid))
        return jsonify(ok=True,command_id=cid,status='queued',message='单次测试已排队；等待 agent 执行及新 IP 上报，不代表换 IP 已成功'),202

    @app.get('/api/admin/servers/<int:sid>/hkt-dhcp/tasks')
    @auth(admin=True)
    def task_history(sid):
        try:
            before=int(request.args.get('before',2**63-1))
            if before<1:raise ValueError()
        except ValueError:return error('无效任务游标',400)
        with connect() as db:
            jobs=db.execute("SELECT id,server_id,status,created,updated FROM commands WHERE server_id=? AND action='hkt_dhcp' AND id<? ORDER BY id DESC LIMIT 21",(sid,before)).fetchall()
        return jsonify(tasks=[dict(j) for j in jobs[:20]],has_more=len(jobs)>20,next_before=jobs[19]['id'] if len(jobs)>20 else None)

    @app.get('/api/admin/servers/<int:sid>/hkt-dhcp/tasks/<int:cid>')
    @auth(admin=True)
    def task_timeline(sid,cid):
        try:
            after=int(request.args.get('after',0))
            if after<0:raise ValueError()
        except ValueError:return error('无效事件游标',400)
        with connect() as db:
            job=db.execute("SELECT id,server_id,status,created,updated FROM commands WHERE id=? AND server_id=? AND action='hkt_dhcp'",(cid,sid)).fetchone()
            if not job:return error('任务不存在',404)
            rows=db.execute('SELECT id,stage,detail,created FROM dhcp_task_events WHERE command_id=? AND id>? ORDER BY id LIMIT 201',(cid,after)).fetchall()
            events=[dict(id=r['id'],stage=r['stage'],detail=json.loads(r['detail']),created=r['created']) for r in rows[:200]]
        return jsonify(job=dict(job),events=events,has_more=len(rows)>200,next_after=events[-1]['id'] if events else after,history_complete=any(e['stage']=='queued' for e in events) if after==0 else None)

    @app.get('/api/admin/servers/<int:sid>/hkt-dhcp/status')
    @auth(admin=True)
    def status(sid):
        with connect() as db:
            job=db.execute("SELECT id,status,created,updated FROM commands WHERE server_id=? AND action='hkt_dhcp' ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
            result=db.execute('SELECT result FROM hkt_dhcp_results WHERE command_id=?',(job['id'],)).fetchone() if job else None
            outcome=json.loads(result['result']) if result else None
            address=None;verified=False
            from ip_dns import candidate_ip,public_v4
            try:
                address=public_v4(candidate_ip(db,{'server_id':sid,'source_id':None},cipher))
                if job and job['status']=='completed' and outcome and outcome.get('state')=='changed':
                    old=public_v4(outcome.get('old_ip'));new=public_v4(outcome.get('new_ip'))
                    verified=old!=new and address==new
            except IntegrationError:pass
        return jsonify(job=dict(job) if job else None,result=outcome,current_ip=address,verified_ip_change=verified)
    @app.post('/api/hkt-dhcp/<int:sid>')
    def trigger(sid):
        bearer=request.headers.get('Authorization','')
        if not bearer.startswith('Bearer ') or len(bearer)>256:return error('API 认证失败',401)
        with connect() as db:cfg=db.execute('SELECT * FROM hkt_dhcp_apis WHERE server_id=?',(sid,)).fetchone()
        if not cfg or not secrets.compare_digest(cfg['token_hash'],hashlib.sha256(bearer[7:].encode()).hexdigest()):return error('API 认证失败',401)
        try:cid=queue(sid,cfg['connection_id'])
        except IntegrationError as e:return error(str(e),409)
        return jsonify(success=True,command_id=cid,status='queued',message='请求已排队，不代表 IP 已变化'),202
