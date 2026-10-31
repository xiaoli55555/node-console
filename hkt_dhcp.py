"""Scoped, outbound-agent DHCP jobs. No arbitrary remote command text."""
import hashlib
import json
import secrets
import time
from flask import jsonify, request, g
from ip_dns import IntegrationError

_connect=None
_cipher=None

def initialize(connect):
    global _connect
    _connect=connect
    with connect() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS hkt_dhcp_apis(
        server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        connection_id INTEGER NOT NULL REFERENCES ip_connections(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL, reset_after INTEGER NOT NULL DEFAULT 0);
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
        if r and not managed:raise IntegrationError('此 VPS 由轮换管理，请通过轮换流程调用，不能绕过排空条件')
        if r and not r['enabled'] and not r['fault_recovery']:raise IntegrationError('轮换已暂停，未处于故障修复流程')
        if r and r['mode']=='fixed_primary' and server_id==r['primary_server_id']:
            from rotation import _fixed_failure
            if not _fixed_failure(db,server_id,now):raise IntegrationError('固定主机 A 未确认故障，禁止换 IP')
        if r and not r['emergency'] and r['drain_started'] and now-r['drain_started']<r['drain_grace_s']:raise IntegrationError('仍在 DNS 排空等待期')
        if r and not r['emergency'] and r['low_samples']<2:raise IntegrationError('尚未达到轮换连接阈值')
        if r and (r['active_server_id']==server_id or r['drain_server_id']!=server_id or r['phase'] not in ('draining','waiting_ip','waiting_probe')):
            raise IntegrationError('此机器仍承载轮换解析，或未进入换 IP 阶段')
        if db.execute('SELECT 1 FROM vps_rotations WHERE failover_server_id=?',(server_id,)).fetchone():raise IntegrationError('冷备用 C 不接受此 DHCP API 动作')
        from server_failover import before_action
        reason=before_action(db,server_id,now,_cipher)
        if reason:
            db.commit() # Persist the takeover request even when the API returns a wait error.
            raise IntegrationError(reason)
        pending=db.execute("SELECT id,action,status FROM commands WHERE server_id=? AND status IN ('queued','issued','accepted','unconfirmed') ORDER BY id DESC LIMIT 1",(server_id,)).fetchone()
        if pending:
            if pending['action']!='hkt_dhcp':raise IntegrationError('服务器另有未完成动作')
            if pending['status']=='unconfirmed':raise IntegrationError('上次 DHCP 结果待核对，请检查 agent 后重置 API')
            return pending['id']
        last=db.execute("SELECT id,status FROM commands WHERE server_id=? AND action='hkt_dhcp' AND id>? ORDER BY id DESC LIMIT 1",(server_id,cfg['reset_after'])).fetchone()
        if last and last['status'] in ('failed','expired'):raise IntegrationError('DHCP 上轮未成功；已停止自动重复，检查网络后重新生成 API 解除')
        admin=db.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
        if not admin:raise IntegrationError('缺少管理员')
        return db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp','queued',?,?)",(server_id,admin['id'],now,now)).lastrowid

def apply_result(db,sid,result,now):
    if not isinstance(result,dict) or type(result.get('id')) is not int or result.get('state') not in ('changed','unchanged','failed'):return
    job=db.execute("SELECT status FROM commands WHERE id=? AND server_id=? AND action='hkt_dhcp'",(result['id'],sid)).fetchone()
    if not job or job['status'] not in ('accepted','unconfirmed'):return
    # A reported success is still subject to fresh agent IP + selected probe gates.
    safe={k:result[k] for k in ('id','state','old_ip','new_ip','attempts','error') if k in result}
    if len(json.dumps(safe))>1024:return
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
            else:cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret,server_id) VALUES(?,'change_ip',?,?,?)",('HKT DHCP VPS #'+str(sid),config,cipher.encrypt(token.encode()).decode(),sid)).lastrowid
            floor=db.execute('SELECT COALESCE(MAX(id),0) FROM commands WHERE server_id=?',(sid,)).fetchone()[0]
            db.execute('INSERT OR REPLACE INTO hkt_dhcp_apis VALUES(?,?,?,?)',(sid,cid,hashlib.sha256(token.encode()).hexdigest(),floor))
            audit(db,'生成 HKT DHCP 专属 API VPS #'+str(sid))
        return jsonify(ok=True,connection_id=cid,path=f'/api/hkt-dhcp/{sid}',token=token,message='已保存为换 IP API；生成不会执行动作。重新生成会撤销旧令牌并解除失败锁定。')
    @app.get('/api/admin/servers/<int:sid>/hkt-dhcp/status')
    @auth(admin=True)
    def status(sid):
        with connect() as db:
            job=db.execute("SELECT id,status,created,updated FROM commands WHERE server_id=? AND action='hkt_dhcp' ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
            result=db.execute('SELECT result FROM hkt_dhcp_results WHERE command_id=?',(job['id'],)).fetchone() if job else None
        return jsonify(job=dict(job) if job else None,result=json.loads(result['result']) if result else None)
    @app.post('/api/hkt-dhcp/<int:sid>')
    def trigger(sid):
        bearer=request.headers.get('Authorization','')
        if not bearer.startswith('Bearer ') or len(bearer)>256:return error('API 认证失败',401)
        with connect() as db:cfg=db.execute('SELECT * FROM hkt_dhcp_apis WHERE server_id=?',(sid,)).fetchone()
        if not cfg or not secrets.compare_digest(cfg['token_hash'],hashlib.sha256(bearer[7:].encode()).hexdigest()):return error('API 认证失败',401)
        try:cid=queue(sid,cfg['connection_id'])
        except IntegrationError as e:return error(str(e),409)
        return jsonify(success=True,command_id=cid,status='queued',message='请求已排队，不代表 IP 已变化'),202
