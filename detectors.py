"""Replaceable detection sources: BOCE asynchronous tasks or authenticated self-hosted probes."""
import hashlib
import ipaddress
import json
import math
import secrets
import time
import urllib.parse
from flask import jsonify,request
from ip_dns import IntegrationError, request_json, candidate_ip

SCHEMA='''
CREATE TABLE IF NOT EXISTS detection_sources(id INTEGER PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,secret TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS detection_plans(server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,source_id INTEGER NOT NULL REFERENCES detection_sources(id),nodes TEXT NOT NULL DEFAULT '[]',interval_s INTEGER NOT NULL DEFAULT 600,automatic INTEGER NOT NULL DEFAULT 0,daily_limit INTEGER NOT NULL DEFAULT 1000,next_at INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT '等待检测',checked INTEGER);
CREATE TABLE IF NOT EXISTS detection_runs(id INTEGER PRIMARY KEY,server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,source_id INTEGER NOT NULL REFERENCES detection_sources(id),ip TEXT NOT NULL,port INTEGER NOT NULL,nodes TEXT NOT NULL,status TEXT NOT NULL,remote_id TEXT,created INTEGER NOT NULL,updated INTEGER NOT NULL,details TEXT NOT NULL DEFAULT '[]',poll_at INTEGER NOT NULL DEFAULT 0,cost INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS detection_pending ON detection_runs(status,poll_at);
'''

def initialize(connect):
    with connect() as db:db.executescript(SCHEMA)

def boce(secret,path,params=None):
    # Fixed upstream host; credential is sent in POST body, never logged or returned.
    data=request_json('https://api.boce.com/v3/'+path,{'Content-Type':'application/x-www-form-urlencoded'},urllib.parse.urlencode({'key':secret,**(params or {})}))
    if not isinstance(data,dict) or data.get('error_code',0)!=0:raise IntegrationError('BOCE API 返回异常；请检查权限、余额和调用限制')
    return data

def source_secret(row,cipher):return cipher.decrypt(row['secret'].encode()).decode()

def summarize(rows,node_ids):
    """Conservative: missing/offline/malformed results never count as target failures."""
    if not isinstance(rows,list):raise IntegrationError('检测结果格式无效')
    by_id={}
    for r in rows:
        if not isinstance(r,dict):continue
        nid=str(r.get('node_id',''))
        if nid in by_id:raise IntegrationError('检测节点返回重复结果')
        by_id[nid]=r
    result=[]
    for nid in node_ids:
        r=by_id.get(str(nid))
        if not r or 'not found node' in str(r.get('error','')).lower():state='unknown'
        else:
            sent=r.get('packets_transmitted');received=r.get('packets_received')
            if type(sent) not in (int,float) or type(received) not in (int,float) or not math.isfinite(sent) or not math.isfinite(received) or sent<=0 or received<0 or received>sent:state='unknown'
            elif received>0:state='reachable'
            elif r.get('error_code')==0:state='unreachable'
            else:state='unknown' # Nonzero errors need provider-specific interpretation, no guess.
        avg=r.get('round_trip_avg') if r else None
        if type(avg) not in (int,float) or not math.isfinite(avg) or avg<0:avg=None
        result.append({'node_id':str(nid),'name':str((r or {}).get('node_name',nid))[:100],'state':state,'latency_ms':avg})
    if any(r['state']=='unknown' for r in result):status='检测异常或结果不完整'
    elif all(r['state']=='reachable' for r in result):status='所选检测点 TCP 可达'
    elif all(r['state']=='unreachable' for r in result):status='所选检测点 TCP 均不通（待复核）'
    else:status='部分检测点 TCP 不通（待复核）'
    return status,result

def finish(db,run,status,rows):
    now=int(time.time())
    db.execute('UPDATE detection_runs SET status=?,details=?,updated=? WHERE id=?',(status,json.dumps(rows),now,run['id']))
    # Do not apply old source/IP results to a reconfigured plan or a changed target.
    plan=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(run['server_id'],)).fetchone()
    current=db.execute('SELECT current_ip FROM ip_monitors WHERE server_id=?',(run['server_id'],)).fetchone()
    if plan and plan['source_id']==run['source_id'] and plan['nodes']==run['nodes'] and (not current or not current['current_ip'] or current['current_ip']==run['ip']):
        db.execute('UPDATE detection_plans SET status=?,checked=? WHERE server_id=?',(status,now,run['server_id']))

def start_run(connect,cipher,sid):
    # Hold the SQLite write lock across creation. Ambiguous POST failure is NOT retried automatically.
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        p=db.execute('SELECT p.*,s.kind,s.secret,s.enabled FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(sid,)).fetchone()
        m=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
        if not p or not m:raise IntegrationError('请先配置 VPS 的检测来源')
        if not p['enabled'] or not m['enabled']:raise IntegrationError('监控或检测来源已暂停')
        if db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND status IN ('creating','pending','queued','issued')",(sid,)).fetchone():raise IntegrationError('已有检测任务进行中，请勿重复提交')
        now=int(time.time())
        if now<p['next_at']:raise IntegrationError('尚未到下一次检测时间，请避免重复扣费')
        ip=candidate_ip(db,m,cipher);nodes=json.loads(p['nodes']) if p['kind']=='boce' else ['self']
        if not nodes:raise IntegrationError('请至少选择一个国内检测点')
        cost=len(nodes) if p['kind']=='boce' else 0
        from datetime import datetime
        from zoneinfo import ZoneInfo
        z=ZoneInfo('Asia/Shanghai');today=datetime.now(z).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()
        used=db.execute('SELECT COALESCE(SUM(cost),0) FROM detection_runs WHERE server_id=? AND created>=?',(sid,today)).fetchone()[0]
        if used+cost>p['daily_limit']:raise IntegrationError('已达到此 VPS 的每日节点检测次数上限')
        rid=db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,poll_at,cost) VALUES(?,?,?,?,?,'creating',?,?,?,?)",(sid,p['source_id'],ip,m['port'],json.dumps(nodes),now,now,now+10,cost)).lastrowid
        db.execute('UPDATE detection_plans SET next_at=?,status=? WHERE server_id=?',(now+p['interval_s'],'检测中',sid))
        try:
            if p['kind']=='boce':
                data=boce(source_secret(p,cipher),'task/create/tcping',{'node_ids':','.join(map(str,nodes)),'host':ip+':'+str(m['port'])})
                remote=data.get('data',{}).get('id')
                if not isinstance(remote,str) or not remote or len(remote)>200 or not remote.isalnum():raise IntegrationError('BOCE 未返回有效任务 ID')
                db.execute("UPDATE detection_runs SET remote_id=?,status='pending' WHERE id=?",(remote,rid))
            else:db.execute("UPDATE detection_runs SET status='queued' WHERE id=?",(rid,))
        except IntegrationError:
            # Keep conservative cost reservation and cooldown; upstream may have accepted the POST.
            db.execute("UPDATE detection_runs SET status='提交异常（不自动重试）' WHERE id=?",(rid,))
            db.execute("UPDATE detection_plans SET status='提交异常，请检查 API 状态；不自动重试本任务' WHERE server_id=?",(sid,))
        db.execute('DELETE FROM detection_runs WHERE id IN (SELECT id FROM detection_runs WHERE created<? AND status NOT IN (\'pending\',\'queued\',\'issued\',\'creating\'))',(now-30*86400,))
        return rid

def tick(connect,cipher):
    now=int(time.time())
    with connect() as db:
        # Timed-out self probes and expired BOCE jobs never imply target is blocked.
        expired=db.execute("SELECT * FROM detection_runs WHERE status IN ('pending','queued','issued','creating') AND created<?",(now-120,)).fetchall()
        for r in expired:finish(db,r,'检测超时（不能判定目标不通）',[])
        pending=[dict(r) for r in db.execute("SELECT r.*,s.secret,s.enabled FROM detection_runs r JOIN detection_sources s ON s.id=r.source_id WHERE r.status='pending' AND r.poll_at<=?",(now,))]
    for r in pending:
        with connect() as db:db.execute('UPDATE detection_runs SET poll_at=? WHERE id=?',(now+10,r['id']))
        try:
            data=boce(source_secret(r,cipher),'task/tcping/'+r['remote_id'])
            if type(data.get('done'))is not bool:raise IntegrationError('BOCE 结果格式无效')
            if not data['done']:continue
            status,rows=summarize(data.get('list'),json.loads(r['nodes']))
            with connect() as db:finish(db,r,status,rows)
        except IntegrationError:
            with connect() as db:finish(db,r,'检测接口异常（不能判定目标不通）',[])
    with connect() as db:
        due=[r[0] for r in db.execute('SELECT p.server_id FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id JOIN detection_sources s ON s.id=p.source_id WHERE p.automatic=1 AND m.enabled=1 AND s.enabled=1 AND p.next_at<=?',(now,))]
    for sid in due:
        try:start_run(connect,cipher,sid)
        except IntegrationError as e:
            with connect() as db:db.execute('UPDATE detection_plans SET next_at=?,status=? WHERE server_id=?',(now+60,str(e),sid))

def register(app,connect,cipher,auth,body,error,audit):
    @app.get('/api/detection')
    @auth(admin=True)
    def detection_overview():
        with connect() as db:
            sources=[{k:r[k] for k in ('id','name','kind','enabled')} for r in db.execute('SELECT * FROM detection_sources')]
            plans=[dict(r) for r in db.execute('SELECT * FROM detection_plans')]
            runs=[dict(r) for r in db.execute('SELECT id,server_id,source_id,ip,port,status,created,updated,details FROM detection_runs ORDER BY id DESC LIMIT 50')]
        for p in plans:p['nodes']=json.loads(p['nodes'])
        for r in runs:r['details']=json.loads(r['details'])
        return jsonify(sources=sources,plans=plans,runs=runs)

    @app.post('/api/detection/sources')
    @auth(admin=True)
    def detection_save_source():
        d=body();kind=d.get('kind');name=d.get('name','');secret=d.get('secret','');enabled=d.get('enabled',True)
        if kind not in ('boce','self') or not isinstance(name,str) or not 1<=len(name.strip())<=80 or not isinstance(secret,str) or len(secret)>4096 or type(enabled)is not bool:return error('检测来源格式无效')
        token=None
        with connect() as db:
            if d.get('id'):
                old=db.execute('SELECT * FROM detection_sources WHERE id=?',(d['id'],)).fetchone()
                if not old or old['kind']!=kind:return error('检测来源不存在或类型不可更改')
                if kind=='self' and secret:return error('自建探针密钥只能由系统生成')
                encrypted=cipher.encrypt(secret.encode()).decode() if secret else old['secret']
                db.execute('UPDATE detection_sources SET name=?,secret=?,enabled=? WHERE id=?',(name.strip(),encrypted,int(enabled),old['id']));sid=old['id']
            else:
                if kind=='self':secret=token=secrets.token_urlsafe(36)
                if not secret:return error('请填写 BOCE API Key')
                sid=db.execute('INSERT INTO detection_sources(name,kind,secret,enabled) VALUES(?,?,?,?)',(name.strip(),kind,cipher.encrypt(secret.encode()).decode(),int(enabled))).lastrowid
            audit(db,'保存检测来源 #'+str(sid))
        return jsonify(ok=True,id=sid,probe_token=token)

    @app.post('/api/detection/sources/<int:sid>/nodes')
    @auth(admin=True)
    def detection_nodes(sid):
        try:
            with connect() as db:s=db.execute('SELECT * FROM detection_sources WHERE id=?',(sid,)).fetchone()
            if not s or s['kind']!='boce':raise IntegrationError('请选择 BOCE 来源')
            result=boce(source_secret(s,cipher),'node/list') # No area parameter => mainland, per official docs.
            rows=result.get('data',{}).get('list')
            if not isinstance(rows,list):raise IntegrationError('节点列表格式异常')
            return jsonify(nodes=[{'id':str(r['id']),'name':str(r.get('node_name',''))[:80],'isp':str(r.get('isp_name',''))[:80]} for r in rows if isinstance(r,dict) and str(r.get('id','')).isdigit()])
        except IntegrationError as e:return error(str(e))

    @app.delete('/api/detection/sources/<int:sid>')
    @auth(admin=True)
    def detection_delete_source(sid):
        with connect() as db:
            if db.execute('SELECT 1 FROM detection_plans WHERE source_id=?',(sid,)).fetchone() or db.execute("SELECT 1 FROM detection_runs WHERE source_id=? AND status IN ('pending','queued','issued','creating')",(sid,)).fetchone():return error('来源仍被使用，请先更换或移除检测计划')
            db.execute('DELETE FROM detection_runs WHERE source_id=?',(sid,));db.execute('DELETE FROM detection_sources WHERE id=?',(sid,));audit(db,'删除检测来源 #'+str(sid))
        return jsonify(ok=True)

    @app.post('/api/detection/plans/<int:sid>')
    @auth(admin=True)
    def detection_save_plan(sid):
        d=body();ids=d.get('nodes',[]);interval=d.get('interval_s',600);limit=d.get('daily_limit',1000);automatic=d.get('automatic',False)
        if not isinstance(ids,list) or len(ids)>20 or any(not str(x).isdigit() for x in ids) or type(interval)is not int or not 120<=interval<=86400 or type(limit)is not int or not 1<=limit<=100000 or type(automatic)is not bool:return error('检测节点、频率或每日上限无效')
        with connect() as db:
            if not db.execute('SELECT 1 FROM ip_monitors WHERE server_id=?',(sid,)).fetchone():return error('请先选择被监控的 VPS')
            s=db.execute('SELECT * FROM detection_sources WHERE id=?',(d.get('source_id'),)).fetchone()
            if not s:return error('请选择检测来源')
            ids=sorted(set(map(str,ids))) if s['kind']=='boce' else ['self']
            if not ids:return error('请填写至少一个节点 ID')
            existing=db.execute('SELECT next_at FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
            db.execute('INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,daily_limit,next_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET source_id=excluded.source_id,nodes=excluded.nodes,interval_s=excluded.interval_s,automatic=excluded.automatic,daily_limit=excluded.daily_limit,status=\'等待新配置检测\',checked=NULL',(sid,s['id'],json.dumps(ids),interval,int(automatic),limit,existing['next_at'] if existing else 0))
            # Old source jobs can finish for history, but must not change the new plan status.
            audit(db,'配置 VPS 检测点 #'+str(sid))
        return jsonify(ok=True)

    @app.delete('/api/detection/plans/<int:sid>')
    @auth(admin=True)
    def detection_delete_plan(sid):
        with connect() as db:
            db.execute('DELETE FROM detection_plans WHERE server_id=?',(sid,));audit(db,'删除 VPS 检测计划 #'+str(sid))
        return jsonify(ok=True)

    @app.post('/api/detection/plans/<int:sid>/run')
    @auth(admin=True)
    def detection_run(sid):
        try:
            rid=start_run(connect,cipher,sid)
            with connect() as db:audit(db,'提交拨测任务 #'+str(rid))
            return jsonify(ok=True,id=rid)
        except IntegrationError as e:return error(str(e))

    def probe_source():
        bearer=request.headers.get('Authorization','')
        if not bearer.startswith('Bearer ') or len(bearer)>200:return None
        supplied=bearer[7:]
        with connect() as db:rows=db.execute("SELECT * FROM detection_sources WHERE kind='self' AND enabled=1").fetchall()
        return next((r for r in rows if secrets.compare_digest(source_secret(r,cipher),supplied)),None)

    @app.post('/api/probe/jobs')
    def detection_probe_jobs():
        s=probe_source()
        if not s:return error('探针认证失败',401)
        now=int(time.time())
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            r=db.execute("SELECT r.* FROM detection_runs r JOIN detection_plans p ON p.server_id=r.server_id JOIN ip_monitors m ON m.server_id=r.server_id WHERE r.source_id=? AND p.source_id=r.source_id AND m.enabled=1 AND r.status='queued' AND r.created>? ORDER BY r.id LIMIT 1",(s['id'],now-120)).fetchone()
            if not r:return jsonify(job=None)
            db.execute("UPDATE detection_runs SET status='issued',updated=? WHERE id=?",(now,r['id']))
        return jsonify(job={'id':r['id'],'ip':r['ip'],'port':r['port']})

    @app.post('/api/probe/results/<int:rid>')
    def detection_probe_result(rid):
        s=probe_source()
        if not s:return error('探针认证失败',401)
        d=body();reachable=d.get('reachable');latency=d.get('latency_ms')
        if type(reachable)is not bool or (latency is not None and (type(latency) not in (int,float) or not math.isfinite(latency) or not 0<=latency<=60000)):return error('结果格式无效')
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            r=db.execute("SELECT * FROM detection_runs WHERE id=? AND source_id=? AND status='issued' AND created>?",(rid,s['id'],int(time.time())-120)).fetchone()
            if not r:return error('任务不存在、已完成或过期',409)
            # Bind result to the exact issued target.
            if d.get('ip')!=r['ip'] or d.get('port')!=r['port']:return error('结果目标不匹配',409)
            state='reachable' if reachable else 'unreachable'
            finish(db,r,'自建探针 TCP 可达' if reachable else '自建探针 TCP 不通（待复核）',[{'node_id':'self','name':s['name'],'state':state,'latency_ms':latency}])
        return jsonify(ok=True)
