"""Replaceable detection sources: BOCE asynchronous tasks or authenticated self-hosted probes."""
import hashlib
import ipaddress
import json
import math
import secrets
import time
import urllib.parse
from flask import jsonify,request
from ip_dns import IntegrationError, request_json, candidate_ip, load_connection, invoke_change_ip_api

SCHEMA='''
CREATE TABLE IF NOT EXISTS detection_sources(id INTEGER PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,secret TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,last_seen INTEGER,verified_at INTEGER);
CREATE TABLE IF NOT EXISTS detection_plans(server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,source_id INTEGER NOT NULL REFERENCES detection_sources(id),nodes TEXT NOT NULL DEFAULT '[]',interval_s INTEGER NOT NULL DEFAULT 600,automatic INTEGER NOT NULL DEFAULT 0,daily_limit INTEGER NOT NULL DEFAULT 1000,next_at INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT '等待检测',checked INTEGER,response_mode TEXT NOT NULL DEFAULT 'none',action_connection_id INTEGER REFERENCES ip_connections(id),failure_threshold INTEGER NOT NULL DEFAULT 3,failure_streak INTEGER NOT NULL DEFAULT 0,failure_ip TEXT,failure_port INTEGER,last_action INTEGER);
CREATE TABLE IF NOT EXISTS detection_runs(id INTEGER PRIMARY KEY,server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,source_id INTEGER NOT NULL REFERENCES detection_sources(id),ip TEXT NOT NULL,port INTEGER NOT NULL,nodes TEXT NOT NULL,status TEXT NOT NULL,remote_id TEXT,created INTEGER NOT NULL,updated INTEGER NOT NULL,details TEXT NOT NULL DEFAULT '[]',poll_at INTEGER NOT NULL DEFAULT 0,cost INTEGER NOT NULL DEFAULT 0,scheduled INTEGER NOT NULL DEFAULT 0,action_result TEXT,action_status TEXT);
CREATE INDEX IF NOT EXISTS detection_pending ON detection_runs(status,poll_at);
'''

def initialize(connect):
    with connect() as db:
        db.executescript(SCHEMA)
        # Additive migrations preserve existing monitoring plans and run history.
        migrations={
            'detection_sources':{
                'last_seen':'INTEGER',
                'verified_at':'INTEGER',
            },
            'detection_plans':{
                'response_mode':"TEXT NOT NULL DEFAULT 'none'",
                'action_connection_id':'INTEGER REFERENCES ip_connections(id)',
                'failure_threshold':'INTEGER NOT NULL DEFAULT 3',
                'failure_streak':'INTEGER NOT NULL DEFAULT 0',
                'failure_ip':'TEXT',
                'failure_port':'INTEGER',
                'last_action':'INTEGER',
            },
            'detection_runs':{
                'scheduled':'INTEGER NOT NULL DEFAULT 0',
                'action_result':'TEXT',
                'action_status':'TEXT',
            },
        }
        for table,columns in migrations.items():
            existing={r[1] for r in db.execute('PRAGMA table_info('+table+')')}
            for name,definition in columns.items():
                if name not in existing:db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')

def boce(secret,path,params=None):
    # BOCE documents key and task parameters as query parameters; do not send form body
    # because its API may reject that as "auth fail key nil".
    query=urllib.parse.urlencode({'key':secret,**(params or {})})
    data=request_json('https://api.boce.com/v3/'+path+'?'+query)
    if not isinstance(data,dict):raise IntegrationError('BOCE API 返回格式错误（不是 JSON 对象）')
    code=data.get('error_code',0)
    if code not in (0,'0'):
        detail=str(data.get('error') or '').strip().replace(secret,'[已隐藏]')[:240]
        suffix=('：'+detail) if detail else ''
        raise IntegrationError('BOCE 返回错误码 '+str(code)[:40]+suffix)
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

def queue_reboot(db,sid,now):
    node=db.execute('SELECT metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
    if not node or not node['seen'] or now-node['seen']>60:return '未执行自动重启：服务器 agent 离线或上报已过期'
    try:metrics=json.loads(node['metrics'] or '{}')
    except (TypeError,ValueError):metrics={}
    if 'reboot' not in metrics.get('capabilities',[]):return '未执行自动重启：服务器 agent 不支持重启，请先更新 agent'
    if db.execute("SELECT 1 FROM commands WHERE server_id=? AND status IN ('queued','issued','accepted') AND created>=?",(sid,now-3600)).fetchone():
        return '未重复排队：此服务器最近已有重启任务'
    admin=db.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
    if not admin:return '未执行自动重启：找不到管理员账号'
    cur=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot','queued',?,?)",(sid,admin['id'],now,now))
    return '已排队自动重启命令 #'+str(cur.lastrowid)+'；agent 下次上报时执行'

def finish(db,run,status,rows):
    now=int(time.time())
    action_result=None
    action_status=None
    db.execute('UPDATE detection_runs SET status=?,details=?,updated=? WHERE id=?',(status,json.dumps(rows),now,run['id']))
    # Do not apply old source/IP results to a reconfigured plan or a changed target.
    plan=db.execute('SELECT p.*,s.enabled AS source_enabled FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(run['server_id'],)).fetchone()
    current=db.execute('SELECT current_ip,enabled FROM ip_monitors WHERE server_id=?',(run['server_id'],)).fetchone()
    if plan and plan['source_enabled'] and plan['source_id']==run['source_id'] and plan['nodes']==run['nodes'] and current and current['enabled'] and (not current['current_ip'] or current['current_ip']==run['ip']):
        scheduled=bool(run['scheduled']) if 'scheduled' in run.keys() else False
        streak=plan['failure_streak']
        if scheduled:
            complete_failure=bool(rows) and all(r.get('state')=='unreachable' for r in rows)
            if complete_failure:
                same_target=plan['failure_ip']==run['ip'] and plan['failure_port']==run['port']
                streak=streak+1 if same_target else 1
                db.execute('UPDATE detection_plans SET failure_streak=?,failure_ip=?,failure_port=? WHERE server_id=?',(streak,run['ip'],run['port'],run['server_id']))
                if plan['automatic'] and plan['response_mode'] in ('reboot','change_api') and streak>=plan['failure_threshold']:
                    if plan['last_action'] and now-plan['last_action']<3600:
                        action_result='已达到失败次数，仍在自动处理冷却期内（1 小时）'
                    else:
                        if plan['response_mode']=='reboot':
                            action_result=queue_reboot(db,run['server_id'],now)
                            action_status='queued' if action_result.startswith('已排队') else 'skipped'
                        elif plan['action_connection_id']:
                            action_result='换 IP API 已排队；为避免重复换 IP，不会自动重试请求'
                            action_status='queued'
                        else:
                            action_result='未执行换 IP：未配置 API 连接'
                            action_status='skipped'
                        if action_status:
                            db.execute('UPDATE detection_runs SET action_status=? WHERE id=?',(action_status,run['id']))
                        if action_status=='queued':
                            db.execute('UPDATE detection_plans SET last_action=?,failure_streak=0,failure_ip=NULL,failure_port=NULL WHERE server_id=?',(now,run['server_id']))
            else:
                streak=0
                db.execute('UPDATE detection_plans SET failure_streak=0,failure_ip=NULL,failure_port=NULL WHERE server_id=?',(run['server_id'],))
        plan_status=status
        if action_result:plan_status+='；'+action_result
        db.execute('UPDATE detection_plans SET status=?,checked=? WHERE server_id=?',(plan_status,now,run['server_id']))
    db.execute('UPDATE detection_runs SET action_result=COALESCE(?,action_result),action_status=COALESCE(?,action_status) WHERE id=?',(action_result,action_status,run['id']))

def start_run(connect,cipher,sid,scheduled=False):
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
        rid=db.execute("INSERT INTO detection_runs(server_id,source_id,ip,port,nodes,status,created,updated,poll_at,cost,scheduled) VALUES(?,?,?,?,?,'creating',?,?,?,?,?)",(sid,p['source_id'],ip,m['port'],json.dumps(nodes),now,now,now+10,cost,int(scheduled))).lastrowid
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
        try:start_run(connect,cipher,sid,scheduled=True)
        except IntegrationError as e:
            with connect() as db:db.execute('UPDATE detection_plans SET next_at=?,status=? WHERE server_id=?',(now+60,str(e),sid))
    execute_change_ip_actions(connect,cipher)

def execute_change_ip_actions(connect,cipher):
    """Claim each queued provider API action once; ambiguous failures are never retried."""
    now=int(time.time())
    with connect() as db:
        queued=[dict(r) for r in db.execute("SELECT r.id,r.server_id,r.ip,p.action_connection_id,s.name FROM detection_runs r JOIN detection_plans p ON p.server_id=r.server_id AND p.source_id=r.source_id JOIN detection_sources ds ON ds.id=p.source_id JOIN ip_monitors m ON m.server_id=r.server_id JOIN servers s ON s.id=r.server_id WHERE r.action_status='queued' AND r.scheduled=1 AND p.automatic=1 AND p.response_mode='change_api' AND p.action_connection_id IS NOT NULL AND ds.enabled=1 AND m.enabled=1 AND (m.current_ip IS NULL OR m.current_ip=r.ip) ORDER BY r.id LIMIT 20")]
    for item in queued:
        with connect() as db:
            if not db.execute("UPDATE detection_runs SET action_status='issued' WHERE id=? AND action_status='queued'",(item['id'],)).rowcount:continue
            try:connection=load_connection(db,cipher,item['action_connection_id'])
            except IntegrationError as e:
                db.execute("UPDATE detection_runs SET action_status='failed',action_result=? WHERE id=?",('换 IP API 配置失效：'+str(e),item['id']))
                continue
        try:
            if connection['kind']!='change_ip':raise IntegrationError('连接不是换 IP API')
            result=invoke_change_ip_api(connection,item['server_id'],item['name'],item['ip'])
            state='submitted'
        except IntegrationError as e:
            result='换 IP API 调用失败或结果不确定：'+str(e)+'；为避免重复操作不会自动重试'
            state='failed'
        with connect() as db:
            db.execute('UPDATE detection_runs SET action_status=?,action_result=? WHERE id=? AND action_status=\'issued\'',(state,result,item['id']))

def register(app,connect,cipher,auth,body,error,audit):
    @app.get('/api/detection')
    @auth(admin=True)
    def detection_overview():
        with connect() as db:
            sources=[{k:r[k] for k in ('id','name','kind','enabled','last_seen','verified_at')} for r in db.execute('SELECT * FROM detection_sources')]
            plans=[dict(r) for r in db.execute('SELECT * FROM detection_plans')]
            runs=[dict(r) for r in db.execute('SELECT id,server_id,source_id,ip,port,status,created,updated,details,action_result,action_status FROM detection_runs ORDER BY id DESC LIMIT 50')]
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
                db.execute('UPDATE detection_sources SET name=?,secret=?,enabled=?,verified_at=CASE WHEN ? THEN NULL ELSE verified_at END WHERE id=?',(name.strip(),encrypted,int(enabled),int(bool(secret)),old['id']));sid=old['id']
            else:
                if kind=='self':secret=token=secrets.token_urlsafe(36)
                if not secret:return error('请填写 BOCE API Key')
                sid=db.execute('INSERT INTO detection_sources(name,kind,secret,enabled) VALUES(?,?,?,?)',(name.strip(),kind,cipher.encrypt(secret.encode()).decode(),int(enabled))).lastrowid
            audit(db,'保存检测来源 #'+str(sid))
        return jsonify(ok=True,id=sid,probe_token=token)

    @app.post('/api/detection/sources/<int:sid>/test')
    @auth(admin=True)
    def detection_test_source(sid):
        """Test the source control channel without probing a VPS or triggering actions."""
        try:
            with connect() as db:s=db.execute('SELECT * FROM detection_sources WHERE id=?',(sid,)).fetchone()
            if not s:raise IntegrationError('检测来源不存在')
            if not s['enabled']:raise IntegrationError('检测来源已暂停，请先启用')
            now=int(time.time())
            if s['kind']=='boce':
                result=boce(source_secret(s,cipher),'node/list')
                rows=result.get('data',{}).get('list')
                if not isinstance(rows,list):raise IntegrationError('BOCE 节点列表格式异常')
                valid=sum(1 for r in rows if isinstance(r,dict) and str(r.get('id','')).isdigit())
                if not valid:raise IntegrationError('BOCE API 可连接，但没有返回可用检测节点')
                message=f'BOCE API 可用，读取到 {valid} 个检测节点；这只是连通性测试，不会提交收费拨测任务'
            elif s['kind']=='self':
                seen=s['last_seen']
                if not seen or now-int(seen)>35:raise IntegrationError('自建探针未在线：检查探针服务、面板 HTTPS 地址及密钥；在线后等待 10–35 秒再测试')
                message='自建探针在线，最近心跳 '+str(max(0,now-int(seen)))+' 秒前；实际 VPS 端口可达性需另行发起手动检测'
            else:raise IntegrationError('未知检测来源类型')
            with connect() as db:db.execute('UPDATE detection_sources SET verified_at=? WHERE id=?',(now,sid))
            return jsonify(ok=True,usable=True,kind=s['kind'],verified_at=now,message=message)
        except IntegrationError as e:
            with connect() as db:db.execute('UPDATE detection_sources SET verified_at=NULL WHERE id=?',(sid,))
            return error(str(e))

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
        d=body();ids=d.get('nodes',[]);interval=d.get('interval_s',600);limit=d.get('daily_limit',1000);automatic=d.get('automatic',False);response_mode=d.get('response_mode','none');action_connection_id=d.get('action_connection_id') or None;failure_threshold=d.get('failure_threshold',3)
        if not isinstance(ids,list) or len(ids)>20 or any(not str(x).isdigit() for x in ids) or type(interval)is not int or not 120<=interval<=86400 or type(limit)is not int or not 1<=limit<=100000 or type(automatic)is not bool or response_mode not in ('none','reboot','change_api') or type(failure_threshold)is not int or not 2<=failure_threshold<=5:return error('检测节点、频率、上限或自动处理策略无效')
        if response_mode!='none' and not automatic:return error('自动处理必须同时开启定时检测')
        if response_mode=='change_api' and type(action_connection_id)is not int:return error('请选择换 IP API 连接')
        if response_mode!='change_api':action_connection_id=None
        with connect() as db:
            if not db.execute('SELECT 1 FROM ip_monitors WHERE server_id=?',(sid,)).fetchone():return error('请先选择被监控的 VPS')
            s=db.execute('SELECT * FROM detection_sources WHERE id=?',(d.get('source_id'),)).fetchone()
            if not s:return error('请选择检测来源')
            if response_mode!='none' and (not s['verified_at'] or time.time()-s['verified_at']>900):return error('启用自动重启或换 IP 前，请先测试探测来源；测试结果 15 分钟内有效')
            if action_connection_id:
                action=db.execute('SELECT kind FROM ip_connections WHERE id=?',(action_connection_id,)).fetchone()
                if not action or action['kind']!='change_ip':return error('请选择有效的换 IP API 连接')
            ids=sorted(set(map(str,ids))) if s['kind']=='boce' else ['self']
            if not ids:return error('请填写至少一个节点 ID')
            existing=db.execute('SELECT next_at FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
            db.execute("UPDATE detection_runs SET action_status='cancelled',action_result='检测配置已更新，未发送换 IP 请求' WHERE server_id=? AND action_status='queued'",(sid,))
            db.execute('INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,automatic,daily_limit,next_at,response_mode,action_connection_id,failure_threshold,failure_streak,failure_ip,failure_port,last_action) VALUES(?,?,?,?,?,?,?,?,?,?,0,NULL,NULL,NULL) ON CONFLICT(server_id) DO UPDATE SET source_id=excluded.source_id,nodes=excluded.nodes,interval_s=excluded.interval_s,automatic=excluded.automatic,daily_limit=excluded.daily_limit,response_mode=excluded.response_mode,action_connection_id=excluded.action_connection_id,failure_threshold=excluded.failure_threshold,failure_streak=0,failure_ip=NULL,failure_port=NULL,last_action=NULL,status=\'等待新配置检测\',checked=NULL',(sid,s['id'],json.dumps(ids),interval,int(automatic),limit,existing['next_at'] if existing else 0,response_mode,action_connection_id,failure_threshold))
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
            rid=start_run(connect,cipher,sid,scheduled=False)
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
            db.execute('UPDATE detection_sources SET last_seen=? WHERE id=?',(now,s['id']))
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
