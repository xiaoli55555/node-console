"""Independent-point confirmation of the same TCP target; never invent primary evidence."""
import probe_groups
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from ip_dns import IntegrationError, candidate_ip

SCHEMA='''CREATE TABLE IF NOT EXISTS detection_rechecks(
 parent_id INTEGER PRIMARY KEY REFERENCES detection_runs(id) ON DELETE CASCADE,
 node TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'queued',remote_id TEXT,
 created INTEGER NOT NULL,submitted INTEGER,poll_at INTEGER NOT NULL DEFAULT 0,
 details TEXT NOT NULL DEFAULT '[]',message TEXT,applied INTEGER NOT NULL DEFAULT 0
);'''
PENDING=('creating','pending','queued','issued')
REFERENCE_HOST='www.baidu.com'
REFERENCE_HOSTS=('www.qq.com','www.baidu.com')
REFERENCE_PORT=80

def initialize(db):
    db.executescript(SCHEMA)
    db.executescript('''CREATE TABLE IF NOT EXISTS detection_guard_costs(id INTEGER PRIMARY KEY,parent_id INTEGER NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,primary_server_id INTEGER NOT NULL,reserved_at INTEGER NOT NULL,cost INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS guard_cost_day ON detection_guard_costs(primary_server_id,reserved_at);''')
    columns={x[1] for x in db.execute('PRAGMA table_info(detection_rechecks)')}
    for name,definition in [('stage',"TEXT NOT NULL DEFAULT 'reference'"),('reference_passed','INTEGER NOT NULL DEFAULT 0'),('reference_details',"TEXT NOT NULL DEFAULT '[]'"),('reference_checked','INTEGER'),('reference_jobs',"TEXT NOT NULL DEFAULT '{}'"),('confirm_source_id','INTEGER'),('confirm_signature','TEXT')]:
        if name not in columns:
            db.execute(f'ALTER TABLE detection_rechecks ADD COLUMN {name} {definition}')
    if 'reference_jobs' not in columns:
        db.execute("UPDATE detection_rechecks SET state='unknown',message='双参照站升级后等待新校验，不沿用在途单站任务' WHERE state IN ('queued','creating','pending')")
    if 'stage' not in columns:
        db.execute("UPDATE detection_rechecks SET state='unknown',message='升级后需要新的参照站校验，不沿用旧复测' WHERE state IN ('queued','creating','pending')")


def confirmation_source(db,p):
    sid=dict(p).get('confirm_source_id') or p['source_id']
    source=db.execute('SELECT * FROM detection_sources WHERE id=?',(sid,)).fetchone()
    if not source or not source['enabled'] or source['owner_id'] is not None:
        raise IntegrationError('复检来源已暂停或不可用')
    if source['kind']=='self':
        probe_groups.validate(db,source,[p['confirm_node']])
        return dict(source,probe_identity=probe_groups.identity(db,source['id'],p['confirm_node']))
    return source


def source_signature(source):
    return hashlib.sha256((str(source['id'])+'|'+source['kind']+'|'+source['secret']+('|' + str(dict(source)['probe_identity']) if 'probe_identity' in dict(source) else '')).encode()).hexdigest()


def reference_profile(db,r,p):
    if p['kind']!='self':return p
    source=confirmation_source(db,p)
    return source if source['kind']!='self' else None



def failed(rows,nodes):
    return bool(nodes) and isinstance(rows,list) and len(rows)==len(nodes) and all(isinstance(x,dict) for x in rows) and {str(x.get('node_id')) for x in rows}==set(map(str,nodes)) and all(x.get('state')=='unreachable' for x in rows)


def confirmed(db,plan,run):
    if not probe_groups.gate(db,run,'unreachable'):return False
    node=dict(plan).get('confirm_node')
    if not node:
        row=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(run['id'],)).fetchone()
        if not row:return None # Legacy evidence has no reference phase.
        return None if row['reference_passed'] and row['state']=='confirmed' and row['applied'] else False
    if not plan['automatic'] or not run['scheduled']:return False
    row=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(run['id'],)).fetchone()
    return bool(row and row['node']==node and (row['confirm_source_id'] or None)==(dict(plan).get('confirm_source_id') or None) and row['state']=='confirmed' and row['applied'] and (row['reference_passed'] or row['stage']=='self_pair'))


def enqueue(db,run,plan,rows,now):
    if not failed(rows,json.loads(run['nodes'])):return False
    node=plan['confirm_node'] or ''
    if node and not dict(plan).get('confirm_source_id') and node in set(map(str,json.loads(run['nodes']))):
        db.execute('UPDATE detection_plans SET status=? WHERE server_id=?',('复测点与首轮重复，不能确认故障，请重新选择',run['server_id']))
        return True
    try:source=confirmation_source(db,plan) if node else None
    except IntegrationError:
        db.execute('UPDATE detection_plans SET status=?,checked=?,failure_streak=0,failure_ip=NULL,failure_port=NULL WHERE server_id=?',('复检来源不可用，本轮不确认故障',now,run['server_id']))
        return True
    db.execute('INSERT OR IGNORE INTO detection_rechecks(parent_id,node,created,confirm_source_id,confirm_signature) VALUES(?,?,?,?,?)',(run['id'],node,now,dict(plan).get('confirm_source_id'),source_signature(source) if source else None))
    row=db.execute('SELECT state FROM detection_rechecks WHERE parent_id=?',(run['id'],)).fetchone()
    message=('首轮全部不通，等待独立来源复检同一 IP 和端口，尚未确认故障' if dict(plan).get('confirm_source_id') else '首轮全部不通，立即使用原检测点并行校验 www.qq.com:80 和 www.baidu.com:80；通过后再复测目标，尚未确认故障') if row['state'] in ('queued','creating','pending') else '独立复测已有结果，不重复提交或执行动作'
    db.execute('UPDATE detection_plans SET status=?,checked=? WHERE server_id=?',(message,now,run['server_id']))
    return True


def _valid(db,job,cipher,now):
    r=db.execute('SELECT * FROM detection_runs WHERE id=?',(job['parent_id'],)).fetchone()
    if not r:return None
    p=db.execute('SELECT p.*,s.kind,s.secret,s.enabled AS source_enabled FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(r['server_id'],)).fetchone()
    m=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(r['server_id'],)).fetchone()
    s=db.execute('SELECT seen FROM servers WHERE id=?',(r['server_id'],)).fetchone()
    if not p or not m or not s or not p['automatic'] or not p['source_enabled'] or not m['enabled']:return None
    fresh=bool(s['seen'] and 0<=now-s['seen']<=60)
    if (not dict(p).get('confirm_source_id') and job['node'] in set(map(str,json.loads(r['nodes'])))) or (p['confirm_node'] or '')!=job['node'] or p['source_id']!=r['source_id'] or p['nodes']!=r['nodes'] or m['port']!=r['port'] or not r['scheduled']:return None
    if (dict(job).get('confirm_source_id') or None)!=(dict(p).get('confirm_source_id') or None):return None
    if job['node']:
        try:cs=confirmation_source(db,p)
        except IntegrationError:return None
        if dict(job).get('confirm_signature') and source_signature(cs)!=job['confirm_signature']:return None
    if not 0<=now-r['updated']<=max(300,p['interval_s']*2):return None
    if db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND id>? AND status NOT IN ('creating','pending','queued','issued') LIMIT 1",(r['server_id'],r['id'])).fetchone():return None
    try:
        if not failed(json.loads(r['details']),json.loads(r['nodes'])):return None
        if fresh:
            if candidate_ip(db,m,cipher)!=r['ip']:return None
        else:
            # External diagnosis of this rotation's frozen old address only; never readiness.
            if m['source_id']:return None
            from rotation import heartbeat_probe_target
            if heartbeat_probe_target(db,r['server_id'],r['port'],now,run=r)!=r['ip']:return None
    except (IntegrationError,ValueError,TypeError):return None
    return r,p


def _stop(db,job,state,message,now):
    db.execute('UPDATE detection_rechecks SET state=?,message=? WHERE parent_id=?',(state,message,job['parent_id']))
    db.execute('UPDATE detection_plans SET status=?,checked=? WHERE server_id=(SELECT server_id FROM detection_runs WHERE id=?)',(message,now,job['parent_id']))
    if state=='unknown':
        current=db.execute('SELECT reference_jobs FROM detection_rechecks WHERE parent_id=?',(job['parent_id'],)).fetchone()
        if current:
            jobs=json.loads(current['reference_jobs'])
            for value in jobs.values():
                if value['state']=='creating':value.update(state='unknown',message='提交未确认，不重复提交')
            db.execute('UPDATE detection_rechecks SET reference_jobs=? WHERE parent_id=?',(json.dumps(jobs,sort_keys=True),job['parent_id']))
        db.execute("UPDATE detection_runs SET status='参照站／复测未确认，本轮不通判定已撤销' WHERE id=?",(job['parent_id'],))
        db.execute('UPDATE detection_plans SET failure_streak=0,failure_ip=NULL,failure_port=NULL WHERE server_id=(SELECT server_id FROM detection_runs WHERE id=?)',(job['parent_id'],))


def daily_usage(db,primary,today):
    shared=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_failover_probe_costs'").fetchone()
    guard="r.server_id=? OR r.id IN (SELECT run_id FROM vps_failover_probe_costs WHERE primary_server_id=?)" if shared else 'r.server_id=?'
    args=(today,primary,primary) if shared else (today,primary)
    base=db.execute('SELECT COALESCE(SUM(MAX(0,r.cost-COALESCE((SELECT SUM(g.cost) FROM detection_guard_costs g WHERE g.parent_id=r.id),0))),0) FROM detection_runs r WHERE r.created>=? AND ('+guard+')',args).fetchone()[0]
    extras=db.execute('SELECT COALESCE(SUM(cost),0) FROM detection_guard_costs WHERE primary_server_id=? AND reserved_at>=?',(primary,today)).fetchone()[0]
    return base+extras


def _budget(db,r,p,now,cost=1):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from failover import budget_primary
    today=datetime.fromtimestamp(now,ZoneInfo('Asia/Shanghai')).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()
    return daily_usage(db,budget_primary(db,r['server_id']),today)+cost<=p['daily_limit']


def _reserve_cost(db,r,cost,now):
    from failover import budget_primary
    db.execute('INSERT INTO detection_guard_costs(parent_id,primary_server_id,reserved_at,cost) VALUES(?,?,?,?)',(r['id'],budget_primary(db,r['server_id']),now,cost))
    db.execute('UPDATE detection_runs SET cost=cost+? WHERE id=?',(cost,r['id']))


def reference_nodes(r,job,p=None):
    if dict(job).get('confirm_source_id'):
        return [job['node']] if (p and p['kind']=='self') or json.loads(r['nodes'])==['self'] else list(map(str,json.loads(r['nodes'])))
    nodes=list(map(str,json.loads(r['nodes'])))
    if job['node'] and job['node'] not in nodes:nodes.append(job['node'])
    return nodes


def _provider_create(p,secret,host,port,nodes,identity,reference=False):
    import detectors as d
    if p['kind']=='boce':
        data=d.boce(secret,'task/create/tcping',{'node_ids':','.join(nodes),'host':host+':'+str(port)})
        remote=data.get('data',{}).get('id') if isinstance(data.get('data'),dict) else None
        if not isinstance(remote,str) or not remote or len(remote)>200 or any(c.isspace() or ord(c)<32 for c in remote):raise IntegrationError('未取得有效任务 ID')
        return remote
    if p['kind']=='baota':return d.baota_probe.create(secret,host,port,nodes,identity,reference=reference)
    if p['kind']=='aliyun':return d.aliyun_probe.create(secret,host,port,nodes,identity,reference=reference)
    raise IntegrationError('此来源不支持参照站检测')


def _provider_poll(p,secret,job,nodes):
    import detectors as d
    if p['kind']=='boce':
        import urllib.parse
        result=d.boce(secret,'task/tcping/'+urllib.parse.quote(job['remote_id'],safe=''))
        if type(result.get('done'))is not bool:raise IntegrationError('结果格式无效')
        if not result['done']:return None
        return d.summarize(result.get('list'),nodes)[1]
    if p['kind']=='baota':return d.baota_probe.poll(secret,job['remote_id'],nodes)
    return d.aliyun_probe.poll(secret,job['remote_id'],nodes,job['submitted'])


def _submit_references(db,job,r,p,cipher,now):
    import detectors as d
    profile=reference_profile(db,r,p)
    if profile is None:
        db.execute("UPDATE detection_rechecks SET stage='self_pair' WHERE parent_id=?",(r['id'],))
        return _submit(db,dict(job,stage='self_pair'),r,p,cipher,now)
    nodes=reference_nodes(r,job,p)
    if not _budget(db,r,p,now,len(nodes)*len(REFERENCE_HOSTS)):
        _stop(db,job,'unknown','双参照站检测额度不足，本轮不通判定已撤销',now);return False
    jobs={host:{'state':'creating','submitted':now,'poll_at':now,'details':[]} for host in REFERENCE_HOSTS}
    encoded=json.dumps(jobs,sort_keys=True)
    db.execute("UPDATE detection_rechecks SET state='creating',submitted=?,reference_jobs=? WHERE parent_id=?",(now,encoded,r['id']))
    _reserve_cost(db,r,len(nodes)*len(jobs),now)
    db.commit()
    secret=d.source_secret(profile,cipher)
    def submit(host):
        try:
            remote=_provider_create(profile,secret,host,80,nodes,'guard-'+host+'-'+str(r['id']),True)
            return host,dict(jobs[host],state='pending',remote_id=remote)
        except Exception:
            return host,dict(jobs[host],state='unknown',message='提交异常或响应不确定，不重复提交')
    with ThreadPoolExecutor(max_workers=2) as pool:results=dict(pool.map(submit,REFERENCE_HOSTS))
    # A settings change or another worker cannot be overwritten by a late POST.
    updated=db.execute("UPDATE detection_rechecks SET state='pending',reference_jobs=?,poll_at=?,message='www.qq.com:80 与 www.baidu.com:80 并行检测中' WHERE parent_id=? AND state='creating' AND reference_jobs=?",(json.dumps(results,sort_keys=True),now,r['id'],encoded)).rowcount
    if not updated:return False
    if all(x['state']=='unknown' for x in results.values()):
        _stop(db,job,'unknown','两个参照站提交均未确认，本轮不通判定已撤销',now)
    else:db.execute('UPDATE detection_plans SET status=?,checked=? WHERE server_id=?',('www.qq.com:80 与 www.baidu.com:80 并行检测中',now,r['server_id']))
    return True


def _poll_references(connect,cipher,parent_id,now):
    import detectors as d
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        current=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(parent_id,)).fetchone()
        if not current:return False
        job=dict(current);valid=_valid(db,job,cipher,now)
        jobs=json.loads(job['reference_jobs']);due=[]
        if not valid:
            for value in jobs.values():
                if value['state']=='pending':value.update(state='unknown',message='目标或配置变化，停止旧站点取结果')
            db.execute('UPDATE detection_rechecks SET reference_jobs=? WHERE parent_id=?',(json.dumps(jobs,sort_keys=True),parent_id))
            if job['stage']=='reference':db.execute("UPDATE detection_rechecks SET state='cancelled' WHERE parent_id=?",(parent_id,))
            return False
        r,p=valid
        for host,value in jobs.items():
            if value['state']!='pending':continue
            if now-value['submitted']>(300 if p['kind']=='baota' else 120):value.update(state='unknown',message='参照站超时，不能证明 VPS 故障',checked=now)
            elif value['poll_at']<=now:
                value['poll_at']=now+1;due.append(host)
        claimed=json.dumps(jobs,sort_keys=True)
        db.execute('UPDATE detection_rechecks SET reference_jobs=? WHERE parent_id=?',(claimed,parent_id))
        profile=reference_profile(db,r,p)
        db.commit()
    # HTTP waits never hold the SQLite writer lock for reference station checks.
    if profile is None:return False
    secret=d.source_secret(profile,cipher);nodes=reference_nodes(r,job,p)
    def poll(host):
        try:return host,_provider_poll(profile,secret,jobs[host],nodes),None
        except Exception:return host,[], '参照站接口异常，结果未知'
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(poll,due))
    for host,rows,error in results:
        if rows is not None:jobs[host].update(state='unknown' if error else 'completed',details=rows,checked=now,message=error or '已取得检测结果')
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        current=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(parent_id,)).fetchone()
        if not current or current['reference_jobs']!=claimed:return False
        valid=_valid(db,current,cipher,now)
        if not valid:return False
        r,p=valid
        db.execute('UPDATE detection_rechecks SET reference_jobs=? WHERE parent_id=?',(json.dumps(jobs,sort_keys=True),parent_id))
        if current['stage']!='reference' or current['state']!='pending':return False # Late results update display only.
        summaries=[]
        for node in nodes:
            choices=[x for station in jobs.values() if station['state']=='completed' for x in station['details'] if str(x.get('node_id'))==node]
            good=next((x for x in choices if x.get('state')=='reachable'),None)
            summaries.append(good or {'node_id':node,'state':'unknown','latency_ms':None})
        passed=all(x['state']=='reachable' for x in summaries)
        db.execute('UPDATE detection_rechecks SET reference_details=?,reference_checked=? WHERE parent_id=?',(json.dumps(summaries),now,parent_id))
        if not passed:
            if any(x['state']=='pending' for x in jobs.values()):return False
            _stop(db,current,'unknown','同一检测点的两个参照站均未通过，本轮不通判定已撤销，不换 IP',now);return True
        db.execute("UPDATE detection_rechecks SET reference_passed=1,stage='target',state='queued',remote_id=NULL,submitted=NULL,poll_at=0 WHERE parent_id=?",(parent_id,))
        if not current['node']:
            db.execute("UPDATE detection_rechecks SET state='confirmed',applied=1,message='双参照站校验通过；按原连续故障阈值处理' WHERE parent_id=?",(parent_id,))
            d.finish(db,r,'参照站通过；目标首轮不通（按连续故障阈值复核）',json.loads(r['details']),reference_confirmed=True)
        else:_submit(db,dict(current,stage='target',state='queued'),r,p,cipher,now)
        return True


def _submit(db,job,r,p,cipher,now):
    import detectors as d
    reference=job['stage']=='reference'
    if reference:return _submit_references(db,job,r,p,cipher,now)
    cs=confirmation_source(db,p)
    if cs['kind']=='self':
        db.execute("UPDATE detection_rechecks SET state='pending',submitted=?,remote_id='self:queued',poll_at=0,message='等待独立自建探针复检同一 IP 和端口' WHERE parent_id=?",(now,r['id']))
        return True
    nodes=list(map(str,json.loads(r['nodes']))) if reference else [job['node']]
    host,port=(REFERENCE_HOST,REFERENCE_PORT) if reference else (r['ip'],r['port'])
    if not _budget(db,r,p,now,len(nodes)):
        _stop(db,job,'unknown','参照站或复测额度不足，不能确认故障，不执行换 IP',now);return False
    db.execute("UPDATE detection_rechecks SET state='creating',submitted=?,remote_id=NULL WHERE parent_id=?",(now,r['id']))
    _reserve_cost(db,r,len(nodes),now)
    db.commit() # Durable one-time submission and quota reservation before network I/O.
    try:
        secret=d.source_secret(cs,cipher)
        if cs['kind']=='boce':
            data=d.boce(secret,'task/create/tcping',{'node_ids':','.join(nodes),'host':host+':'+str(port)})
            remote=data.get('data',{}).get('id') if isinstance(data.get('data'),dict) else None
            if not isinstance(remote,str) or not remote or len(remote)>200 or any(c.isspace() or ord(c)<32 for c in remote):raise IntegrationError('未取得有效任务 ID')
        elif cs['kind']=='baota':remote=d.baota_probe.create(secret,host,port,nodes,'guard-'+job['stage']+'-'+str(r['id']),reference=reference)
        elif cs['kind']=='aliyun':remote=d.aliyun_probe.create(secret,host,port,nodes,'guard-'+job['stage']+'-'+str(r['id']),reference=reference)
        else:raise IntegrationError('此来源不支持参照站检测')
        changed=db.execute("UPDATE detection_rechecks SET state='pending',remote_id=?,poll_at=? WHERE parent_id=? AND state='creating' AND stage IN ('target','self_pair') AND submitted=?",(remote,now,r['id'],now)).rowcount
        if not changed:return False
        message='参照站 www.baidu.com:80 检测中' if reference else '参照站已通过，独立复测点正在检测目标 IP'
        db.execute('UPDATE detection_rechecks SET message=? WHERE parent_id=?',(message,r['id']))
        db.execute('UPDATE detection_plans SET status=?,checked=? WHERE server_id=?',(message,now,r['server_id']))
        return True
    except IntegrationError:
        _stop(db,job,'unknown','参照站／复测提交异常或响应不确定，不自动重复提交；不能确认目标故障',now)
        return False


def _apply(db,job,r,p,now,rows):
    import detectors as d
    state='confirmed' if failed(rows,[job['node']]) else ('reachable' if len(rows)==1 and str(rows[0].get('node_id'))==job['node'] and rows[0].get('state')=='reachable' else 'unknown')
    db.execute('UPDATE detection_rechecks SET state=?,details=?,message=? WHERE parent_id=?',(state,json.dumps(rows),('两个独立自建探针复核；' if job['stage']=='self_pair' else '参照站通过；')+'独立复测 '+state,r['id']))
    if state=='confirmed':
        d.finish(db,r,'首轮与独立复测点均不通（已复核）',json.loads(r['details']),recheck_confirmed=True,reference_confirmed=True)
        db.execute('UPDATE detection_rechecks SET applied=1 WHERE parent_id=?',(r['id'],))
    else:
        db.execute("UPDATE detection_runs SET status='独立复测可达或未知，本轮不通判定已撤销' WHERE id=?",(r['id'],))
        db.execute('UPDATE detection_plans SET status=?,checked=?,failure_streak=0,failure_ip=NULL,failure_port=NULL WHERE server_id=?',('独立复测可达，本轮不确认故障' if state=='reachable' else '独立复测未知，本轮不确认故障',now,r['server_id']))


def _poll_target(connect,cipher,parent_id,now):
    import detectors as d
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(parent_id,)).fetchone()
        if not row or row['stage'] not in ('target','self_pair') or row['state']!='pending':return False
        job=dict(row);valid=_valid(db,job,cipher,now)
        if not valid:
            db.execute("UPDATE detection_rechecks SET state='cancelled',message='目标或配置变化，取消旧复检' WHERE parent_id=?",(parent_id,));return False
        r,p=valid
        if now-(job['submitted'] or job['created'])>(300 if confirmation_source(db,p)['kind']=='baota' else 120):
            _stop(db,job,'unknown','独立复测超时，本轮不通判定已撤销',now);return True
        cs=confirmation_source(db,p)
        if cs['kind']=='self':return False
        if job['poll_at']>now:return False
        claim=now+1
        db.execute('UPDATE detection_rechecks SET poll_at=? WHERE parent_id=?',(claim,parent_id));db.commit()
    try:rows=_provider_poll(cs,d.source_secret(cs,cipher),job,[job['node']]);error=False
    except Exception:rows=[];error=True
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(parent_id,)).fetchone()
        if not row or row['stage'] not in ('target','self_pair') or row['state']!='pending' or row['poll_at']!=claim or row['remote_id']!=job['remote_id']:return False
        valid=_valid(db,row,cipher,now)
        if not valid:
            db.execute("UPDATE detection_rechecks SET state='cancelled',message='目标或配置变化，丢弃迟到结果' WHERE parent_id=?",(parent_id,));return False
        if error:_stop(db,row,'unknown','独立复测接口异常，本轮不通判定已撤销',now);return True
        if rows is None:return False
        r,p=valid;_apply(db,row,r,p,now,rows);return True


def claim_self(db,source,cipher,now):
    rows=db.execute("SELECT c.* FROM detection_rechecks c JOIN detection_runs r ON r.id=c.parent_id WHERE COALESCE(c.confirm_source_id,r.source_id)=? AND c.node=? AND c.stage IN ('target','self_pair') AND c.state='pending' AND c.remote_id='self:queued' ORDER BY c.parent_id LIMIT 50",(source['id'],source.get('probe_node_id','self'))).fetchall()
    for job in rows:
        valid=_valid(db,job,cipher,now)
        if not valid:
            _stop(db,job,'cancelled','目标或配置变化，取消旧复检',now);continue
        if now-(job['submitted'] or job['created'])>120:
            _stop(db,job,'unknown','自建复检超时，不能确认故障',now);continue
        r,p=valid
        db.execute("UPDATE detection_rechecks SET remote_id='self:issued' WHERE parent_id=? AND remote_id='self:queued'",(r['id'],))
        return {'id':-r['id'],'ip':r['ip'],'port':r['port']}
    return None


def finish_self(db,source,cipher,parent_id,data,now):
    job=db.execute("SELECT c.* FROM detection_rechecks c JOIN detection_runs r ON r.id=c.parent_id WHERE c.parent_id=? AND COALESCE(c.confirm_source_id,r.source_id)=? AND c.node=? AND c.state='pending' AND c.remote_id='self:issued'",(parent_id,source['id'],source.get('probe_node_id','self'))).fetchone()
    if not job or now-(job['submitted'] or job['created'])>120:return False
    valid=_valid(db,job,cipher,now)
    if not valid:return False
    r,p=valid
    if data.get('ip')!=r['ip'] or type(data.get('port'))is not int or data['port']!=r['port']:return False
    rows=[{'node_id':source.get('probe_node_id','self'),'name':source.get('probe_node_name',source['name']),'state':'reachable' if data['reachable'] else 'unreachable','latency_ms':data.get('latency_ms')}]
    _apply(db,job,r,p,now,rows)
    return True


def tick(connect,cipher,server_ids=None):
    import detectors as d
    now=int(time.time());changed=False
    if server_ids is not None and not server_ids:return False
    clause='' if server_ids is None else ' AND parent_id IN (SELECT id FROM detection_runs WHERE server_id IN ('+','.join('?' for _ in server_ids)+'))'
    with connect() as db:jobs=[dict(x) for x in db.execute("SELECT * FROM detection_rechecks WHERE state IN ('queued','creating','pending')"+clause+' ORDER BY parent_id LIMIT 50',() if server_ids is None else tuple(server_ids))]
    with connect() as db:
        background=[x[0] for x in db.execute("SELECT parent_id FROM detection_rechecks WHERE stage!='reference' AND reference_jobs LIKE '%pending%' ORDER BY parent_id LIMIT 50")]
    for parent_id in background:_poll_references(connect,cipher,parent_id,now)
    for job in jobs:
        if job['stage']=='reference' and job['state']=='pending':
            changed=_poll_references(connect,cipher,job['parent_id'],now) or changed;continue
        if job['stage'] in ('target','self_pair') and job['state']=='pending':
            changed=_poll_target(connect,cipher,job['parent_id'],now) or changed;continue
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(job['parent_id'],)).fetchone()
            if not current or current['state'] not in ('queued','creating','pending'):continue
            job=dict(current);valid=_valid(db,job,cipher,now)
            if not valid:
                db.execute("UPDATE detection_rechecks SET state='cancelled',message='目标、配置或上报已变化，取消旧校验' WHERE parent_id=?",(job['parent_id'],));continue
            r,p=valid
            if job['state']=='creating':
                _stop(db,job,'unknown','提交结果未确认，不重复扣费；本轮不能判定故障',now);continue
            if job['state']=='queued':
                _submit(db,job,r,p,cipher,now);changed=True;continue
    return changed


def snapshot(db,parent_id):
    row=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(parent_id,)).fetchone()
    group=probe_groups.snapshot(db,parent_id)
    if not row:return {'probe_group':group} if group else None
    source=db.execute('SELECT name FROM detection_sources WHERE id=?',(row['confirm_source_id'],)).fetchone() if row['confirm_source_id'] else None
    confirmation={'source_id':row['confirm_source_id'],'source_name':source['name'] if source else '与首轮相同来源','node':row['node'],'state':row['state'],'details':json.loads(row['details'])} if row['node'] else None
    return {'probe_group':group,'confirmation':confirmation,'host':REFERENCE_HOST,'hosts':list(REFERENCE_HOSTS),'stations':[dict(value,host=host,port=80) for host,value in json.loads(row['reference_jobs']).items()],'port':REFERENCE_PORT,'parent_id':parent_id,
            'stage':row['stage'],'state':row['state'],'passed':bool(row['reference_passed']),'confirm_source_id':row['confirm_source_id'],'reference_required':row['stage']!='self_pair',
            'checked':row['reference_checked'],'details':json.loads(row['reference_details']),
            'message':row['message'] or '使用原检测点加测参照站，等待结果'}
