"""Independent-point confirmation of the same TCP target; never invent primary evidence."""
import json
import time
from ip_dns import IntegrationError, candidate_ip

SCHEMA='''CREATE TABLE IF NOT EXISTS detection_rechecks(
 parent_id INTEGER PRIMARY KEY REFERENCES detection_runs(id) ON DELETE CASCADE,
 node TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'queued',remote_id TEXT,
 created INTEGER NOT NULL,submitted INTEGER,poll_at INTEGER NOT NULL DEFAULT 0,
 details TEXT NOT NULL DEFAULT '[]',message TEXT,applied INTEGER NOT NULL DEFAULT 0
);'''
PENDING=('creating','pending','queued','issued')


def failed(rows,nodes):
    return bool(nodes) and isinstance(rows,list) and len(rows)==len(nodes) and all(isinstance(x,dict) for x in rows) and {str(x.get('node_id')) for x in rows}==set(map(str,nodes)) and all(x.get('state')=='unreachable' for x in rows)


def confirmed(db,plan,run):
    node=dict(plan).get('confirm_node')
    if not node:return None
    if not plan['automatic'] or not run['scheduled']:return False
    row=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(run['id'],)).fetchone()
    return bool(row and row['node']==node and row['state']=='confirmed' and row['applied'])


def enqueue(db,run,plan,rows,now):
    if not failed(rows,json.loads(run['nodes'])):return False
    if plan['confirm_node'] in set(map(str,json.loads(run['nodes']))):
        db.execute('UPDATE detection_plans SET status=? WHERE server_id=?',('复测点与首轮重复，不能确认故障，请重新选择',run['server_id']))
        return True
    db.execute('INSERT OR IGNORE INTO detection_rechecks(parent_id,node,created) VALUES(?,?,?)',(run['id'],plan['confirm_node'],now))
    row=db.execute('SELECT state FROM detection_rechecks WHERE parent_id=?',(run['id'],)).fetchone()
    message='首轮全部不通，等待独立复测点 #'+plan['confirm_node']+' 检测同一 IP；尚未确认故障' if row['state'] in ('queued','creating','pending') else '独立复测已有结果，不重复提交或执行动作'
    db.execute('UPDATE detection_plans SET status=?,checked=? WHERE server_id=?',(message,now,run['server_id']))
    return True


def _valid(db,job,cipher,now):
    r=db.execute('SELECT * FROM detection_runs WHERE id=?',(job['parent_id'],)).fetchone()
    if not r:return None
    p=db.execute('SELECT p.*,s.kind,s.secret,s.enabled AS source_enabled FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(r['server_id'],)).fetchone()
    m=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(r['server_id'],)).fetchone()
    s=db.execute('SELECT seen FROM servers WHERE id=?',(r['server_id'],)).fetchone()
    if not p or not m or not s or not p['automatic'] or not p['source_enabled'] or not m['enabled'] or not s['seen'] or not 0<=now-s['seen']<=60:return None
    if job['node'] in set(map(str,json.loads(r['nodes']))) or p['confirm_node']!=job['node'] or p['source_id']!=r['source_id'] or p['nodes']!=r['nodes'] or m['port']!=r['port'] or not r['scheduled']:return None
    if not 0<=now-r['updated']<=max(300,p['interval_s']*2):return None
    if db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND id>? AND status NOT IN ('creating','pending','queued','issued') LIMIT 1",(r['server_id'],r['id'])).fetchone():return None
    try:
        if candidate_ip(db,m,cipher)!=r['ip'] or not failed(json.loads(r['details']),json.loads(r['nodes'])):return None
    except (IntegrationError,ValueError,TypeError):return None
    return r,p


def _stop(db,job,state,message,now):
    db.execute('UPDATE detection_rechecks SET state=?,message=? WHERE parent_id=?',(state,message,job['parent_id']))
    db.execute('UPDATE detection_plans SET status=?,checked=? WHERE server_id=(SELECT server_id FROM detection_runs WHERE id=?)',(message,now,job['parent_id']))


def _budget(db,r,p,now):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from failover import budget_primary
    today=datetime.fromtimestamp(now,ZoneInfo('Asia/Shanghai')).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()
    primary=budget_primary(db,r['server_id'])
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_failover_probe_costs'").fetchone():
        used=db.execute('SELECT COALESCE(SUM(cost),0) FROM detection_runs WHERE created>=? AND (server_id=? OR id IN (SELECT run_id FROM vps_failover_probe_costs WHERE primary_server_id=?))',(today,primary,primary)).fetchone()[0]
    else:used=db.execute('SELECT COALESCE(SUM(cost),0) FROM detection_runs WHERE server_id=? AND created>=?',(r['server_id'],today)).fetchone()[0]
    return used+1<=p['daily_limit']


def tick(connect,cipher,server_ids=None):
    import detectors as d
    now=int(time.time())
    if server_ids is not None and not server_ids:return
    clause='' if server_ids is None else ' AND parent_id IN (SELECT id FROM detection_runs WHERE server_id IN ('+','.join('?' for _ in server_ids)+'))'
    with connect() as db:jobs=[dict(x) for x in db.execute("SELECT * FROM detection_rechecks WHERE state IN ('queued','creating','pending')"+clause+' ORDER BY parent_id LIMIT 50',() if server_ids is None else tuple(server_ids))]
    for job in jobs:
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT * FROM detection_rechecks WHERE parent_id=?',(job['parent_id'],)).fetchone()
            if not current or current['state'] not in ('queued','creating','pending'):continue
            job=dict(current)
            valid=_valid(db,job,cipher,now)
            if not valid:
                # Preserve the new plan's status after reconfiguration.
                db.execute("UPDATE detection_rechecks SET state='cancelled',message='配置、当前 IP、端口、在线状态或最新结果已变化，取消旧复测' WHERE parent_id=?",(job['parent_id'],));continue
            r,p=valid
            if job['state']=='creating':
                _stop(db,job,'unknown','复测提交结果未确认，不重复扣费；本轮不能判定故障',now);continue
            if job['state']=='queued':
                if not _budget(db,r,p,now):
                    _stop(db,job,'unknown','复测额度不足，不能确认故障，不执行换 IP',now);continue
                db.execute("UPDATE detection_rechecks SET state='creating',submitted=? WHERE parent_id=?",(now,r['id']))
                db.execute('UPDATE detection_runs SET cost=cost+1 WHERE id=?',(r['id'],))
                db.commit() # Reserve cost and the single POST attempt before network I/O.
                try:
                    secret=d.source_secret(p,cipher);nodes=[job['node']]
                    if p['kind']=='boce':
                        data=d.boce(secret,'task/create/tcping',{'node_ids':job['node'],'host':r['ip']+':'+str(r['port'])})
                        remote=data.get('data',{}).get('id') if isinstance(data.get('data'),dict) else None
                        if not isinstance(remote,str) or not remote or len(remote)>200 or any(c.isspace() or ord(c)<32 for c in remote):raise IntegrationError('复测未取得有效任务 ID')
                    elif p['kind']=='baota':remote=d.baota_probe.create(secret,r['ip'],r['port'],nodes,'recheck-'+str(r['id']))
                    elif p['kind']=='aliyun':remote=d.aliyun_probe.create(secret,r['ip'],r['port'],nodes,'recheck-'+str(r['id']))
                    else:raise IntegrationError('此来源不支持独立节点复测')
                    db.execute("UPDATE detection_rechecks SET state='pending',remote_id=?,poll_at=? WHERE parent_id=?",(remote,now+1,r['id']))
                except IntegrationError:
                    _stop(db,job,'unknown','复测提交异常或响应不确定，不自动重试；本轮不能判定故障',now)
                continue
            if now-(job['submitted'] or job['created'])>(300 if p['kind']=='baota' else 120):
                _stop(db,job,'unknown','独立复测超时，不能判定故障，不执行换 IP',now);continue
            if job['poll_at']>now:continue
            db.execute('UPDATE detection_rechecks SET poll_at=? WHERE parent_id=?',(now+5,r['id']))
            try:
                secret=d.source_secret(p,cipher);nodes=[job['node']]
                if p['kind']=='boce':
                    import urllib.parse
                    result=d.boce(secret,'task/tcping/'+urllib.parse.quote(job['remote_id'],safe=''))
                    if type(result.get('done'))is not bool:raise IntegrationError('复测结果格式无效')
                    if not result['done']:continue
                    _,rows=d.summarize(result.get('list'),nodes)
                elif p['kind']=='baota':rows=d.baota_probe.poll(secret,job['remote_id'],nodes)
                else:rows=d.aliyun_probe.poll(secret,job['remote_id'],nodes,job['submitted'])
                if rows is None:continue
            except IntegrationError:
                _stop(db,job,'unknown','独立复测接口异常，不能判定故障，不执行换 IP',now);continue
            state='confirmed' if failed(rows,nodes) else ('reachable' if len(rows)==1 and str(rows[0].get('node_id'))==job['node'] and rows[0].get('state')=='reachable' else 'unknown')
            db.execute('UPDATE detection_rechecks SET state=?,details=?,message=? WHERE parent_id=?',(state,json.dumps(rows),'独立复测 '+state,r['id']))
            if state=='confirmed':
                # One completed primary run plus one independent failed point is
                # one confirmed incident, not fabricated repeated primary runs.
                d.finish(db,r,'首轮与独立复测点均不通（已复核）',json.loads(r['details']),recheck_confirmed=True)
                db.execute('UPDATE detection_rechecks SET applied=1 WHERE parent_id=?',(r['id'],))
            else:
                db.execute('UPDATE detection_plans SET status=?,checked=?,failure_streak=0,failure_ip=NULL,failure_port=NULL WHERE server_id=?',('独立复测可达，本轮不确认故障' if state=='reachable' else '独立复测未知，本轮不确认故障',now,r['server_id']))
