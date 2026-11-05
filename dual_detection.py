"""Two independent sources per round. Preserve raw evidence; only both failures authorize failure."""
import probe_groups
import hashlib
import json
import time
from ip_dns import IntegrationError, candidate_ip

SELF_OFFSET=1000000000000
PENDING=('queued','creating','pending','issued')


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS detection_dual_runs(
      parent_id INTEGER PRIMARY KEY REFERENCES detection_runs(id) ON DELETE CASCADE,
      source_id INTEGER NOT NULL,nodes TEXT NOT NULL,signature TEXT NOT NULL,
      state TEXT NOT NULL DEFAULT 'collecting',decision TEXT NOT NULL DEFAULT 'pending',
      primary_done INTEGER NOT NULL DEFAULT 0,primary_status TEXT,primary_details TEXT NOT NULL DEFAULT '[]',
      secondary_state TEXT NOT NULL DEFAULT 'queued',secondary_details TEXT NOT NULL DEFAULT '[]',
      remote_id TEXT,submitted INTEGER,poll_at INTEGER NOT NULL DEFAULT 0,message TEXT)''')


def enabled(p):return bool(dict(p).get('dual_source_id'))


def signature(db,p,port):
    sources=[]
    for sid in (p['source_id'],dict(p).get('dual_source_id')):
        row=db.execute('SELECT id,kind,secret,enabled FROM detection_sources WHERE id=?',(sid,)).fetchone()
        selected=json.loads(p['nodes'] if sid==p['source_id'] else dict(p).get('dual_nodes','[]'))
        sources.append([list(row),[probe_groups.identity(db,sid,n) for n in selected] if row['kind']=='self' else []] if row else None)
    values=[sources,p['nodes'],dict(p).get('dual_nodes','[]'),port,dict(p).get('confirm_source_id'),dict(p).get('confirm_node')]
    return hashlib.sha256(json.dumps(values,sort_keys=True).encode()).hexdigest()


def second(db,p):
    source=db.execute('SELECT * FROM detection_sources WHERE id=?',(p['dual_source_id'],)).fetchone()
    if not source or not source['enabled']:raise IntegrationError('第二探测来源不可用')
    nodes=json.loads(p['dual_nodes'])
    if not nodes:raise IntegrationError('请选择第二来源的节点')
    return source,nodes


def extra_cost(db,p):
    if not enabled(p):return 0
    source,nodes=second(db,p)
    return 0 if source['kind']=='self' else len(nodes)


def create(db,p,run):
    if not enabled(p):return
    db.execute('INSERT INTO detection_dual_runs(parent_id,source_id,nodes,signature) VALUES(?,?,?,?)',
               (run['id'],p['dual_source_id'],p['dual_nodes'],signature(db,p,run['port'])))
    source,nodes=second(db,p)
    if source['kind']=='self':probe_groups.create_tasks(db,run,source['id'],nodes,kind='dual')


def valid(db,group):
    run=db.execute('SELECT * FROM detection_runs WHERE id=?',(group['parent_id'],)).fetchone()
    if not run:return None
    plan=db.execute('SELECT p.*,m.port,m.enabled AS monitor_enabled,m.current_ip,m.source_id AS ip_source_id FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(run['server_id'],)).fetchone()
    if not plan or not enabled(plan) or not plan['monitor_enabled']:return None
    if plan['source_id']!=run['source_id'] or plan['nodes']!=run['nodes'] or plan['port']!=run['port']:return None
    if plan['current_ip'] and plan['current_ip']!=run['ip']:return None
    if not plan['ip_source_id']:
        seen=db.execute('SELECT seen FROM servers WHERE id=?',(run['server_id'],)).fetchone()
        if seen and seen['seen'] and 0<=int(time.time())-seen['seen']<=90:
            try:
                if candidate_ip(db,{'server_id':run['server_id'],'source_id':None},None)!=run['ip']:return None
            except IntegrationError:return None
    if signature(db,plan,run['port'])!=group['signature']:return None
    states=db.execute('SELECT enabled FROM detection_sources WHERE id IN (?,?)',(run['source_id'],group['source_id'])).fetchall()
    if len(states)!=2 or not all(x['enabled'] for x in states):return None
    return run,plan


def gate(db,run,wanted):
    if not probe_groups.evidence_valid(db,run) or not probe_groups.selection_matches(db,run,wanted):return False
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detection_dual_runs'").fetchone():return True
    group=db.execute('SELECT * FROM detection_dual_runs WHERE parent_id=?',(run['id'],)).fetchone()
    if not group:
        p=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(run['server_id'],)).fetchone()
        return not p or not enabled(p)
    if group['state']!='done' or group['decision']!=wanted or not valid(db,group):return False
    if wanted=='unreachable':
        # Alibaba remains observation-only, including when used as the second source.
        if db.execute("SELECT 1 FROM detection_sources WHERE id IN (?,?) AND kind='aliyun'",(run['source_id'],group['source_id'])).fetchone():return False
    return True


def _state(rows,nodes):
    if not isinstance(rows,list) or len(rows)!=len(nodes) or not rows or any(not isinstance(x,dict) for x in rows):return 'unknown'
    if {str(x.get('node_id')) for x in rows}!=set(map(str,nodes)):return 'unknown'
    if all(x.get('state')=='reachable' for x in rows):return 'reachable'
    if all(x.get('state')=='unreachable' for x in rows):return 'unreachable'
    return 'unknown'


def cancel(db,group):
    db.execute('UPDATE detection_plans SET failure_streak=0,failure_ip=NULL,failure_port=NULL WHERE server_id=(SELECT server_id FROM detection_runs WHERE id=?)',(group['parent_id'],))
    db.execute("UPDATE detection_dual_runs SET state='cancelled',decision='unknown',message='目标、来源或配置变化，丢弃旧轮结果' WHERE parent_id=?",(group['parent_id'],))
    db.execute("UPDATE detection_runs SET status='双来源旧轮已取消，不能确认故障' WHERE id=? AND status IN ('creating','queued','pending','issued','dual_waiting')",(group['parent_id'],))


def finalize(db,parent_id):
    import detectors
    group=db.execute('SELECT * FROM detection_dual_runs WHERE parent_id=?',(parent_id,)).fetchone()
    if not group or group['state']!='collecting':return
    current=valid(db,group)
    if not current:cancel(db,group);return
    if not group['primary_done'] or group['secondary_state'] in PENDING:return
    run,plan=current
    primary=json.loads(group['primary_details']);secondary=json.loads(group['secondary_details'])
    a=_state(primary,json.loads(run['nodes']));b=_state(secondary,json.loads(group['nodes']))
    decision=a if a==b and a in ('reachable','unreachable') else ('mixed' if 'reachable' in (a,b) else 'unknown')
    message={'reachable':'两个来源均可达','unreachable':'两个来源均明确不通，按故障阈值与复检策略处理','mixed':'双来源结果不同，不确认故障','unknown':'双来源结果不完整或未知，不确认故障'}[decision]
    db.execute("UPDATE detection_dual_runs SET state='done',decision=?,message=? WHERE parent_id=? AND state='collecting'",(decision,message,parent_id))
    # Preserve the first source's original node evidence; no synthetic successes/failures.
    db.execute("UPDATE detection_runs SET status='pending' WHERE id=?",(parent_id,))
    detectors.finish(db,run,message,primary,dual_ready=True)


def capture(db,run,status,rows):
    group=db.execute('SELECT * FROM detection_dual_runs WHERE parent_id=?',(run['id'],)).fetchone()
    if not group:
        p=db.execute('SELECT * FROM detection_plans WHERE server_id=?',(run['server_id'],)).fetchone()
        if p and enabled(p):
            db.execute("UPDATE detection_runs SET status='旧单来源结果，不参与双来源判定',details=? WHERE id=?",(json.dumps(rows),run['id']))
            return True
        return False
    if group['state']!='collecting':
        if group['state']=='cancelled':db.execute("UPDATE detection_runs SET status='双来源旧轮已取消' WHERE id=? AND status IN ('creating','queued','pending','issued','dual_waiting')",(run['id'],))
        return True
    if not valid(db,group):cancel(db,group);return True
    if not group['primary_done']:
        db.execute('UPDATE detection_dual_runs SET primary_done=1,primary_status=?,primary_details=? WHERE parent_id=?',(status,json.dumps(rows),run['id']))
        db.execute("UPDATE detection_runs SET status='dual_waiting',details=? WHERE id=?",(json.dumps(rows),run['id']))
        db.execute("UPDATE detection_plans SET status='首轮已返回，等待第二来源结果' WHERE server_id=?",(run['server_id'],))
    finalize(db,run['id'])
    return True


def _complete(db,group,rows):
    db.execute("UPDATE detection_dual_runs SET secondary_state='done',secondary_details=? WHERE parent_id=? AND state='collecting'",(json.dumps(rows),group['parent_id']))
    finalize(db,group['parent_id'])


def claim_self(db,source,now):
    task=probe_groups.claim(db,source,now,kind='dual')
    if task:return task
    if source.get('probe_node_id','self')!='self':return None
    for group in db.execute("SELECT * FROM detection_dual_runs WHERE source_id=? AND state='collecting' AND secondary_state='queued' AND NOT EXISTS(SELECT 1 FROM self_probe_tasks t WHERE t.parent_id=detection_dual_runs.parent_id AND t.kind='dual') ORDER BY parent_id LIMIT 50",(source['id'],)).fetchall():
        current=valid(db,group)
        if not current:cancel(db,group);continue
        run,_=current
        if now-run['created']>120:_complete(db,group,[]);continue
        db.execute("UPDATE detection_dual_runs SET secondary_state='issued',submitted=? WHERE parent_id=?",(now,run['id']))
        return {'id':-(SELF_OFFSET+run['id']),'ip':run['ip'],'port':run['port']}
    return None


def finish_self(db,source,parent_id,data,now):
    group=db.execute("SELECT * FROM detection_dual_runs WHERE parent_id=? AND source_id=? AND state='collecting' AND secondary_state='issued'",(parent_id,source['id'])).fetchone()
    if not group:return False
    current=valid(db,group)
    if not current:cancel(db,group);return False
    run,_=current
    if now-run['created']>120 or data.get('ip')!=run['ip'] or type(data.get('port'))is not int or data['port']!=run['port']:return False
    receipt=probe_groups.receive(db,source,run,data,kind='dual')
    if receipt is not None:
        if not receipt:return False
        rows=probe_groups.completed(db,run,kind='dual')
        if rows is not None:_complete(db,group,rows)
        return True
    if source.get('probe_node_id','self')!='self':return False
    _complete(db,group,[{'node_id':'self','name':source['name'],'state':'reachable' if data['reachable'] else 'unreachable','latency_ms':data.get('latency_ms')}])
    return True


def tick(connect,cipher,server_ids=None):
    import detection_recheck as recheck
    import detectors
    now=int(time.time())
    if server_ids is not None and not server_ids:return
    scope='' if server_ids is None else ' AND r.server_id IN ('+','.join('?' for _ in server_ids)+')'
    with connect() as db:
        groups=[dict(x) for x in db.execute("SELECT g.* FROM detection_dual_runs g JOIN detection_runs r ON r.id=g.parent_id WHERE g.state='collecting'"+scope+' ORDER BY g.parent_id LIMIT 100',() if server_ids is None else tuple(server_ids))]
    for group in groups:
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT * FROM detection_dual_runs WHERE parent_id=?',(group['parent_id'],)).fetchone()
            if not current or current['state']!='collecting':continue
            value=valid(db,current)
            if not value:cancel(db,current);continue
            run,plan=value
            if server_ids is not None and run['server_id'] not in server_ids:continue
            source,nodes=second(db,plan)
            timeout=300 if source['kind']=='baota' else 120
            if now-run['created']>timeout:
                if not current['primary_done']:
                    db.execute("UPDATE detection_dual_runs SET primary_done=1,primary_status='检测超时',primary_details='[]' WHERE parent_id=?",(run['id'],))
                if current['secondary_state'] in PENDING:_complete(db,current,[])
                else:finalize(db,run['id'])
                continue
            state=current['secondary_state']
            if source['kind']=='self':continue
            if state=='creating':continue # Uncertain submission is never repeated.
            if state not in ('queued','pending') or current['poll_at']>now:continue
            creating=state=='queued'
            if creating:db.execute("UPDATE detection_dual_runs SET secondary_state='creating',submitted=?,poll_at=? WHERE parent_id=?",(now,now+5,run['id']))
            else:db.execute('UPDATE detection_dual_runs SET poll_at=? WHERE parent_id=?',(now+5,run['id']))
            claim=now+5
            job=dict(current,submitted=now if creating else current['submitted'])
            db.commit()
        try:
            secret=detectors.source_secret(source,cipher)
            if creating:
                remote=recheck._provider_create(source,secret,run['ip'],run['port'],nodes,'dual-'+str(run['id']))
                rows=None
            else:rows=recheck._provider_poll(source,secret,job,nodes)
        except Exception:
            rows=[];remote=None
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT * FROM detection_dual_runs WHERE parent_id=?',(run['id'],)).fetchone()
            if not current or current['state']!='collecting' or current['poll_at']!=claim or current['secondary_state']!=('creating' if creating else 'pending'):continue
            if not valid(db,current):cancel(db,current);continue
            if creating and rows is None:
                db.execute("UPDATE detection_dual_runs SET secondary_state='pending',remote_id=? WHERE parent_id=?",(remote,run['id']))
            elif rows is not None:_complete(db,current,rows)


def snapshot(db,parent_id):
    group=db.execute('SELECT * FROM detection_dual_runs WHERE parent_id=?',(parent_id,)).fetchone()
    if not group:return None
    run=db.execute('SELECT source_id FROM detection_runs WHERE id=?',(parent_id,)).fetchone()
    def name(sid):
        r=db.execute('SELECT name FROM detection_sources WHERE id=?',(sid,)).fetchone()
        return r['name'] if r else '已删除来源'
    return {'state':group['state'],'decision':group['decision'],'message':group['message'],
            'sources':[{'source_id':run['source_id'],'name':name(run['source_id']),'state':'done' if group['primary_done'] else ('pending' if group['state']=='collecting' else 'unknown'),'details':json.loads(group['primary_details'])},
                       {'source_id':group['source_id'],'name':name(group['source_id']),'state':('unknown' if group['state']=='cancelled' and group['secondary_state'] in PENDING else group['secondary_state']),'details':json.loads(group['secondary_details'])}]}
