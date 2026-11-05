"""Independent probe identities and per-node tasks inside one self-hosted source."""
import hashlib
import json
import secrets
import time
from ip_dns import IntegrationError, candidate_ip


def initialize(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS self_probe_nodes(
      id INTEGER PRIMARY KEY,source_id INTEGER NOT NULL REFERENCES detection_sources(id) ON DELETE CASCADE,
      name TEXT NOT NULL,secret TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,last_seen INTEGER);
      CREATE TABLE IF NOT EXISTS self_probe_tasks(
      parent_id INTEGER NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,node_id TEXT NOT NULL,source_id INTEGER NOT NULL,
      identity TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'queued',details TEXT,
      PRIMARY KEY(parent_id,kind,node_id));
      CREATE INDEX IF NOT EXISTS self_probe_queue ON self_probe_tasks(source_id,node_id,state);''')

    columns={r[1] for r in db.execute('PRAGMA table_info(self_probe_tasks)')}
    if 'claimed_at' not in columns:db.execute('ALTER TABLE self_probe_tasks ADD COLUMN claimed_at INTEGER')

def nodes(db,source):
    now=int(time.time())
    result=[{'id':'self','name':source['name'],'isp':'自建探针','enabled':True,'last_seen':source['last_seen'],
             'online':bool(source['enabled'] and source['last_seen'] and 0<=now-source['last_seen']<=35)}]
    for r in db.execute('SELECT id,name,enabled,last_seen FROM self_probe_nodes WHERE source_id=? ORDER BY id',(source['id'],)):
        result.append({'id':'probe-'+str(r['id']),'name':r['name'],'isp':'自建探针','enabled':bool(r['enabled']),
                       'last_seen':r['last_seen'],'online':bool(source['enabled'] and r['enabled'] and r['last_seen'] and 0<=now-r['last_seen']<=35)})
    return result


def validate(db,source,selected):
    if not selected and db.execute('SELECT 1 FROM self_probe_nodes WHERE source_id=? LIMIT 1',(source['id'],)).fetchone():raise IntegrationError('请至少选择一个自建节点')
    selected=sorted(set(map(str,selected or ['self'])))
    available={n['id'] for n in nodes(db,source) if n['enabled']}
    if not selected or len(selected)>20 or not set(selected)<=available:raise IntegrationError('请选择此自建来源中已启用的有效节点')
    return selected


def identity(db,source_id,node_id):
    source=db.execute('SELECT * FROM detection_sources WHERE id=? AND kind=\'self\' AND enabled=1',(source_id,)).fetchone()
    if not source:return None
    if node_id=='self':secret=source['secret']
    else:
        if not node_id.startswith('probe-') or not node_id[6:].isdigit():return None
        row=db.execute('SELECT secret FROM self_probe_nodes WHERE id=? AND source_id=? AND enabled=1',(int(node_id[6:]),source_id)).fetchone()
        if not row:return None
        secret=row['secret']
    return hashlib.sha256((str(source_id)+'|'+node_id+'|'+secret).encode()).hexdigest()


def authenticate(db,cipher,token):
    from detectors import source_secret
    for s in db.execute("SELECT * FROM detection_sources WHERE kind='self' AND enabled=1"):
        try:match=secrets.compare_digest(source_secret(s,cipher),token)
        except Exception:continue
        if match:return dict(s,probe_node_id='self',probe_node_name=s['name'])
    for n in db.execute('SELECT n.*,s.name AS source_name FROM self_probe_nodes n JOIN detection_sources s ON s.id=n.source_id WHERE n.enabled=1 AND s.enabled=1'):
        try:match=secrets.compare_digest(cipher.decrypt(n['secret'].encode()).decode(),token)
        except Exception:continue
        if match:
            s=db.execute('SELECT * FROM detection_sources WHERE id=?',(n['source_id'],)).fetchone()
            return dict(s,probe_node_id='probe-'+str(n['id']),probe_node_name=n['name'])
    return None


def heartbeat(db,source,now):
    key=source.get('probe_node_id','self')
    if key=='self':db.execute('UPDATE detection_sources SET last_seen=? WHERE id=?',(now,source['id']))
    else:db.execute('UPDATE self_probe_nodes SET last_seen=? WHERE id=? AND source_id=?',(now,int(key[6:]),source['id']))


def create_tasks(db,run,source_id,selected,kind='primary'):
    for node in selected:
        stamp=identity(db,source_id,node)
        if stamp is None:raise IntegrationError('自建节点已暂停或不可用')
        db.execute('INSERT INTO self_probe_tasks(parent_id,kind,node_id,source_id,identity) VALUES(?,?,?,?,?)',(run['id'],kind,node,source_id,stamp))


def evidence_valid(db,run):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='self_probe_tasks'").fetchone():return True
    rows=db.execute("SELECT * FROM self_probe_tasks WHERE parent_id=? AND kind='primary'",(run['id'],)).fetchall()
    if not rows:return True # Existing in-flight single-node jobs remain compatible.
    return len(rows)==len(json.loads(run['nodes'])) and {x['node_id'] for x in rows}==set(json.loads(run['nodes'])) and all(x['state']=='done' and x['identity']==identity(db,x['source_id'],x['node_id']) for x in rows)


def selection_matches(db,run,wanted):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='self_probe_tasks'").fetchone():return True
    tasks=db.execute("SELECT * FROM self_probe_tasks WHERE parent_id=? AND kind='primary'",(run['id'],)).fetchall()
    if len(tasks)<2:return True
    return all(t['state']=='done' and t['details'] and json.loads(t['details']).get('state')==wanted for t in tasks)


def gate(db,run,wanted):
    return evidence_valid(db,run) and selection_matches(db,run,wanted)


def claim(db,source,now,kind='primary'):
    node=source.get('probe_node_id','self')
    rows=db.execute('SELECT t.* FROM self_probe_tasks t JOIN detection_runs r ON r.id=t.parent_id WHERE t.source_id=? AND t.node_id=? AND t.kind=? AND (t.state=\'queued\' OR (t.state=\'issued\' AND COALESCE(t.claimed_at,0)<=?)) AND r.created>? ORDER BY t.parent_id LIMIT 50',(source['id'],node,kind,now-30,now-120)).fetchall()
    for task in rows:
        run=db.execute('SELECT * FROM detection_runs WHERE id=?',(task['parent_id'],)).fetchone()
        if task['identity']!=identity(db,source['id'],node):continue
        p=db.execute('SELECT p.*,m.port,m.enabled FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(run['server_id'],)).fetchone()
        if not p or not p['enabled'] or run['status'] not in ('queued','issued') or p['source_id']!=run['source_id'] or p['nodes']!=run['nodes'] or p['port']!=run['port']:continue
        db.execute("UPDATE detection_runs SET status='issued',updated=? WHERE id=?",(now,run['id']))
        job_id=run['id']
        db.execute("UPDATE self_probe_tasks SET state='issued',claimed_at=? WHERE parent_id=? AND kind=? AND node_id=?",(now,run['id'],kind,node))
        return {'id':job_id,'ip':run['ip'],'port':run['port']}
    return None


def receive(db,source,run,data,kind='primary'):
    node=source.get('probe_node_id','self')
    tasks=db.execute('SELECT * FROM self_probe_tasks WHERE parent_id=? AND kind=?',(run['id'],kind)).fetchall()
    if not tasks:return None
    task=next((x for x in tasks if x['source_id']==source['id'] and x['node_id']==node and x['state']=='issued'),None)
    if not task or task['identity']!=identity(db,source['id'],node):return False
    if int(time.time())-run['created']>120 or data.get('ip')!=run['ip'] or type(data.get('port'))is not int or data['port']!=run['port']:return False
    if kind=='primary':
        p=db.execute('SELECT p.*,m.port,m.enabled,m.current_ip,m.source_id AS ip_source_id FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(run['server_id'],)).fetchone()
        if not p or not p['enabled'] or p['source_id']!=run['source_id'] or p['nodes']!=run['nodes'] or p['port']!=run['port']:return False
        if p['current_ip'] and p['current_ip']!=run['ip']:return False
        seen=db.execute('SELECT seen FROM servers WHERE id=?',(run['server_id'],)).fetchone()
        if not p['ip_source_id'] and seen and seen['seen'] and 0<=int(time.time())-seen['seen']<=90:
            try:
                if candidate_ip(db,{'server_id':run['server_id'],'source_id':None},None)!=run['ip']:return False
            except IntegrationError:return False
    row={'node_id':node,'name':source.get('probe_node_name',source['name']),'state':'reachable' if data['reachable'] else 'unreachable','latency_ms':data.get('latency_ms')}
    db.execute("UPDATE self_probe_tasks SET state='done',details=? WHERE parent_id=? AND kind=? AND node_id=?",(json.dumps(row),run['id'],kind,node))
    return True


def completed(db,run,kind='primary'):
    tasks=db.execute('SELECT * FROM self_probe_tasks WHERE parent_id=? AND kind=? ORDER BY node_id',(run['id'],kind)).fetchall()
    if not tasks or any(x['state']!='done' for x in tasks):return None
    if any(x['identity']!=identity(db,x['source_id'],x['node_id']) for x in tasks):return []
    return [json.loads(x['details']) for x in tasks]


def snapshot(db,parent_id):
    tasks=db.execute("SELECT * FROM self_probe_tasks WHERE parent_id=? AND kind='primary' ORDER BY node_id",(parent_id,)).fetchall()
    if len(tasks)<2:return None
    run=db.execute('SELECT * FROM detection_runs WHERE id=?',(parent_id,)).fetchone()
    source=db.execute('SELECT * FROM detection_sources WHERE id=?',(run['source_id'],)).fetchone()
    labels={n['id']:n['name'] for n in nodes(db,source)} if source else {}
    pending=run['status'] in ('queued','issued','pending','creating')
    result=[]
    for t in tasks:
        detail=json.loads(t['details']) if t['details'] else None
        result.append({'id':t['node_id'],'name':labels.get(t['node_id'],t['node_id']),
                       'state':t['state'] if t['state']=='done' or pending else 'unknown','result':detail})
    return {'source_id':run['source_id'],'name':source['name'] if source else '已删除来源','nodes':result,
            'complete':all(t['state']=='done' for t in tasks),'pending':pending}


def cancel_pending(db,server_id=None,source_id=None,node_id=None):
    where="(r.status IN ('queued','issued','pending','creating') OR EXISTS(SELECT 1 FROM detection_rechecks c WHERE c.parent_id=r.id AND c.state IN ('queued','pending','creating')))";args=[]
    if server_id is not None:where+=' AND r.server_id=?';args.append(server_id)
    if source_id is not None:where+=' AND t.source_id=?';args.append(source_id)
    if node_id is not None:where+=' AND t.node_id=?';args.append(node_id)
    ids=[r[0] for r in db.execute('SELECT DISTINCT r.id FROM detection_runs r JOIN self_probe_tasks t ON t.parent_id=r.id WHERE '+where,args)]
    for rid in ids:
        db.execute("UPDATE self_probe_tasks SET state='cancelled' WHERE parent_id=? AND state IN ('queued','issued')",(rid,))
        db.execute("UPDATE detection_runs SET status='自建节点配置变化，旧轮已取消' WHERE id=?",(rid,))
        db.execute("UPDATE detection_rechecks SET state='cancelled',message='首轮节点配置变化，取消旧复检' WHERE parent_id=? AND state IN ('queued','pending','creating')",(rid,))
        db.execute('UPDATE detection_plans SET failure_streak=0,failure_ip=NULL,failure_port=NULL WHERE server_id=(SELECT server_id FROM detection_runs WHERE id=?)',(rid,))
    if source_id is not None:
        clause='' if node_id is None else ' AND node=?'
        values=(source_id,) if node_id is None else (source_id,node_id)
        db.execute("UPDATE detection_rechecks SET state='cancelled',message='节点配置变化，取消旧复检' WHERE state IN ('queued','pending','creating') AND parent_id IN (SELECT id FROM detection_runs r WHERE COALESCE(detection_rechecks.confirm_source_id,r.source_id)=?)"+clause,values)
