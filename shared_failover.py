"""Coordinate probe profiles when several protected hosts share one standby."""
import json
from ip_dns import IntegrationError, candidate_ip, public_v4


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS shared_failover_probe(
      backup_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
      kind TEXT NOT NULL, parent_id INTEGER NOT NULL, signature TEXT NOT NULL,
      switched_at INTEGER NOT NULL, run_floor INTEGER NOT NULL)''')
    db.execute('CREATE TABLE IF NOT EXISTS shared_failover_attempt(kind TEXT NOT NULL,parent_id INTEGER NOT NULL,attempted_at INTEGER NOT NULL,PRIMARY KEY(kind,parent_id))')


def references(db,sid):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='server_failovers'").fetchone():return []
    rows=[]
    for r in db.execute('SELECT * FROM server_failovers WHERE backup_id=?',(sid,)):
        rows.append(dict(r,kind='server',key=r['server_id'],primary=r['server_id']))
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='vps_failover_probe_state'").fetchone():return rows
    for r in db.execute('SELECT r.*,s.active AS probe_active,s.signature AS probe_signature,s.activated_at AS probe_activated,s.run_floor AS probe_floor,s.original_plan,s.original_monitor FROM vps_rotations r JOIN vps_failover_probe_state s ON s.rotation_id=r.id WHERE r.failover_server_id=?',(sid,)):
        rows.append(dict(r,kind='rotation',key=r['id'],primary=r['primary_server_id'],backup_id=sid,cold=1,active=r['probe_active'],signature=r['probe_signature'],activated_at=r['probe_activated'],run_floor=r['probe_floor']))
    return rows


def shared(db,sid):return len(references(db,sid))>1


def original(db,sid,exclude=None):
    return next((r for r in references(db,sid) if (r['kind'],r['key'])!=exclude),None)


def active_other(db,sid,kind,key):
    return any(r['active'] for r in references(db,sid) if (r['kind'],r['key'])!=(kind,key))


def context(db,kind,key):
    if kind=='server':
        row=db.execute('SELECT * FROM server_failovers WHERE server_id=?',(key,)).fetchone()
        return dict(row,kind=kind,key=key,primary=key) if row else None
    r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(key,)).fetchone()
    if not r:return None
    return next((x for x in references(db,r['failover_server_id']) if x['kind']==kind and x['key']==key),None)


def _profile(db,r):
    from failover import probe_config
    p=probe_config(db,r['primary'],r['owner_id'])
    sig=json.dumps([p['source_id'],p['nodes'],p['interval_s'],p['daily_limit'],p['failure_threshold'],p['monitor_port']])
    return p,sig


def _run(db,r,p,address=None):
    sql="SELECT * FROM detection_runs WHERE server_id=? AND source_id=? AND nodes=? AND port=? AND status NOT IN ('creating','pending','queued','issued')"
    args=[r['backup_id'],p['source_id'],p['nodes'],p['monitor_port']]
    if address is not None:sql+=' AND ip=?';args.append(address)
    return db.execute(sql+' ORDER BY id DESC LIMIT 1',args).fetchone()


def _valid(run,r,p,now,address):
    if not run or run['id']<=r['run_floor'] or run['created']<r['activated_at'] or run['ip']!=address or not 0<=now-run['updated']<=90:return False
    try:rows=json.loads(run['details']);nodes=json.loads(p['nodes'])
    except (TypeError,ValueError):return False
    return bool(nodes and isinstance(rows,list) and len(rows)==len(nodes) and all(isinstance(x,dict) and x.get('state')=='reachable' for x in rows) and {str(x.get('node_id')) for x in rows}==set(map(str,nodes)))


def activate(db,kind,key,now):
    r=context(db,kind,key);p,sig=_profile(db,r);sid=r['backup_id']
    floor=db.execute('SELECT COALESCE(MAX(id),0) FROM detection_runs WHERE server_id=?',(sid,)).fetchone()[0]
    if not r['active'] or r['signature']!=sig:
        db.execute('DELETE FROM shared_failover_attempt WHERE kind=? AND parent_id=?',(kind,key))
        if kind=='server':db.execute('UPDATE server_failovers SET active=1,signature=?,activated_at=?,run_floor=? WHERE server_id=?',(sig,now,floor,key))
        else:db.execute('UPDATE vps_failover_probe_state SET active=1,signature=?,activated_at=?,run_floor=? WHERE rotation_id=?',(sig,now,floor,key))
        r=context(db,kind,key)
    try:address=public_v4(candidate_ip(db,{'server_id':sid,'source_id':None},None))
    except IntegrationError:address=None
    run=_run(db,r,p,address) if address else None
    # Preserve a parent's verified result while another parent's profile runs.
    if _valid(run,r,p,now,address) and now-run['updated']<60:return
    if run and run['id']>r['run_floor'] and 0<=now-run['updated']<15:return
    if db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND status IN ('creating','pending','queued','issued')",(sid,)).fetchone():return
    controller=db.execute('SELECT * FROM shared_failover_probe WHERE backup_id=?',(sid,)).fetchone()
    if controller:
        newer=db.execute('SELECT 1 FROM detection_runs WHERE server_id=? AND id>?',(sid,controller['run_floor'])).fetchone()
        if not newer and now-controller['switched_at']<30:return
    # A profile whose budget/provider is unavailable must not monopolize the
    # physical standby plan. Oldest unserved active profile gets the next slot.
    candidates=[]
    for peer in references(db,sid):
        if not peer['active'] or not peer['cold']:continue
        try:pp,_=_profile(db,peer)
        except IntegrationError:continue
        result=_run(db,peer,pp,address) if address else None
        if _valid(result,peer,pp,now,address) and now-result['updated']<60:continue
        if result and result['id']>peer['run_floor'] and 0<=now-result['updated']<15:continue
        attempted=db.execute('SELECT attempted_at FROM shared_failover_attempt WHERE kind=? AND parent_id=?',(peer['kind'],peer['key'])).fetchone()
        candidates.append((attempted[0] if attempted else -1,peer['kind'],peer['key']))
    if candidates and min(candidates)[1:]!=(kind,key):return
    db.execute('INSERT INTO shared_failover_attempt(kind,parent_id,attempted_at) VALUES(?,?,?) ON CONFLICT(kind,parent_id) DO UPDATE SET attempted_at=excluded.attempted_at',(kind,key,now))
    db.execute('INSERT INTO ip_monitors(server_id,port,enabled) VALUES(?,?,1) ON CONFLICT(server_id) DO UPDATE SET port=excluded.port,enabled=1,source_id=NULL',(sid,p['monitor_port']))
    db.execute("INSERT INTO detection_plans(server_id,source_id,nodes,interval_s,daily_limit,automatic,next_at,response_mode,action_enabled,owner_id,failure_threshold) VALUES(?,?,?,?,?,1,?,'none',0,?,?) ON CONFLICT(server_id) DO UPDATE SET source_id=excluded.source_id,nodes=excluded.nodes,interval_s=excluded.interval_s,daily_limit=excluded.daily_limit,automatic=1,next_at=excluded.next_at,response_mode='none',action_enabled=0,owner_id=excluded.owner_id,failure_threshold=excluded.failure_threshold,failure_streak=0",(sid,p['source_id'],p['nodes'],p['interval_s'],p['daily_limit'],now,r['owner_id'],p['failure_threshold']))
    db.execute('INSERT INTO shared_failover_probe(backup_id,kind,parent_id,signature,switched_at,run_floor) VALUES(?,?,?,?,?,?) ON CONFLICT(backup_id) DO UPDATE SET kind=excluded.kind,parent_id=excluded.parent_id,signature=excluded.signature,switched_at=excluded.switched_at,run_floor=excluded.run_floor',(sid,kind,key,sig,now,floor))


def ready(db,cipher,kind,key,now,offline_s):
    import rotation
    r=context(db,kind,key);p,sig=_profile(db,r);sid=r['backup_id']
    if not r['active'] or sig!=r['signature']:raise IntegrationError('等待共享备用机验证当前主机的探测配置')
    if not rotation._owned_server(db,sid,r['owner_id']):raise IntegrationError('共享备用机归属已变化')
    if rotation._offline(db,sid,now,offline_s) or rotation._pending_action(db,sid):raise IntegrationError('共享备用机离线或有未完成的动作')
    address=public_v4(candidate_ip(db,{'server_id':sid,'source_id':None},cipher))
    if not _valid(_run(db,r,p,address),r,p,now,address):raise IntegrationError('等待共享备用机通过本主机所选检测点；其他主机结果不能替代')
    try:
        with rotation.socket.create_connection((address,p['monitor_port']),timeout=4):pass
    except OSError:raise IntegrationError('共享备用机业务端口不可达') from None
    return address,p['monitor_port'],{}


def budget_primary(db,sid):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='shared_failover_probe'").fetchone():return None
    c=db.execute('SELECT * FROM shared_failover_probe WHERE backup_id=?',(sid,)).fetchone()
    if not c:return None
    r=context(db,c['kind'],c['parent_id'])
    if not r or not r['active']:return None
    try:p,sig=_profile(db,r)
    except IntegrationError:return None
    current=db.execute('SELECT source_id,nodes FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
    return r['primary'] if current and current['source_id']==p['source_id'] and current['nodes']==p['nodes'] and sig==c['signature'] else None
