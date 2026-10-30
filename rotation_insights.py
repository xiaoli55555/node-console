"""Read-only rotation analysis and narrowly scoped DNS observation tokens."""
import hashlib
import ipaddress
import json
import math
import re
import secrets
import time
from flask import g, jsonify, request

SCHEMA='''
CREATE TABLE IF NOT EXISTS rotation_dns_trials(
 id INTEGER PRIMARY KEY,rotation_id INTEGER NOT NULL REFERENCES vps_rotations(id) ON DELETE CASCADE,
 hostname TEXT NOT NULL,line TEXT NOT NULL,old_ip TEXT NOT NULL,new_ip TEXT NOT NULL,
 submitted INTEGER NOT NULL,readback INTEGER NOT NULL,ttl INTEGER NOT NULL,observable INTEGER NOT NULL,
 expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS insight_ip_history ON ip_events(server_id,observed);
CREATE INDEX IF NOT EXISTS insight_detection_ip_time ON detection_runs(server_id,ip,created);
CREATE INDEX IF NOT EXISTS rotation_trials_time ON rotation_dns_trials(rotation_id,submitted);
CREATE TABLE IF NOT EXISTS rotation_observers(
 id INTEGER PRIMARY KEY,rotation_id INTEGER NOT NULL REFERENCES vps_rotations(id) ON DELETE CASCADE,
 label TEXT NOT NULL,region TEXT NOT NULL,isp TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,created INTEGER NOT NULL,last_seen INTEGER);
CREATE TABLE IF NOT EXISTS rotation_dns_samples(
 trial_id INTEGER NOT NULL REFERENCES rotation_dns_trials(id) ON DELETE CASCADE,
 observer_id INTEGER NOT NULL REFERENCES rotation_observers(id) ON DELETE CASCADE,
 first_at INTEGER NOT NULL,last_at INTEGER NOT NULL,first_new INTEGER,stable_at INTEGER,
 streak INTEGER NOT NULL DEFAULT 0,samples INTEGER NOT NULL DEFAULT 0,errors INTEGER NOT NULL DEFAULT 0,
 saw_old INTEGER NOT NULL DEFAULT 0,last_answers TEXT NOT NULL DEFAULT '[]',resolver TEXT,
 PRIMARY KEY(trial_id,observer_id));
CREATE TABLE IF NOT EXISTS rotation_recovery_timings(
 id INTEGER PRIMARY KEY,rotation_id INTEGER NOT NULL REFERENCES vps_rotations(id) ON DELETE CASCADE,
 attempt INTEGER NOT NULL,server_id INTEGER NOT NULL,started INTEGER NOT NULL,ip_seen INTEGER,verified INTEGER,
 UNIQUE(rotation_id,attempt));
CREATE TABLE IF NOT EXISTS rotation_analysis_tokens(
 rotation_id INTEGER PRIMARY KEY REFERENCES vps_rotations(id) ON DELETE CASCADE,
 token_hash TEXT UNIQUE NOT NULL,created INTEGER NOT NULL);
'''

def initialize(connect):
    with connect() as db:db.executescript(SCHEMA)

def digest(token):return hashlib.sha256(token.encode()).hexdigest()

def record_switch(db,rid,binding,old_ip,new_ip,submitted,readback,ttl,proxied=False):
    host=binding['domain'] if binding['rr']=='@' else binding['rr']+'.'+binding['domain']
    db.execute('INSERT INTO rotation_dns_trials(rotation_id,hostname,line,old_ip,new_ip,submitted,readback,ttl,observable,expires) VALUES(?,?,?,?,?,?,?,?,?,?)',
               (rid,host,binding['line'],old_ip,new_ip,submitted,readback,ttl,int(not proxied),readback+max(1800,ttl*2+120)))
    db.execute('DELETE FROM rotation_dns_trials WHERE submitted<?',(readback-90*86400,))

def record_progress(db,before,after,now):
    if not before or not after:return
    if after['action_attempts']>before['action_attempts'] and after['drain_server_id']:
        db.execute('INSERT OR IGNORE INTO rotation_recovery_timings(rotation_id,attempt,server_id,started) VALUES(?,?,?,?)',(after['id'],after['action_attempts'],after['drain_server_id'],after['action_started'] or now))
    sid=after['drain_server_id'] or before['drain_server_id']
    if sid and after['phase']=='waiting_probe' and before['phase']!='waiting_probe':
        db.execute('UPDATE rotation_recovery_timings SET ip_seen=COALESCE(ip_seen,?) WHERE rotation_id=? AND attempt=? AND server_id=?',(now,after['id'],after['action_attempts'],sid))
    if sid and after['phase']=='active' and before['phase']=='waiting_probe':
        db.execute('UPDATE rotation_recovery_timings SET verified=? WHERE rotation_id=? AND attempt=? AND server_id=?',(now,after['id'],after['action_attempts'],sid))
    db.execute('DELETE FROM rotation_recovery_timings WHERE started<?',(now-90*86400,))

def quantile(values,q):
    values=sorted(values)
    if not values:return None
    return values[max(0,math.ceil(len(values)*q)-1)]

def describe(values):
    return {'count':len(values),'p10_s':quantile(values,.1),'median_s':quantile(values,.5),'p95_s':quantile(values,.95),'max_s':max(values) if values else None}

def summarize(db,rid,now=None):
    now=int(time.time()) if now is None else now
    r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
    if not r:return None
    server_ids=(r['primary_server_id'],r['other_server_id'])
    episodes=[]
    for sid in server_ids:
        events=db.execute('SELECT id,addresses,observed FROM ip_events WHERE server_id=? AND observed>=? ORDER BY id',(sid,now-30*86400)).fetchall()
        history=[]
        for event in events:
            try:ips=sorted(set(str(ipaddress.ip_address(x)) for x in json.loads(event['addresses']) if ipaddress.ip_address(x).version==4))
            except (ValueError,TypeError):continue
            if len(ips)==1 and (not history or history[-1]['ipv4']!=ips[0]):history.append(dict(event,ipv4=ips[0]))
        events=history
        for index,event in enumerate(events):
            ips=[event['ipv4']]
            end=events[index+1]['observed'] if index+1<len(events) else now
            runs=db.execute('SELECT ip,created,updated,nodes,details FROM detection_runs WHERE server_id=? AND ip=? AND created>=? AND created<? ORDER BY created,id',(sid,ips[0],event['observed'],end)).fetchall()
            last_good=None;failure=None;previous_nodes=None
            for run in runs:
                try:
                    rows=json.loads(run['details']);nodes=json.loads(run['nodes'])
                    if not nodes or len(rows)!=len(nodes) or {str(x.get('node_id')) for x in rows}!=set(map(str,nodes)):continue
                    if previous_nodes is not None and previous_nodes!=run['nodes']:last_good=None
                    previous_nodes=run['nodes']
                    if all(x.get('state')=='reachable' for x in rows):last_good=run['created']
                    if all(x.get('state')=='unreachable' for x in rows):failure=run;break
                except (TypeError,ValueError,AttributeError):continue
            # The first retained IP may predate installation; never treat it as a new allocation.
            known_start=index>0
            episodes.append({'server_id':sid,'ip':ips[0],'first_observed':event['observed'],'end_observed':end,
                'start_observed_after_change':known_start,'outcome':'all_nodes_unreachable' if failure else 'right_censored',
                'first_failure_at':failure['updated'] if failure else None,
                'last_reachable_age_s':max(0,last_good-event['observed']) if failure and known_start and last_good else None,
                'failure_detected_age_s':max(0,failure['updated']-event['observed']) if failure and known_start else None})
    trials=db.execute('SELECT * FROM rotation_dns_trials WHERE rotation_id=? AND submitted>=? ORDER BY id DESC',(rid,now-30*86400)).fetchall()
    observations=db.execute('SELECT s.*,o.label,o.region,o.isp,t.submitted,t.readback,t.id AS tid FROM rotation_dns_samples s JOIN rotation_observers o ON o.id=s.observer_id JOIN rotation_dns_trials t ON t.id=s.trial_id WHERE t.rotation_id=? AND t.submitted>=?',(rid,now-30*86400)).fetchall()
    stable=[x['stable_at']-x['submitted'] for x in observations if x['stable_at']]
    warmed=[x['stable_at']-x['submitted'] for x in observations if x['stable_at'] and x['saw_old']]
    providers=[t['readback']-t['submitted'] for t in trials]
    lower=[e['last_reachable_age_s'] for e in episodes if e['last_reachable_age_s'] is not None]
    observers=[dict(x) for x in db.execute('SELECT id,label,region,isp,enabled,last_seen FROM rotation_observers WHERE rotation_id=?',(rid,))]
    groups=[]
    for observer in observers:
        selected=[x for x in observations if x['observer_id']==observer['id']]
        groups.append(dict(observer,completed=sum(bool(x['stable_at']) for x in selected),pending=sum(not x['stable_at'] for x in selected),
                           propagation=describe([x['stable_at']-x['submitted'] for x in selected if x['stable_at']])))
    # Advisory heuristic only: IP age may span standby plus serving time, approximately two cycles.
    ttl=max([t['ttl'] for t in trials] or [r['lead_s'] or 60])
    lead=max(ttl+60,quantile(warmed,.95) or 0)
    recoveries=db.execute('SELECT * FROM rotation_recovery_timings WHERE rotation_id=? AND started>=?',(rid,now-30*86400)).fetchall()
    recovery_times=[x['verified']-x['started'] for x in recoveries if x['verified']]
    candidate=None;reasons=[]
    for sid in server_ids:
        if sum(e['server_id']==sid and e['last_reachable_age_s'] is not None for e in episodes)<5:reasons.append('VPS #'+str(sid)+' 至少需要 5 次起点可观测、失效前有成功探测的 IP 样本')
    if len(warmed)<5:reasons.append('至少需要 5 份先观察到旧值、后稳定为新值的 DNS 样本')
    distinct={(x['region'],x['isp']) for x in observers if any(y['observer_id']==x['id'] and y['stable_at'] and y['saw_old'] for y in observations)}
    if len(distinct)<3:reasons.append('至少需要 3 个地区/运营商观察组合；标签为自行声明，并非全国覆盖证明')
    if not reasons:
        age=quantile(lower,.1);margin=max(600,int(age*.2),(quantile(recovery_times,.95) or 0)+lead);seconds=(age-margin)//2-lead
        if seconds>=60:candidate={'interval_s':int(seconds+lead),'lead_s':int(lead),'effective_dns_switch_after_s':int(seconds),'model':'两机 IP 存活时间可能跨越备用和承载两个周期；取失效前成功年龄 P10，预留 20% 或至少 10 分钟裕量'}
        else:reasons.append('观测到的安全窗口不足以容纳 DNS 缓存裕量，不建议自动推导周期')
    return {'rotation_id':rid,'servers':list(server_ids),'generated_at':now,'window_days':30,'current':{'interval_s':r['interval_s'],'lead_s':r['lead_s'],'offline_after_s':r['offline_after_s']},
        'ip_lifetimes':{'observed_episodes':len(episodes),'censored':sum(x['outcome']=='right_censored' for x in episodes),'last_reachable_before_failure':describe(lower),'episodes':episodes[-100:]},
        'recovery':{'attempts_observed':len(recoveries),'completed':describe(recovery_times),'ip_reported':describe([x['ip_seen']-x['started'] for x in recoveries if x['ip_seen']]),'incomplete':sum(not x['verified'] for x in recoveries)},
        'dns':{'trials':len(trials),'proxied_unobservable':sum(not x['observable'] for x in trials),'provider_readback':describe(providers),
            'observed_stable':describe(stable),'observed_old_then_stable':describe(warmed),'observers':groups,
            'incomplete_observations':sum(not x['stable_at'] for x in observations),'trials_without_observations':sum(not any(x['tid']==t['id'] for x in observations) for t in trials if t['observable']),'national_coverage_claimed':False},
        'recommendation':{'mode':'advisory_only','ready':candidate is not None,'candidate':candidate,'reasons':reasons,'suggested_lead_s':lead},
        'limitations':['IP 起点为 agent 首次观察变化，不是供应商分配时间','全节点 TCP 不通不等于已证实被墙；超时、未知和缺失不算失败','未观测到失效的 IP 作为删失样本，不当成故障寿命','DNS 统计只代表已部署节点和所选记录线路；未稳定的样本保留，不作为零延迟','Cloudflare 代理记录无法通过公共 DNS 比较源站 IP','本接口不会修改策略、DNS 或调用换 IP API']}

def register(app,connect,auth,body,error,audit):
    def owned(db,sid):
        return db.execute('SELECT r.* FROM vps_rotations r JOIN servers s ON s.id=? WHERE (r.primary_server_id=s.id OR r.other_server_id=s.id) AND s.owner_id=? AND r.owner_id=?',(sid,g.user['id'],g.user['id'])).fetchone()
    def bearer():
        value=request.headers.get('Authorization','')
        return value[7:] if value.startswith('Bearer ') and len(value)<256 else ''
    def observer(db):
        return db.execute('SELECT * FROM rotation_observers WHERE token_hash=? AND enabled=1',(digest(bearer()),)).fetchone()

    @app.get('/api/admin/rotation-insights')
    @auth(admin=True)
    def admin_insights():
        with connect() as db:
            rows=db.execute('SELECT id FROM vps_rotations ORDER BY id DESC LIMIT 100').fetchall()
            return jsonify(rotations=[summarize(db,r['id']) for r in rows])

    @app.post('/api/admin/rotation-insights/<int:rid>/analysis-token')
    @auth(admin=True)
    def admin_analysis_token(rid):
        with connect() as db:
            if not db.execute('SELECT 1 FROM vps_rotations WHERE id=?',(rid,)).fetchone():return error('轮换计划不存在',404)
            token=secrets.token_urlsafe(36)
            db.execute('INSERT INTO rotation_analysis_tokens(rotation_id,token_hash,created) VALUES(?,?,?) ON CONFLICT(rotation_id) DO UPDATE SET token_hash=excluded.token_hash,created=excluded.created',(rid,digest(token),int(time.time())))
            audit(db,'管理员生成轮换只读统计令牌 #'+str(rid))
            return jsonify(token=token,path='/api/rotation-insights/'+str(rid),scope='read_only_statistics',message='仅本次显示；重新生成使旧令牌失效')

    @app.delete('/api/admin/rotation-insights/<int:rid>/analysis-token')
    @auth(admin=True)
    def admin_revoke_analysis(rid):
        with connect() as db:
            if not db.execute('SELECT 1 FROM vps_rotations WHERE id=?',(rid,)).fetchone():return error('轮换计划不存在',404)
            db.execute('DELETE FROM rotation_analysis_tokens WHERE rotation_id=?',(rid,));audit(db,'管理员撤销轮换统计令牌 #'+str(rid))
        return jsonify(ok=True)

    @app.get('/api/client/servers/<int:sid>/rotation/insights')
    @auth()
    def insights(sid):
        with connect() as db:
            r=owned(db,sid)
            if not r:return error('轮换计划不存在',404)
            return jsonify(summarize(db,r['id']))

    @app.post('/api/client/servers/<int:sid>/rotation/analysis-token')
    @auth()
    def analysis_token(sid):
        with connect() as db:
            r=owned(db,sid)
            if not r:return error('轮换计划不存在',404)
            token=secrets.token_urlsafe(36)
            db.execute('INSERT INTO rotation_analysis_tokens(rotation_id,token_hash,created) VALUES(?,?,?) ON CONFLICT(rotation_id) DO UPDATE SET token_hash=excluded.token_hash,created=excluded.created',(r['id'],digest(token),int(time.time())))
            audit(db,'生成轮换只读统计令牌 #'+str(r['id']))
            return jsonify(token=token,path='/api/rotation-insights/'+str(r['id']),scope='read_only_statistics',message='仅本次显示；重新生成使旧令牌失效')

    @app.delete('/api/client/servers/<int:sid>/rotation/analysis-token')
    @auth()
    def revoke_analysis(sid):
        with connect() as db:
            r=owned(db,sid)
            if not r:return error('轮换计划不存在',404)
            db.execute('DELETE FROM rotation_analysis_tokens WHERE rotation_id=?',(r['id'],));audit(db,'撤销轮换统计令牌 #'+str(r['id']))
        return jsonify(ok=True)

    @app.get('/api/rotation-insights/<int:rid>')
    def external_insights(rid):
        with connect() as db:
            if not db.execute('SELECT 1 FROM rotation_analysis_tokens WHERE rotation_id=? AND token_hash=?',(rid,digest(bearer()))).fetchone():return error('统计令牌无效',401)
            return jsonify(summarize(db,rid))

    @app.post('/api/client/servers/<int:sid>/rotation/observers')
    @auth()
    def create_observer(sid):
        d=body()
        if any(not isinstance(d.get(k),str) or not 1<=len(d[k].strip())<=80 for k in ('label','region','isp')):return error('请填写观察节点名称、地区和运营商')
        with connect() as db:
            r=owned(db,sid)
            if not r:return error('轮换计划不存在',404)
            if db.execute('SELECT COUNT(*) FROM rotation_observers WHERE rotation_id=? AND enabled=1',(r['id'],)).fetchone()[0]>=20:return error('每个轮换最多 20 个观察节点')
            token=secrets.token_urlsafe(36)
            oid=db.execute('INSERT INTO rotation_observers(rotation_id,label,region,isp,token_hash,created) VALUES(?,?,?,?,?,?)',(r['id'],d['label'].strip(),d['region'].strip(),d['isp'].strip(),digest(token),int(time.time()))).lastrowid
            audit(db,'创建 DNS 观察节点 #'+str(oid))
            return jsonify(id=oid,token=token,scope='dns_observer_only',message='请部署在对应 DNS 记录线路的真实网络；不得把标签当成实际定位证明')

    @app.delete('/api/client/servers/<int:sid>/rotation/observers/<int:oid>')
    @auth()
    def remove_observer(sid,oid):
        with connect() as db:
            r=owned(db,sid)
            if not r:return error('轮换计划不存在',404)
            db.execute('UPDATE rotation_observers SET enabled=0 WHERE id=? AND rotation_id=?',(oid,r['id']));audit(db,'停用 DNS 观察节点 #'+str(oid))
        return jsonify(ok=True)

    @app.get('/api/rotation-observer/jobs')
    def observer_jobs():
        now=int(time.time())
        with connect() as db:
            o=observer(db)
            if not o:return error('观察节点令牌无效',401)
            db.execute('UPDATE rotation_observers SET last_seen=? WHERE id=?',(now,o['id']))
            rows=db.execute('SELECT t.* FROM rotation_dns_trials t WHERE t.rotation_id=? AND t.observable=1 AND t.expires>? AND NOT EXISTS(SELECT 1 FROM rotation_dns_samples s WHERE s.trial_id=t.id AND s.observer_id=? AND s.stable_at IS NOT NULL) ORDER BY t.id DESC LIMIT 1',(o['rotation_id'],now,o['id'])).fetchall()
            # With no pending trial, warm the same recursive cache before the next switch.
            if not rows:
                b=db.execute('SELECT b.* FROM dns_bindings b JOIN vps_rotations r ON r.binding_id=b.id WHERE r.id=?',(o['rotation_id'],)).fetchone()
                return jsonify(jobs=[{'id':0,'hostname':b['domain'] if b['rr']=='@' else b['rr']+'.'+b['domain'],'line':b['line'],'warmup':True}] if b else [])
            return jsonify(jobs=[{'id':r['id'],'hostname':r['hostname'],'line':r['line'],'expected_ip':r['new_ip'],'expires':r['expires']} for r in rows])

    @app.post('/api/rotation-observer/results')
    def observer_result():
        d=body();tid=d.get('trial_id');answers=d.get('answers');resolver=d.get('resolver','');failed=d.get('error',False)
        if type(tid)is not int or type(failed)is not bool or not isinstance(answers,list) or len(answers)>32 or not isinstance(resolver,str) or len(resolver)>128:return error('DNS 观察结果格式无效')
        try:
            if any(not isinstance(x,str) for x in answers):raise ValueError()
            answers=sorted(set(str(ipaddress.IPv4Address(x)) for x in answers))
        except (ValueError,TypeError):return error('只接受 IPv4 A 记录结果')
        now=int(time.time())
        with connect() as db:
            db.execute('BEGIN IMMEDIATE');o=observer(db)
            if not o:return error('观察节点令牌无效',401)
            t=db.execute('SELECT * FROM rotation_dns_trials WHERE id=? AND rotation_id=? AND observable=1 AND expires>?',(tid,o['rotation_id'],now)).fetchone()
            if not t:return error('观察任务不存在或已过期',404)
            old=db.execute('SELECT * FROM rotation_dns_samples WHERE trial_id=? AND observer_id=?',(tid,o['id'])).fetchone()
            if old and old['stable_at']:return jsonify(ok=True,stable=True)
            if old and now-old['last_at']<2:return error('上报过于频繁',429)
            matched=not failed and answers==[t['new_ip']]
            streak=(old['streak'] if old else 0)+1 if matched else 0
            first=(old['first_new'] if old else None) or (now if matched else None)
            stable=(old['stable_at'] if old else None) or (now if streak>=3 else None)
            saw=int(bool((old and old['saw_old']) or (not failed and t['old_ip'] in answers)))
            db.execute('INSERT INTO rotation_dns_samples(trial_id,observer_id,first_at,last_at,first_new,stable_at,streak,samples,errors,saw_old,last_answers,resolver) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(trial_id,observer_id) DO UPDATE SET last_at=excluded.last_at,first_new=excluded.first_new,stable_at=excluded.stable_at,streak=excluded.streak,samples=excluded.samples,errors=excluded.errors,saw_old=excluded.saw_old,last_answers=excluded.last_answers,resolver=excluded.resolver',
                (tid,o['id'],old['first_at'] if old else now,now,first,stable,streak,(old['samples'] if old else 0)+1,(old['errors'] if old else 0)+int(failed),saw,json.dumps(answers),resolver))
            db.execute('UPDATE rotation_observers SET last_seen=? WHERE id=?',(now,o['id']))
        return jsonify(ok=True,stable=stable is not None)
