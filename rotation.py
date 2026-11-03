"""Safe two-VPS DNS rotation with connection draining and IP refresh."""
import fcntl
import ipaddress
import json
import socket
import time
from pathlib import Path

from flask import g, jsonify
from rotation_insights import record_switch, record_progress
import failover
import rotation_groups
import detection_recheck
import rotation_timing
import rotation_schedule
from contextlib import nullcontext

from detectors import boce_dns_gate, queue_reboot
from ip_dns import (
    ChangeIPUncertain, IntegrationError, candidate_ip, get_dns_record,
    invoke_change_ip_api, load_connection, public_v4, update_dns_record,
    validate_dns_record,
)

SCHEMA = '''
CREATE TABLE IF NOT EXISTS vps_rotations(
 id INTEGER PRIMARY KEY,
 owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 primary_server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 other_server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 binding_id INTEGER NOT NULL UNIQUE REFERENCES dns_bindings(id) ON DELETE CASCADE,
 active_server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 enabled INTEGER NOT NULL DEFAULT 0,
 interval_s INTEGER NOT NULL DEFAULT 7200,
 connection_threshold INTEGER NOT NULL DEFAULT 80,
 phase TEXT NOT NULL DEFAULT 'active',
 next_switch_at INTEGER NOT NULL,
 drain_server_id INTEGER,
 drain_started INTEGER,
 drain_grace_s INTEGER NOT NULL DEFAULT 0,
 old_ip TEXT,
 new_ip TEXT,
 action_started INTEGER,
 action_attempts INTEGER NOT NULL DEFAULT 0,
 last_sample_at INTEGER,
 low_samples INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT '已暂停',
 updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vps_rotation_drain_timings(
 id INTEGER PRIMARY KEY,
 rotation_id INTEGER NOT NULL REFERENCES vps_rotations(id) ON DELETE CASCADE,
 server_id INTEGER NOT NULL, old_ip TEXT, started INTEGER NOT NULL,
 threshold INTEGER NOT NULL, grace_s INTEGER NOT NULL,
 finished INTEGER, elapsed_s INTEGER, tcp INTEGER,
 outcome TEXT NOT NULL DEFAULT 'pending',
 UNIQUE(rotation_id,server_id,started)
);
CREATE INDEX IF NOT EXISTS vps_rotation_due ON vps_rotations(enabled,phase,next_switch_at);
CREATE TABLE IF NOT EXISTS vps_rotation_events(
 id INTEGER PRIMARY KEY, rotation_id INTEGER NOT NULL REFERENCES vps_rotations(id) ON DELETE CASCADE,
 server_id INTEGER, message TEXT NOT NULL, created INTEGER NOT NULL
);
'''

def initialize(connect):
    with connect() as db:
        db.executescript(SCHEMA)
        if 'emergency' not in {r[1] for r in db.execute('PRAGMA table_info(vps_rotations)')}:db.execute('ALTER TABLE vps_rotations ADD COLUMN emergency INTEGER NOT NULL DEFAULT 0')

        if 'lead_s' not in {r[1] for r in db.execute('PRAGMA table_info(vps_rotations)')}:db.execute('ALTER TABLE vps_rotations ADD COLUMN lead_s INTEGER NOT NULL DEFAULT 0')

        if 'offline_after_s' not in {r[1] for r in db.execute('PRAGMA table_info(vps_rotations)')}:db.execute('ALTER TABLE vps_rotations ADD COLUMN offline_after_s INTEGER NOT NULL DEFAULT 15')
        columns={r[1] for r in db.execute('PRAGMA table_info(vps_rotations)')}
        for name,definition in [('mode',"TEXT NOT NULL DEFAULT 'alternating'"),('takeover_s','INTEGER NOT NULL DEFAULT 600'),('first_switch_at','INTEGER'),('mobile_only_ack','INTEGER NOT NULL DEFAULT 0'),('dns_intent','TEXT'),('fault_recovery','INTEGER NOT NULL DEFAULT 0'),('reboot_command_id','INTEGER'),('emergency_probe_after','INTEGER'),('standby_ready_at','INTEGER'),('standby_ready_server','INTEGER'),('preload_refresh_deadline','INTEGER'),('preload_base_attempt','INTEGER'),('reused_ip','TEXT'),('reused_server_id','INTEGER'),('drain_base_attempt','INTEGER'),('external_dns_check_at','INTEGER'),('external_dns_pending','INTEGER NOT NULL DEFAULT 0')]:
            if name not in columns:db.execute(f'ALTER TABLE vps_rotations ADD COLUMN {name} {definition}')
        for name,definition in [('drain_schedule','TEXT'),('drain_schedule_key','TEXT'),('drain_schedule_after','INTEGER'),('force_drain_threshold','INTEGER NOT NULL DEFAULT 0'),('force_drain_samples','TEXT'),('urgent_probe_floors','TEXT'),('heartbeat_check','TEXT'),('repair_check','TEXT'),('repair_check_required','INTEGER NOT NULL DEFAULT 0')]:
            if name not in columns:db.execute(f'ALTER TABLE vps_rotations ADD COLUMN {name} {definition}')
        failover.initialize(db)
        rotation_timing.initialize(db)


# Existing tasks keep their alternating behavior after upgrading.
def _fixed(r):
    return r['mode']=='fixed_primary'


def _rotation_tcp_count(metrics,now):
    stamp=metrics.get('connections_sampled')
    count=metrics.get('tcp')
    if type(stamp)is not int or not 0<=now-stamp<=45:
        raise IntegrationError('等待新鲜 TCP 已建立连接总数；采样缺失或过期，不会按 0 处理')
    if type(count)is not int or count<0:raise IntegrationError('TCP 已建立连接总数无效，暂停换 IP')
    return count,stamp


def _force_drain_ready(db,r,count,stamp,now):
    """Opt-in one-hour escape hatch; never reinterpret normal low samples."""
    threshold=r['force_drain_threshold']
    if not threshold or r['drain_started'] is None or now-r['drain_started']<3600 or stamp<r['drain_started']+3600:
        db.execute('UPDATE vps_rotations SET force_drain_samples=NULL WHERE id=?',(r['id'],))
        return False
    try:state=json.loads(r['force_drain_samples'] or '{}')
    except (ValueError,TypeError):state={}
    if not isinstance(state,dict) or state.get('started')!=r['drain_started'] or state.get('threshold')!=threshold:
        state={'started':r['drain_started'],'threshold':threshold,'count':0,'stamp':0}
    if not 0<=now-state['stamp']<=45:state['count']=0
    if stamp>state['stamp']:
        state.update(stamp=stamp,count=min(2,state['count']+1) if count<threshold else 0)
        db.execute('UPDATE vps_rotations SET force_drain_samples=? WHERE id=?',(json.dumps(state),r['id']))
    db.execute('UPDATE vps_rotations SET status=? WHERE id=?',(f'排空已满 1 小时；强制阈值 TCP < {threshold}，当前 {count}，连续低值采样 {state["count"]}/2',r['id']))
    return state['count']>=2


def _drain_timing(db,r,now,outcome=None,tcp=None,start=False):
    """Observe one DNS handoff; never count action retries as new drains."""
    if not r['drain_server_id'] or r['drain_started'] is None:return
    threshold=rotation_schedule.effective(r,now)['threshold']
    if start:db.execute("INSERT OR IGNORE INTO vps_rotation_drain_timings(rotation_id,server_id,old_ip,started,threshold,grace_s) VALUES(?,?,?,?,?,?)",
               (r['id'],r['drain_server_id'],r['old_ip'],r['drain_started'],threshold,r['drain_grace_s']))
    db.execute("UPDATE vps_rotation_drain_timings SET threshold=? WHERE rotation_id=? AND server_id=? AND started=? AND outcome='pending'",(threshold,r['id'],r['drain_server_id'],r['drain_started']))
    if r['emergency']:outcome='skipped'
    if outcome=='forced':
        db.execute("UPDATE vps_rotation_drain_timings SET threshold=? WHERE rotation_id=? AND server_id=? AND started=? AND outcome='pending'",(r['force_drain_threshold'],r['id'],r['drain_server_id'],r['drain_started']))
    if outcome:
        db.execute("UPDATE vps_rotation_drain_timings SET outcome=?,finished=?,elapsed_s=?,tcp=? WHERE rotation_id=? AND server_id=? AND started=? AND outcome='pending'",
                   (outcome,now,max(0,now-r['drain_started']) if outcome=='completed' else None,tcp,r['id'],r['drain_server_id'],r['drain_started']))


def _drain_statistics(db,r,limit=20):
    # Per-record measurements avoid conflating different DNS TTLs in a group.
    records=[dict(x) for x in db.execute("SELECT d.*,s.name AS server_name FROM vps_rotation_drain_timings d LEFT JOIN servers s ON s.id=d.server_id WHERE rotation_id=? ORDER BY started DESC,id DESC LIMIT ?",(r['id'],limit))]
    summaries=[dict(x) for x in db.execute("SELECT d.server_id,s.name AS server_name,COUNT(*) AS count,ROUND(AVG(elapsed_s)) AS average_s,MIN(elapsed_s) AS min_s,MAX(elapsed_s) AS max_s FROM vps_rotation_drain_timings d LEFT JOIN servers s ON s.id=d.server_id WHERE rotation_id=? AND outcome='completed' GROUP BY d.server_id",(r['id'],))]
    counts={x['outcome']:x['count'] for x in db.execute('SELECT outcome,COUNT(*) AS count FROM vps_rotation_drain_timings WHERE rotation_id=? GROUP BY outcome',(r['id'],))}
    return {'records':records,'summaries':summaries,'counts':counts}


def _admin_user(db,uid):
    row=db.execute('SELECT role FROM users WHERE id=?',(uid,)).fetchone()
    return bool(row and row['role']=='admin')

def _owned_server(db,sid,uid):
    if _admin_user(db,uid):return db.execute('SELECT id,name,metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
    return db.execute('SELECT id,name,metrics,seen FROM servers WHERE id=? AND owner_id=?',(sid,uid)).fetchone()

def _rotation_json(db,row):
    if not row:return None
    data=dict(row)
    data['drain_effective']=rotation_schedule.effective(row,int(time.time()))
    data['drain_tcp']=None
    if row['drain_server_id']:
        metrics=db.execute('SELECT metrics FROM servers WHERE id=?',(row['drain_server_id'],)).fetchone()
        if metrics:
            try:
                snapshot=json.loads(metrics['metrics'] or '{}')
                if isinstance(snapshot,dict):data['drain_tcp']=_rotation_tcp_count(snapshot,int(time.time()))[0]
            except (ValueError,TypeError,IntegrationError):pass
    if not row['emergency'] and not rotation_schedule.samples_current(row,int(time.time())):data['low_samples']=0
    try:data['drain_schedule']=rotation_schedule.config(row)
    except (ValueError,TypeError,IntegrationError):data['drain_schedule']=rotation_schedule.validate(rotation_schedule.DEFAULT)
    group=rotation_groups.members(db,row)
    data['binding_ids']=[p['binding_id'] for p in group]
    data['member_ids']=[p['id'] for p in group]
    data['member_phases']=[{'id':p['id'],'binding_id':p['binding_id'],'phase':p['phase'],'active_server_id':p['active_server_id'],'status':p['status']} for p in group]
    data['group_pending']=len({(p['phase'],p['active_server_id'],bool(p['dns_intent'])) for p in group})>1
    data['primary_failover_active']=bool(db.execute('SELECT 1 FROM vps_failover_leases l JOIN vps_rotations p ON p.id=l.rotation_id WHERE p.primary_server_id=?',(row['primary_server_id'],)).fetchone())
    names=db.execute('SELECT id,name FROM servers WHERE id IN (?,?)',(data['primary_server_id'],data['other_server_id'])).fetchall()
    data['primary_name']=next((x['name'] for x in names if x['id']==data['primary_server_id']),str(data['primary_server_id']))
    data['other_name']=next((x['name'] for x in names if x['id']==data['other_server_id']),str(data['other_server_id']))
    active=db.execute('SELECT name FROM servers WHERE id=?',(data['active_server_id'],)).fetchone()
    data['active_name']=active['name'] if active else str(data['active_server_id'])
    backup=db.execute('SELECT name FROM servers WHERE id=?',(data['failover_server_id'],)).fetchone()
    data['failover_name']=backup['name'] if backup else None
    data['failover_binding_ids']=json.loads(data['failover_binding_ids'])
    data['failover_leases']=[dict(x) for x in db.execute('SELECT binding_id,current_ip,target_ip,intent FROM vps_failover_leases WHERE rotation_id IN ('+','.join('?' for _ in group)+') OR binding_id IN ('+','.join('?' for _ in group)+')',data['member_ids']+data['binding_ids'])]
    mobile_lease=next((x for x in data['failover_leases'] if x['binding_id']==data['binding_id']),None)
    if data['failover_leases'] and not data['failover_server_id']:
        inherited=db.execute('SELECT r.failover_server_id,r.failover_status,s.name FROM vps_failover_leases l JOIN vps_rotations r ON r.id=l.rotation_id JOIN servers s ON s.id=r.failover_server_id WHERE l.binding_id=?',((mobile_lease or data['failover_leases'][0])['binding_id'],)).fetchone()
        if inherited:data['failover_server_id']=inherited['failover_server_id'];data['failover_name']=inherited['name'];data['failover_status']=inherited['failover_status']
    data['failover_plan_count']=db.execute('SELECT COUNT(*) FROM (SELECT 1 FROM vps_rotations WHERE failover_server_id=? AND owner_id=? GROUP BY primary_server_id,other_server_id,owner_id,mode)',(data['failover_server_id'],data['owner_id'])).fetchone()[0] if data['failover_server_id'] else 0
    data['mobile_effective_server_id']=data['failover_server_id'] if mobile_lease and not mobile_lease['intent'] else data['active_server_id']
    if mobile_lease:data['active_name']='解析待核对' if mobile_lease['intent'] else (data['failover_name'] or str(data['failover_server_id']))+'（故障转移）'
    if len({p['active_server_id'] for p in group})>1:data['active_name']='多条记录切换中'
    data['drain_statistics']=_drain_statistics(db,row)
    data['timing']=rotation_timing.snapshot(db,row,int(time.time()))
    data['events']=[dict(e) for e in db.execute('SELECT server_id,message,created FROM vps_rotation_events WHERE rotation_id IN ('+','.join('?' for _ in group)+') ORDER BY id DESC LIMIT 50',data['member_ids'])]
    return data

def _server_snapshot(db,sid,now,cipher):
    row=db.execute('SELECT s.metrics,s.seen,m.source_id,m.port,m.enabled FROM servers s JOIN ip_monitors m ON m.server_id=s.id WHERE s.id=?',(sid,)).fetchone()
    if not row or not row['enabled'] or not row['seen'] or not 0<=now-row['seen']<=45:raise IntegrationError('两台 VPS 都必须在线，且最近 45 秒内有 agent 上报')
    try:metrics=json.loads(row['metrics'] or '{}')
    except (TypeError,ValueError):raise IntegrationError('VPS 资源数据格式无效') from None
    sampled=metrics.get('connections_sampled')
    tcp=metrics.get('tcp')
    if type(tcp)is not int or type(sampled)is not int or now-sampled>45 or sampled>now+5:raise IntegrationError('TCP 连接数采样已过期，请确认两台 VPS 客户端在线')
    address=candidate_ip(db,{'server_id':sid,'source_id':row['source_id']},cipher)
    return {'ip':public_v4(address),'port':row['port'],'tcp':tcp,'sampled':sampled,'metrics':metrics}

def _validated_plan(db,sid,uid):
    plan=db.execute('SELECT p.*,s.owner_id AS source_owner,s.server_id AS source_server,s.enabled AS source_enabled,m.enabled AS monitor_enabled,m.port AS monitor_port FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(sid,)).fetchone()
    admin=_admin_user(db,uid)
    if not plan or not plan['source_enabled'] or not plan['automatic'] or not plan['monitor_enabled']:
        raise IntegrationError('两台 VPS 都必须开启检测计划和 IP 监控')
    if plan['response_mode']=='reboot':
        if admin:
            if plan['source_owner'] is not None or plan['owner_id'] not in (None,uid):raise IntegrationError('管理员轮换需使用后台检测来源')
        elif plan['owner_id']!=uid or plan['source_owner']!=uid or plan['source_server']!=sid:
            raise IntegrationError('请使用该客户、该 VPS 专属的探测计划')
        node=db.execute('SELECT metrics FROM servers WHERE id=?',(sid,)).fetchone()
        try:capabilities=json.loads(node['metrics'] or '{}').get('capabilities',[])
        except (TypeError,ValueError):capabilities=[]
        if 'reboot' not in capabilities:raise IntegrationError('此 VPS 的 agent 不支持重启，请先升级 agent')
        return dict(plan,action_connection_id=None,rotation_action='reboot')
    if admin:
        if plan['source_owner'] is not None or plan['owner_id'] not in (None,uid):raise IntegrationError('管理员轮换需使用后台检测来源，不能混用客户密钥')
        action=db.execute("SELECT id,kind,owner_id,server_id FROM ip_connections WHERE id=? AND kind='change_ip' AND owner_id IS NULL",(plan['action_connection_id'],)).fetchone()
        if not action:raise IntegrationError('请在后台检测点配置中，为每台 VPS 的检测计划选择重启或指定换 IP API')
    else:
        if plan['owner_id']!=uid or plan['source_owner']!=uid or plan['source_server']!=sid:raise IntegrationError('请使用该客户、该 VPS 专属的探测计划')
        action=db.execute("SELECT id,kind,owner_id,server_id FROM ip_connections WHERE kind='change_ip' AND owner_id=? AND server_id=? ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END,id DESC LIMIT 1",(uid,sid,plan['action_connection_id'] or -1)).fetchone()
        if not action:raise IntegrationError('请为该 VPS 选择重启方式或保存专属换 IP API')
    return dict(plan,action_connection_id=action['id'])

def _client_rotation(app,connect,cipher,auth,body,error,audit):
    @auth()
    def get_rotation(sid):
        if g.user['role'] not in ('admin','client'):return error('无权管理轮换',403)
        with connect() as db:
            if not _owned_server(db,sid,g.user['id']):return error('服务器不存在',404)
            rotation=db.execute('SELECT * FROM vps_rotations WHERE owner_id=? AND (primary_server_id=? OR other_server_id=?) ORDER BY id LIMIT 1',(g.user['id'],sid,sid)).fetchone()
            return jsonify(rotation=_rotation_json(db,rotation))
    get_rotation.__name__='client_get_vps_rotation'

    @auth()
    def save_one(sid):
        if g.user['role'] not in ('admin','client'):return error('无权管理轮换',403)
        d=getattr(g,'rotation_payload',None) or body();other=d.get('other_server_id');binding_id=d.get('binding_id');interval=d.get('interval_s',7200);threshold=d.get('connection_threshold',80);enabled=d.get('enabled');offline_after=d.get('offline_after_s',15);lead=d.get('lead_s',min(120,interval//4) if type(interval)is int else 0)
        if d.get('mode')=='fixed_primary':lead=0
        if type(other)is not int or other==sid or type(binding_id)is not int or type(interval)is not int or not 60<=interval<=604800 or type(threshold)is not int or not 1<=threshold<=10000 or type(offline_after)is not int or not 10<=offline_after<=120 or type(lead)is not int or not 0<=lead<interval or type(enabled)is not bool:return error('请检查备用 VPS、DNS 记录、轮换间隔、连接数阈值和开关')
        now=int(time.time())
        try:
            with (nullcontext(g.rotation_db) if hasattr(g,'rotation_db') else connect()) as db:
                if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
                if not _owned_server(db,sid,g.user['id']) or not _owned_server(db,other,g.user['id']):return error('两台 VPS 必须都分配给当前客户',404)
                existing=db.execute('SELECT * FROM vps_rotations WHERE binding_id=?',(binding_id,)).fetchall()
                if len(existing)>1:return error('VPS 或 DNS 记录已用于其他轮换任务',409)
                rotation=existing[0] if existing else None
                if rotation and g.user['role']!='admin' and rotation['owner_id']!=g.user['id']:return error('轮换计划不属于当前客户',403)
                schedule=rotation_schedule.validate(d['drain_schedule']) if 'drain_schedule' in d else None
                force_threshold=d.get('force_drain_threshold',rotation['force_drain_threshold'] if rotation else 0)
                if type(force_threshold)is not int or not 0<=force_threshold<=10000:
                    return error('满 1 小时强制换 IP 的连接数阈值应为 1～10000，或 0 关闭')
                effective_uid=rotation['owner_id'] if rotation else g.user['id']
                mode=d.get('mode',rotation['mode'] if rotation else 'alternating')
                takeover=d.get('takeover_s',rotation['takeover_s'] if rotation else 600)
                first=d.get('first_switch_at',rotation['first_switch_at'] if rotation else None)
                ack=d.get('mobile_only_ack',bool(rotation['mobile_only_ack']) if rotation else False)
                if mode not in ('alternating','fixed_primary') or type(takeover)is not int or not 60<=takeover<=604800 or (first is not None and (type(first)is not int or not 0<=first<=253402300799)) or type(ack)is not bool:
                    return error('请检查轮换模式、接替时长（必须短于周期）和首次切入时间')
                if mode=='fixed_primary' and not ack:return error('请确认仅轮换选定的 DNS 记录；选择默认线路时，该记录覆盖的所有运营商都会切换')
                if rotation and mode!=rotation['mode'] and (rotation['enabled'] or rotation['phase']!='active' or rotation['active_server_id']!=sid or rotation['dns_intent']):
                    return error('切换模式前请暂停任务，并确认流程已完成且解析已回到主 VPS',409)

                if rotation and (rotation['primary_server_id']!=sid or rotation['other_server_id']!=other or rotation['binding_id']!=binding_id):return error('已有轮换任务绑定了不同的 VPS 或 DNS 记录；请先暂停原任务',409)
                if rotation and rotation['phase']!='active' and (rotation['other_server_id']!=other or rotation['binding_id']!=binding_id):return error('正在排空旧 VPS 或等待换 IP 完成，暂不能更换轮换对象',409)
                failover_changed=rotation and any(k in d and d[k]!=(json.loads(rotation[k]) if k=='failover_binding_ids' else rotation[k]) for k in ('failover_server_id','failover_binding_ids','failover_recovery_s'))
                if rotation and failover_changed and db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=?',(rotation['id'],)).fetchone():raise IntegrationError('A 故障转移正在接替，解析切回前不能修改备用机或接替记录')
                if rotation and not enabled and (rotation['enabled'] or mode==rotation['mode']) and not failover_changed:
                    kept_threshold=d.get('connection_threshold',rotation['connection_threshold'])
                    db.execute('UPDATE vps_rotations SET force_drain_samples=CASE WHEN force_drain_threshold<>? THEN NULL ELSE force_drain_samples END,force_drain_threshold=? WHERE id=?',(force_threshold,force_threshold,rotation['id']))
                    db.execute("UPDATE vps_rotations SET enabled=0,status='轮换已暂停',interval_s=?,low_samples=CASE WHEN connection_threshold<>? THEN 0 ELSE low_samples END,last_sample_at=CASE WHEN connection_threshold<>? THEN NULL ELSE last_sample_at END,connection_threshold=?,lead_s=?,offline_after_s=?,takeover_s=?,first_switch_at=?,mobile_only_ack=?,updated=? WHERE id=?",(d.get('interval_s',rotation['interval_s']),kept_threshold,kept_threshold,kept_threshold,0 if mode=='fixed_primary' else d.get('lead_s',rotation['lead_s']),d.get('offline_after_s',rotation['offline_after_s']),takeover,first,int(ack),now,rotation['id']))
                    if schedule is not None:rotation_schedule.save(db,rotation['id'],schedule,now)
                    audit(db,'暂停双 VPS 定时轮换 #'+str(rotation['id']))
                    return jsonify(ok=True,rotation=_rotation_json(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rotation['id'],)).fetchone()))
                import server_failover
                if server_failover.reserved(db,sid) or server_failover.reserved(db,other):return error('冷备用已被单机故障转移占用，不能参与轮换',409)
                rotation_groups.compatible(db,sid,other,mode,effective_uid,rotation['id'] if rotation else None)
                conflicts=False
                if enabled and (conflicts or db.execute('SELECT 1 FROM vps_rotations WHERE id<>? AND failover_server_id IN (?,?) AND (enabled=1 OR failover_server_id IS NOT NULL OR EXISTS(SELECT 1 FROM vps_failover_leases l WHERE l.rotation_id=vps_rotations.id))',(rotation['id'] if rotation else -1,sid,other)).fetchone()):return error('其中一台 VPS 已参加其他启用中的轮换或故障转移任务',409)
                binding=db.execute('SELECT b.*,c.kind,c.owner_id AS connection_owner,c.server_id AS connection_server FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE b.id=?',(binding_id,)).fetchone()
                binding_owner=None if _admin_user(db,effective_uid) else effective_uid
                if not binding or binding['server_id']!=sid or binding['connection_owner']!=binding_owner or (binding_owner is not None and binding['connection_server']!=sid):return error('DNS 绑定与该轮换的管理员/客户配置范围不一致',404)
                _validated_plan(db,sid,effective_uid);_validated_plan(db,other,effective_uid)
                if _validated_plan(db,sid,effective_uid)['monitor_port']!=binding['port']:return error('DNS 记录端口和主 VPS 监控端口不一致，请重新保存检测端口',409)
                a=_server_snapshot(db,sid,now,cipher);b=_server_snapshot(db,other,now,cipher)
                if a['port']!=b['port'] or a['port']!=binding['port']:return error('两台 VPS 的业务 TCP 检测端口必须相同')
                if a['ip']==b['ip']:return error('两台 VPS 当前公网 IP 相同，不能进行轮换')
                if mode=='fixed_primary':_rotation_tcp_count(b['metrics'],now)
                if enabled and (not rotation or not rotation['enabled']) and (_pending_action(db,sid) or _pending_action(db,other)):return error('机器存在未完成的重启或换 IP 动作，完成核对后再启用轮换；这不代表 DNS 记录仍被旧计划占用',409)
                if mode=='fixed_primary' and (not rotation or not rotation['enabled']):
                    pending=db.execute("SELECT * FROM vps_rotations WHERE drain_server_id IN (?,?) AND phase IN ('waiting_ip','waiting_probe')",(sid,other)).fetchall()
                    if any(p['primary_server_id']!=sid or p['other_server_id']!=other or p['owner_id']!=effective_uid for p in pending):return error('共享机器仍由其他计划换 IP 或复检，完成后再新建或启用计划',409)
                active_ip=(a['ip'] if not rotation or rotation['active_server_id']==sid else b['ip'])
                connection=load_connection(db,cipher,binding['connection_id'])
                record=get_dns_record(connection,dict(binding))
                validate_dns_record(record,dict(binding),connection)
                if record.get('content',record.get('Value'))!=active_ip or binding['expected_ip']!=active_ip:return error('DNS 当前解析必须指向轮换任务当前承载 VPS 的新鲜公网 IP')
                db.execute('UPDATE dns_bindings SET automatic=0 WHERE id=?',(binding_id,))
                if rotation:
                    # Editing a running plan must not give its carrier a fresh
                    # interval. New timing settings apply after the next handoff;
                    # only re-enabling or changing modes starts a new schedule.
                    restart_schedule=enabled and (not rotation['enabled'] or rotation['mode']!=mode)
                    db.execute('UPDATE vps_rotations SET interval_s=?,connection_threshold=?,enabled=?,status=?,next_switch_at=CASE WHEN ? THEN ? ELSE next_switch_at END,updated=? WHERE id=?',(interval,threshold,int(enabled),'轮换已开启' if enabled else '轮换已暂停',int(restart_schedule),now+interval-lead,now,rotation['id']))
                    rid=rotation['id']
                else:
                    rid=db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,interval_s,connection_threshold,phase,next_switch_at,status,updated) VALUES(?,?,?,?,?,1,?,?,'active',?,'轮换已开启',?)",(g.user['id'],sid,other,binding_id,sid,interval,threshold,now+interval-lead,now)).lastrowid
                if schedule is not None:rotation_schedule.save(db,rid,schedule,now)
                db.execute('UPDATE vps_rotations SET lead_s=?,offline_after_s=? WHERE id=?',(lead,offline_after,rid))
                db.execute('UPDATE vps_rotations SET force_drain_samples=CASE WHEN force_drain_threshold<>? THEN NULL ELSE force_drain_samples END,force_drain_threshold=? WHERE id=?',(force_threshold,force_threshold,rid))
                db.execute('UPDATE vps_rotations SET mode=?,takeover_s=?,first_switch_at=?,mobile_only_ack=? WHERE id=?',(mode,takeover,first,int(ack),rid))
                if rotation and threshold!=rotation['connection_threshold']:
                    db.execute('UPDATE vps_rotations SET low_samples=0,last_sample_at=NULL WHERE id=?',(rid,))
                if mode=='fixed_primary' and (not rotation or not rotation['enabled'] or rotation['mode']!=mode):
                    due=first if first and first>now else now
                    if rotation and rotation['active_server_id']==other:due=now+interval
                    db.execute('UPDATE vps_rotations SET next_switch_at=?,lead_s=0 WHERE id=?',(due,rid))
                elif mode=='fixed_primary':
                    db.execute('UPDATE vps_rotations SET next_switch_at=?,lead_s=0 WHERE id=?',(rotation['next_switch_at'],rid))

                if not enabled:db.execute("UPDATE vps_rotations SET enabled=0,status='轮换已暂停' WHERE id=?",(rid,))
                failover.configure(db,cipher,rid,d,now)
                if not rotation:rotation_timing.change(db,rid,sid,active_ip,int(time.time()),'plan_created')
                audit(db,'配置双 VPS 定时轮换 #'+str(rid))
                return jsonify(ok=True,rotation=_rotation_json(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()))
        except IntegrationError as e:return error(str(e),409)

    @auth()
    def save_rotation(sid):
        d=body();requested=d.get('binding_ids');rid=d.get('rotation_id')
        if rid is not None and type(rid)is not int:return error('轮换计划编号无效')
        if requested is not None and (not isinstance(requested,list) or not 1<=len(requested)<=50 or any(type(x)is not int or x<1 for x in requested) or len(set(requested))!=len(requested)):return error('请选择 1～50 条不同的 DNS 记录')
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone() if rid is not None else db.execute('SELECT * FROM vps_rotations WHERE binding_id=?',(d.get('binding_id') or (requested[0] if requested else None),)).fetchone()
            if rid is not None and (not old or old['primary_server_id']!=sid):return error('轮换计划不存在',404)
            if old and g.user['role']!='admin' and old['owner_id']!=g.user['id']:return error('轮换计划不属于当前账号',403)
            group=rotation_groups.members(db,old) if old else []
            old_ids=[x['binding_id'] for x in group]
            ids=requested if requested is not None else (old_ids or [d.get('binding_id')])
            if old and set(ids)!=set(old_ids):return error('已有计划的记录范围不能直接改变，请暂停并删除后重新创建',409)
            if not old and any(db.execute('SELECT 1 FROM vps_rotations WHERE binding_id=?',(bid,)).fetchone() for bid in ids):return error('所选记录已被其他计划管理',409)
            # A different record cannot silently create another plan on the same
            # physical pair; multi-selection creates one explicit group atomically.
            if not old and db.execute('SELECT 1 FROM vps_rotations WHERE primary_server_id=? AND other_server_id=?',(sid,d.get('other_server_id'))).fetchone():return error('这对 VPS 已有计划，请从原计划管理记录',409)
            g.rotation_db=db
            try:
                created=[]
                for bid in ids:
                    g.rotation_payload=dict(d,binding_id=bid)
                    response=app.make_response(save_one.__wrapped__(sid))
                    if response.status_code>=400:
                        db.rollback();return response
                    created.append(response.get_json()['rotation']['id'])
                root=db.execute('SELECT * FROM vps_rotations WHERE id=?',(min(created),)).fetchone()
                return jsonify(ok=True,rotation=_rotation_json(db,root))
            finally:
                g.pop('rotation_db',None);g.pop('rotation_payload',None)

    @auth()
    def readiness(sid):
        if g.user['role'] not in ('admin','client'):return error('无权管理轮换',403)
        d=body();other=d.get('other_server_id');bid=d.get('binding_id');checks=[];now=int(time.time());recommended=120
        with connect() as db:
            if type(other)is not int or not _owned_server(db,sid,g.user['id']) or not _owned_server(db,other,g.user['id']):return error('请选择两台自己的 VPS',404)
            existing=db.execute('SELECT owner_id FROM vps_rotations WHERE primary_server_id=?',(sid,)).fetchone()
            effective_uid=existing['owner_id'] if existing and g.user['role']=='admin' else g.user['id']
            for target in (sid,other):
                try:
                    _validated_plan(db,target,effective_uid);snap=_server_snapshot(db,target,now,cipher)
                    if d.get('mode')=='fixed_primary' and target==other:_rotation_tcp_count(snap['metrics'],now)
                    reason=boce_dns_gate(db,target,snap['ip'],snap['port'],require_plan=True)
                    if reason:raise IntegrationError(reason)
                    message='IP、TCP 上报、BOCE 和换 IP 动作（重启 / API）已就绪'
                    if d.get('mode')=='fixed_primary' and target==other:message='使用现有 TCP 已建立连接总数；IP、所选检测点和换 IP 动作已就绪'
                    checks.append({'name':'VPS #'+str(target),'ok':True,'message':message})
                except IntegrationError as e:checks.append({'name':'VPS #'+str(target),'ok':False,'message':str(e)})
            backup=d.get('failover_server_id')
            if backup is not None:
                try:
                    if type(backup)is not int or backup in (sid,other):raise IntegrationError('A 故障转移必须选择不同于 A/B 的第三台 VPS')
                    failover.probe_config(db,sid,effective_uid)
                    failover.standby_ready(db,cipher,{'primary_server_id':sid,'owner_id':effective_uid,'offline_after_s':d.get('offline_after_s',15)},backup,now)
                    if not db.execute('SELECT 1 FROM dns_bindings WHERE server_id=?',(sid,)).fetchone():raise IntegrationError('A 尚未绑定解析记录')
                    checks.append({'name':'A 故障转移 VPS','ok':True,'message':'冷备用就绪；故障时继承 A 的探测点，待命不拨测、不消耗额度'})
                except IntegrationError as e:checks.append({'name':'A 故障转移 VPS','ok':False,'message':str(e)})
            selected=d.get('binding_ids') or [bid]
            if not isinstance(selected,list) or not 1<=len(selected)<=50 or any(type(x)is not int for x in selected):return error('请选择 1～50 条 DNS 记录')
            for bid in selected:
                binding=db.execute('SELECT b.*,c.owner_id AS credential_owner FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE b.id=? AND b.server_id=?',(bid,sid)).fetchone()
                try:
                    if not binding or binding['credential_owner']!=(None if _admin_user(db,effective_uid) else effective_uid):raise IntegrationError('请选择主 VPS 自有 DNS 绑定')
                    conn=load_connection(db,cipher,binding['connection_id']);record=get_dns_record(conn,binding);validate_dns_record(record,binding,conn)
                    ttl=int(record.get('ttl',record.get('TTL',300)) or 300);ttl=300 if ttl<=1 else ttl;recommended=max(recommended,ttl+60)
                    checks.append({'name':'DNS 记录','ok':True,'message':'记录身份与当前值核对通过；启用后接管单机自动解析，本次未修改 DNS；建议提前至少 '+str(recommended)+' 秒'})
                except IntegrationError as e:checks.append({'name':'DNS 记录','ok':False,'message':str(e)})
        return jsonify(ok=all(x['ok'] for x in checks),checks=checks,recommended_lead_s=recommended)
    app.add_url_rule('/api/client/servers/<int:sid>/rotation/readiness','client_rotation_readiness',readiness,methods=['POST'])

    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_get_vps_rotation',get_rotation,methods=['GET'])
    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_save_vps_rotation',save_rotation,methods=['PUT'])

    @auth()
    def delete_rotation(sid):
        if g.user['role'] not in ('admin','client'):return error('无权管理轮换',403)
        with connect() as lookup:
            db_file=lookup.execute('PRAGMA database_list').fetchone()[2]
        with open(str(Path(db_file).with_suffix('.rotation.lock')),'a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return error('轮换动作正在提交，请稍后重试删除',409)
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                if not _owned_server(db,sid,g.user['id']):return error('服务器不存在',404)
                from flask import request
                requested=request.args.get('rotation_id',type=int)
                choices=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? AND (? OR owner_id=?) ORDER BY id',(sid,int(g.user['role']=='admin'),g.user['id'])).fetchall()
                if requested is None and len({p['other_server_id'] for p in choices})>1:return error('该主机有多个计划，请指定 rotation_id 删除目标计划',409)
                rotation=next((p for p in choices if p['id']==requested),None) if requested is not None else (choices[0] if choices else None)
                if not rotation:return error('轮换计划不存在',404)
                group=rotation_groups.members(db,rotation)
                for member in group:
                    if member['enabled']:return error('请先暂停轮换再删除',409)
                    if member['dns_intent']:return error('DNS 写入结果待核对，请确认实际解析后再删除',409)
                    if db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=? OR binding_id=?',(member['id'],member['binding_id'])).fetchone():return error('C 正在接替解析，请等待安全切回 A 后再删除',409)
                ids={m['id'] for m in group}
                for target in (rotation['primary_server_id'],rotation['other_server_id']):
                    remaining=[p for p in db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? OR other_server_id=?',(target,target)).fetchall() if p['id'] not in ids]
                    if remaining:
                        inflight=next((p for p in group if p['drain_server_id']==target and p['phase']=='waiting_ip' and p['action_started'] is not None),None)
                        if inflight:
                            recipient=next((p for p in remaining if p['active_server_id']!=target and p['mode']=='fixed_primary'),None)
                            if not recipient:return error('共享机器已有在途动作，尚无安全接管该动作的其他计划',409)
                            fields=['phase','drain_server_id','drain_started','drain_grace_s','old_ip','new_ip','action_started','action_attempts','reboot_command_id','last_sample_at','low_samples','emergency','fault_recovery']
                            db.execute('UPDATE vps_rotations SET '+','.join(k+'=?' for k in fields)+',status=?,updated=? WHERE id=?',[inflight[k] for k in fields]+['原计划已删除，接管共享主机的在途换 IP 动作；不重复发送',int(time.time()),recipient['id']])
                        continue
                    db.execute('UPDATE detection_plans SET action_enabled=0 WHERE server_id=?',(target,))
                    db.execute("UPDATE detection_runs SET action_status='cancelled',action_result='轮换计划已删除，停止自动换 IP 重试；已发出的外部请求无法撤回' WHERE server_id=? AND action_status IN ('queued','issued','submitted','uncertain','verifying')",(target,))
                    db.execute("UPDATE commands SET status='cancelled',updated=? WHERE server_id=? AND action IN ('reboot','hkt_dhcp') AND status='queued'",(int(time.time()),target))
                for member in group:
                    failover.stop_probe(db,member['id'],remove=True)
                    db.execute('DELETE FROM vps_rotations WHERE id=?',(member['id'],))
                    db.execute("UPDATE dns_bindings SET automatic=0,candidate=NULL,candidate_since=NULL,status='轮换计划已删除，DNS 记录已释放，可用于新计划',updated=? WHERE id=?",(int(time.time()),member['binding_id']))
                audit(db,'删除多记录轮换计划 #'+str(rotation['id']))
        return jsonify(ok=True)
    delete_rotation.__name__='client_delete_vps_rotation'
    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_delete_vps_rotation',delete_rotation,methods=['DELETE'])
    @app.get('/api/admin/rotations')
    @auth(admin=True)
    def admin_rotations():
        with connect() as db:
            return jsonify(rotations=[dict(_rotation_json(db,r),owner_role=db.execute('SELECT role FROM users WHERE id=?',(r['owner_id'],)).fetchone()['role']) for r in rotation_groups.roots(db)],servers=[dict(x) for x in db.execute('SELECT id,name FROM servers')],bindings=[dict(x) for x in db.execute('SELECT b.id,b.server_id,b.domain,b.rr,b.line,b.expected_ip,c.owner_id AS credential_owner FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id')],dns_connections=[dict(x) for x in db.execute("SELECT id,name,kind,json_extract(config,'$.zone_name') AS zone_name FROM ip_connections WHERE owner_id IS NULL AND kind IN ('alidns','cloudflare')")])
    @app.patch('/api/admin/rotations/<int:rid>/failover')
    @auth(admin=True)
    def admin_rotation_failover(rid):
        d=body()
        if not isinstance(d,dict) or not d or set(d)-{'failover_server_id','failover_recovery_s'}:
            return error('此入口只保存故障转移 VPS 和恢复稳定时间')
        if 'failover_server_id' in d and d['failover_server_id'] is not None and type(d['failover_server_id'])is not int:
            return error('请选择故障转移 VPS，或选择不启用')
        now=int(time.time())
        try:
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                root=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
                if not root:return error('轮换计划不存在',404)
                group=rotation_groups.members(db,root)
                for member in group:failover.configure(db,cipher,member['id'],d,now)
                audit(db,'配置轮换计划故障转移 #'+str(rid))
                result=_rotation_json(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone())
            return jsonify(ok=True,rotation=result)
        except IntegrationError as e:return error(str(e),409)
    @app.get('/api/admin/rotation-drain-statistics')
    @auth(admin=True)
    def admin_drain_statistics():
        with connect() as db:
            return jsonify(rotations=[dict(_rotation_json(db,r),drain_statistics=_drain_statistics(db,r,200),ip_actions=[dict(x) for x in db.execute('SELECT t.*,s.name AS server_name FROM rotation_recovery_timings t LEFT JOIN servers s ON s.id=t.server_id WHERE rotation_id=? ORDER BY started DESC,id DESC LIMIT 200',(r['id'],))]) for r in db.execute('SELECT * FROM vps_rotations ORDER BY id')],incidents=[dict(x) for x in db.execute('SELECT d.id,d.server_id,s.name AS server_name,d.ip,d.port,d.confirmed_at,d.closed_at,d.state FROM detection_incidents d JOIN servers s ON s.id=d.server_id WHERE d.confirmed_at IS NOT NULL ORDER BY d.confirmed_at DESC LIMIT 500')])
    app.add_url_rule('/api/admin/servers/<int:sid>/rotation','admin_save_rotation',auth(admin=True)(save_rotation.__wrapped__),methods=['PUT'])
    app.add_url_rule('/api/admin/servers/<int:sid>/rotation/readiness','admin_rotation_readiness',auth(admin=True)(readiness.__wrapped__),methods=['POST'])
    app.add_url_rule('/api/admin/servers/<int:sid>/rotation','admin_delete_rotation',auth(admin=True)(delete_rotation.__wrapped__),methods=['DELETE'])


def _event(db,rid,sid,message,now):
    db.execute('INSERT INTO vps_rotation_events(rotation_id,server_id,message,created) VALUES(?,?,?,?)',(rid,sid,message,now))
    db.execute('DELETE FROM vps_rotation_events WHERE id NOT IN (SELECT id FROM vps_rotation_events ORDER BY id DESC LIMIT 500)')

def _fresh_ip(db,sid,now,cipher):
    server=db.execute('SELECT metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
    monitor=db.execute('SELECT source_id,port,enabled FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
    if not server or not monitor or not monitor['enabled'] or not server['seen'] or not 0<=now-server['seen']<=45:raise IntegrationError('等待 VPS agent 新鲜上报')
    address=candidate_ip(db,{'server_id':sid,'source_id':monitor['source_id']},cipher)
    return public_v4(address),monitor['port'],json.loads(server['metrics'] or '{}')

def _failed_ip(db,sid,now):
    plan=db.execute('SELECT p.*,m.port FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(sid,)).fetchone()
    node=db.execute('SELECT metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
    if not plan or not node or not node['seen'] or now-node['seen']>45:return False
    try:address=candidate_ip(db,{'server_id':sid,'source_id':None},None)
    except IntegrationError:return False
    run=db.execute("SELECT * FROM detection_runs WHERE server_id=? AND status NOT IN ('creating','pending','queued','issued') ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
    if not run or run['source_id']!=plan['source_id'] or run['nodes']!=plan['nodes'] or run['ip']!=address or run['port']!=plan['port'] or now-run['updated']>max(120,plan['interval_s']*2):return False
    confirmation=detection_recheck.confirmed(db,plan,run)
    if confirmation is False:return False
    try:
        rows=json.loads(run['details']);nodes=json.loads(plan['nodes'])
        return bool(nodes) and len(rows)==len(nodes) and {str(x.get('node_id')) for x in rows}==set(map(str,nodes)) and all(x.get('state')=='unreachable' for x in rows)
    except (TypeError,ValueError,AttributeError):return False

def _carrier_suspect(db,sid,now):
    """A current raw failure may request a safe standby check, never authorize repair."""
    if _failed_ip(db,sid,now):return True
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detection_rechecks'").fetchone():return False
    if not db.execute("SELECT 1 FROM detection_rechecks c JOIN detection_runs r ON r.id=c.parent_id WHERE r.server_id=? AND c.state IN ('queued','creating','pending') LIMIT 1",(sid,)).fetchone():return False
    row=db.execute("SELECT r.*,p.nodes AS plan_nodes,p.source_id AS plan_source,m.port AS monitor_port,s.seen FROM detection_runs r JOIN detection_plans p ON p.server_id=r.server_id JOIN detection_sources source ON source.id=p.source_id JOIN ip_monitors m ON m.server_id=r.server_id JOIN servers s ON s.id=r.server_id WHERE r.server_id=? AND p.automatic=1 AND source.enabled=1 AND m.enabled=1 AND r.scheduled=1 AND r.status NOT IN ('creating','pending','queued','issued') ORDER BY r.id DESC LIMIT 1",(sid,)).fetchone()
    if not row or not row['seen'] or not 0<=now-row['seen']<=45 or not 0<=now-row['updated']<=120:return False
    if row['source_id']!=row['plan_source'] or row['nodes']!=row['plan_nodes'] or row['port']!=row['monitor_port']:return False
    check=db.execute("SELECT state FROM detection_rechecks WHERE parent_id=?",(row['id'],)).fetchone()
    if not check or check['state'] not in ('queued','creating','pending'):return False
    try:
        address=candidate_ip(db,{'server_id':sid,'source_id':None},None)
        return address==row['ip'] and detection_recheck.failed(json.loads(row['details']),json.loads(row['nodes']))
    except (IntegrationError,ValueError,TypeError):return False


def _pending_action(db,sid,verified_candidate=None):
    """A queued/issued action may execute after an apparently healthy probe."""
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='commands'").fetchone():
        if db.execute("SELECT 1 FROM commands WHERE server_id=? AND action IN ('reboot','hkt_dhcp') AND status IN ('queued','issued','accepted','unconfirmed') LIMIT 1",(sid,)).fetchone():return True
    if verified_candidate is not None:
        return bool(db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND action_status IN ('queued','issued','submitted','uncertain','verifying') AND (action_status<>'verifying' OR action_candidate IS NULL OR action_candidate<>?) LIMIT 1",(sid,verified_candidate)).fetchone())
    return bool(db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND action_status IN ('queued','issued','submitted','uncertain','verifying') LIMIT 1",(sid,)).fetchone())


def _fixed_failure(db,sid,now):
    """Only the configured nodes/IP/port count, using the configured failure threshold."""
    if not _failed_ip(db,sid,now):return False
    plan=db.execute('SELECT p.*,m.port,m.enabled AS monitor_enabled,s.enabled AS source_enabled FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(sid,)).fetchone()
    if not plan or not plan['automatic'] or not plan['monitor_enabled'] or not plan['source_enabled']:return False
    if dict(plan).get('confirm_node'):return True # _failed_ip already required the independent failed point.
    threshold=max(1,plan['failure_threshold'])
    runs=db.execute("SELECT * FROM detection_runs WHERE server_id=? AND status NOT IN ('creating','pending','queued','issued') ORDER BY id DESC LIMIT ?",(sid,threshold)).fetchall()
    if len(runs)!=threshold:return False
    nodes=set(map(str,json.loads(plan['nodes'])))
    if not nodes:return False
    address=runs[0]['ip']
    for run in runs:
        if detection_recheck.confirmed(db,plan,run) is False:return False
        if run['source_id']!=plan['source_id'] or run['nodes']!=plan['nodes'] or run['ip']!=address or run['port']!=plan['port'] or not 0<=now-run['updated']<=max(120,plan['interval_s']*2):return False
        try:rows=json.loads(run['details'])
        except (ValueError,TypeError):return False
        if not isinstance(rows,list) or len(rows)!=len(nodes) or any(not isinstance(x,dict) for x in rows):return False
        if {str(x.get('node_id')) for x in rows}!=nodes or any(x.get('state')!='unreachable' for x in rows):return False
    return True


def _request_probe(db,sid,now):
    # Keep an accelerated cadence until a complete, current result is available.
    last=db.execute('SELECT MAX(created) FROM detection_runs WHERE server_id=?',(sid,)).fetchone()[0]
    if last is None or now-last>=10:
        db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,sid))


def _request_new_ip_probe(db,sid,ip,port,now,urgent=False):
    # The worker may already have submitted this exact new-IP round before
    # rotation observes the agent update. Do not queue a second paid task.
    existing=urgent and db.execute("SELECT 1 FROM detection_runs r JOIN detection_plans p ON p.server_id=r.server_id WHERE r.server_id=? AND r.ip=? AND r.port=? AND r.source_id=p.source_id AND r.nodes=p.nodes AND (r.status IN ('creating','pending','queued','issued') OR r.created>=?) LIMIT 1",(sid,ip,port,now)).fetchone()
    if not existing:db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,sid))


def _preferred_rotation_ip(db,sid,ip):
    # Registered HKT DHCP machines must never be published with a nonpreferred IP.
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='hkt_dhcp_apis'").fetchone():
        if db.execute('SELECT 1 FROM hkt_dhcp_apis WHERE server_id=?',(sid,)).fetchone() and not ip.startswith('42.'):
            raise IntegrationError('HKT 优选 IP 策略：仅允许 42 开头的 IPv4 进入轮换；当前 '+ip)


def _fixed_ready(db,cipher,r,sid,now,verified_candidate=None,allow_draining=False):
    rotation_groups.target_guard(db,r,sid)
    if _offline(db,sid,now,r['offline_after_s']):raise IntegrationError('目标 VPS 心跳已超时，不能接替')
    if not allow_draining and not _fixed(r) and r['phase']=='draining' and r['drain_server_id']==sid:raise IntegrationError('旧 VPS 尚未完成排空、换 IP 和复检，不能重新承载')
    if r['phase'] in ('waiting_ip','waiting_probe') and r['drain_server_id']==sid:raise IntegrationError('目标 VPS 的换 IP / 复检尚未结束，不能接替')
    if _pending_action(db,sid,verified_candidate):raise IntegrationError('目标 VPS 有未结束的重启或换 IP 动作，不能接替')
    ip,port,metrics=_fresh_ip(db,sid,now,cipher)
    _preferred_rotation_ip(db,sid,ip)
    if verified_candidate is not None and ip!=verified_candidate:raise IntegrationError('待恢复候选 IP 已变化，重新验证')
    last=db.execute("SELECT updated FROM detection_runs WHERE server_id=? AND status NOT IN ('creating','pending','queued','issued') ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
    if not last or not 0<=now-last['updated']<=90:raise IntegrationError('目标 VPS 所选检测点结果过期，正在加急复测')
    reason=boce_dns_gate(db,sid,ip,port,require_plan=True)
    if reason:raise IntegrationError('目标 VPS 尚未通过其所选检测点：'+reason)
    try:
        with socket.create_connection((ip,port),timeout=4):pass
    except OSError:raise IntegrationError('目标 VPS 业务端口不可达') from None
    return ip,port,metrics


def _fixed_action_safe(db,cipher,r,old,now):
    if old==r['active_server_id']:raise IntegrationError('此 VPS 当前仍承载所选线路解析，禁止换 IP')
    active=r['active_server_id']
    _request_probe(db,active,now)
    if _pending_action(db,active):raise IntegrationError('承载 VPS 有未完成动作，禁止同时更换两台 IP')
    both_failed=_fixed_failure(db,active,now) and _fixed_failure(db,old,now)
    if not both_failed:_fixed_ready(db,cipher,r,active,now)
    if _pending_action(db,old):raise IntegrationError('此 VPS 已有未完成动作，禁止重复换 IP')


def _begin_fixed_repair(db,cipher,r,sid,now,message):
    ip,_,_=_fresh_ip(db,sid,now,cipher)
    emergency=1
    db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,drain_started=?,drain_grace_s=0,old_ip=?,new_ip=NULL,action_started=NULL,reboot_command_id=NULL,last_sample_at=NULL,low_samples=?,emergency=?,status=?,updated=? WHERE id=?",(sid,now,ip,2 if emergency else 0,emergency,message,now,r['id']))
    _event(db,r['id'],sid,message,now)


def _reconcile_fixed_dns(connect,cipher,rid,now):
    """Reconcile an external DNS write before any further switching or IP action."""
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not r or not r['dns_intent']:return False
        intent=json.loads(r['dns_intent'])
        binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
        if not binding:raise IntegrationError('DNS 写入结果待核对，但绑定已删除')
        conn=load_connection(db,cipher,binding['connection_id'])
        record=get_dns_record(conn,binding)
        actual=record.get('content',record.get('Value'))
        validate_dns_record(record,dict(binding,expected_ip=actual),conn)
        if actual!=intent['to']:
            message='DNS 写入结果尚未确认，暂停切换及换 IP；等待回读目标值' if actual==intent['from'] else 'DNS 已被外部改为其他 IP，暂停切换及换 IP，需核对记录'
            db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,now,rid));return True
        target=intent['target'];old=r['active_server_id'];ttl=intent['ttl']
        normal_takeover=target==r['other_server_id'] and not _fixed_failure(db,r['primary_server_id'],now)
        emergency=int(bool(intent.get('emergency',target==r['other_server_id'] and not normal_takeover)) and not intent.get('offline',False))
        phase='active' if normal_takeover else 'draining'
        delay=r['interval_s'] if target==r['other_server_id'] else 0
        message='已回读确认此前 DNS 切换结果，恢复固定主机协调流程'
        record_switch(db,rid,binding,intent['from'],intent['to'],intent['submitted'],now,ttl,bool(record.get('proxied',False)))
        rotation_timing.change(db,rid,target,intent['to'],now,'dns_reconciled')
        db.execute('UPDATE dns_bindings SET expected_ip=?,status=?,updated=? WHERE id=?',(intent['to'],message,now,binding['id']))
        db.execute('UPDATE vps_rotations SET active_server_id=?,phase=?,drain_server_id=?,drain_started=?,drain_grace_s=?,old_ip=?,new_ip=NULL,action_started=NULL,reboot_command_id=NULL,last_sample_at=NULL,low_samples=?,emergency=?,next_switch_at=?,dns_intent=NULL,status=?,updated=? WHERE id=?',(target,phase,None if normal_takeover else old,None if normal_takeover else now,0 if emergency or normal_takeover else ttl+60,None if normal_takeover else intent['from'],2 if emergency else 0,emergency,now+delay,message,now,rid))
        if emergency:db.execute('UPDATE vps_rotations SET fault_recovery=1 WHERE id=?',(rid,))
        if phase=='draining':_drain_timing(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone(),now,start=True)
        _event(db,rid,target,message,now)
        return True


def _coordinate_fixed(connect,cipher,rid,now):
    """Return False only when the existing serialized repair flow may advance."""
    if _reconcile_fixed_dns(connect,cipher,rid,now):return True
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not r or not r['enabled']:return True
        a,b=r['primary_server_id'],r['other_server_id']
        for sid in (a,b):
            if _failed_ip(db,sid,now):_request_probe(db,sid,now)
        af,bf=_fixed_failure(db,a,now),_fixed_failure(db,b,now)
        active=r['active_server_id'];failed=af if active==a else bf
        target=b if active==a else a
        # A repair in flight is not cancelled or overwritten, even if the active
        # machine fails. Finish/verify the target before publishing its address.
        if r['phase'] in ('waiting_ip','waiting_probe'):
            _request_probe(db,r['drain_server_id'],now)
            if failed:_request_probe(db,active,now)
            return False
        if _offline(db,active,now,r['offline_after_s']):
            _request_probe(db,target,now)
            try:_fixed_ready(db,cipher,r,target,now)
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('离线接替等待：'+str(e),now,rid));return True
            db.commit()
            _dns_switch(connect,cipher,rid,now,emergency=True,offline=True)
            return False
        if failed and not (bf if target==b else af):
            _request_probe(db,target,now)
            try:_fixed_ready(db,cipher,r,target,now)
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('故障接替等待：'+str(e),now,rid))
                return True
            # Before an action is submitted, a draining B can be reclaimed.
            db.commit()
            _dns_switch(connect,cipher,rid,now,emergency=True)
            return False
        if r['phase']=='draining':return False
        if r['phase']!='active':raise IntegrationError('固定主机轮换状态异常')
        standby_failed=bf if target==b else af
        if standby_failed:
            if not failed:
                _request_probe(db,active,now)
                try:_fixed_ready(db,cipher,r,active,now)
                except IntegrationError as e:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('故障修复等待：'+str(e),now,rid));return True
            message='所选检测点确认主 VPS 不通，所选记录保持轮换机，协调主 VPS 自动换 IP' if target==a else '轮换 VPS 所选检测点不通，保持当前解析，立即修复故障 IP'
            _begin_fixed_repair(db,cipher,r,target,now,message)
            return True
        if r['next_switch_at']-now<=60:
            _request_probe(db,a,now);_request_probe(db,b,now)
        if r['next_switch_at']<=now:
            try:_fixed_ready(db,cipher,r,target,now)
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('计划切换延后：'+str(e),now,rid));return True
            db.commit()
            _dns_switch(connect,cipher,rid,now)
        return True


def _offline(db,sid,now,timeout=15):
    node=db.execute('SELECT seen FROM servers WHERE id=?',(sid,)).fetchone()
    return not node or not node['seen'] or now-node['seen']>=timeout


def heartbeat_probe_target(db,sid,port,now,run=None):
    """Probe the frozen DNS carrier address even when its agent has gone stale."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_rotations'").fetchone():raise IntegrationError('agent 上报已过期，且没有轮换心跳复测任务')
    if _pending_action(db,sid):raise IntegrationError('原机存在在途动作，等待心跳复测')
    addresses=set()
    for r in db.execute("SELECT r.*,b.expected_ip,b.port AS dns_port FROM vps_rotations r JOIN dns_bindings b ON b.id=r.binding_id WHERE r.mode='alternating' AND ((r.active_server_id=? AND r.heartbeat_check IS NOT NULL) OR (r.drain_server_id=? AND r.repair_check_required=1 AND r.repair_check IS NOT NULL)) AND NOT EXISTS(SELECT 1 FROM vps_failover_leases l WHERE l.binding_id=r.binding_id)",(sid,sid)):
        repairing=r['drain_server_id']==sid and r['repair_check_required'] and r['phase']=='draining' and r['action_started'] is None
        try:state=json.loads(r['repair_check'] if repairing else r['heartbeat_check'])
        except (ValueError,TypeError):continue
        address=r['old_ip'] if repairing else r['expected_ip']
        if state.get('sid')==sid and state.get('ip')==address and r['dns_port']==port and not r['dns_intent'] and not r['external_dns_pending']:
            if run is not None and (run['id']<=state.get('floor',0) or run['created']<state.get('after',0) or run['source_id']!=state.get('source') or run['nodes']!=state.get('nodes')):continue
            addresses.add(public_v4(address))
    if len(addresses)!=1:raise IntegrationError('没有唯一已确认的承载 IP 可供心跳复测')
    address=addresses.pop()
    monitor=db.execute('SELECT current_ip FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
    if monitor and monitor['current_ip'] and monitor['current_ip']!=address:raise IntegrationError('已观察到 IP 变化，不能复用旧承载地址')
    node=db.execute('SELECT metrics FROM servers WHERE id=?',(sid,)).fetchone()
    try:
        metrics=json.loads(node['metrics'] or '{}') if node else {}
        def known_ips(values):
            result=set()
            for value in values:
                try:result.add(public_v4(value))
                except IntegrationError:pass
            return result
        known=known_ips(metrics.get('public_ips',[])) or known_ips(metrics.get('egress_ips',[]))
    except (ValueError,TypeError,AttributeError):raise IntegrationError('上报地址格式异常，不能复用旧承载地址') from None
    if known and known!={address}:raise IntegrationError('已上报的地址与本轮冻结 IP 不一致，取消旧诊断')
    return address


def _heartbeat_confirmed(db,r,now,subject=None,subject_ip=None,force=False):
    """Missing telemetry alone is not an outage: require a new domestic round."""
    if _fixed(r):return True
    sid=r['active_server_id'] if subject is None else subject
    field='repair_check' if force else 'heartbeat_check'
    current=db.execute(f'SELECT {field} FROM vps_rotations WHERE id=?',(r['id'],)).fetchone()
    try:state=json.loads(current[field] or '{}')
    except (ValueError,TypeError):state={}
    if not force and not _offline(db,sid,now,r['offline_after_s']):
        if state:
            db.execute('UPDATE vps_rotations SET heartbeat_check=NULL WHERE id=?',(r['id'],))
            message='心跳上报已恢复正常；保留当前 DNS 和原轮换截止时间'
            if (r['status'] or '').startswith('心跳超时'):
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,now,r['id']))
            if state.get('sid')==sid:_event(db,r['id'],sid,message,now)
        return False
    binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
    plan=db.execute('SELECT p.*,m.port AS monitor_port,m.enabled AS monitor_enabled,s.enabled AS source_enabled FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(sid,)).fetchone()
    if not binding or not plan or not plan['automatic'] or not plan['monitor_enabled'] or not plan['source_enabled']:return None
    address=public_v4(subject_ip or binding['expected_ip']);port=binding['port']
    if port!=plan['monitor_port']:return None
    if state.get('sid')!=sid or state.get('ip')!=address or state.get('source')!=plan['source_id'] or state.get('nodes')!=plan['nodes']:
        state={'sid':sid,'ip':address,'source':plan['source_id'],'nodes':plan['nodes'],'after':now+1,
               'floor':db.execute('SELECT COALESCE(MAX(id),0) FROM detection_runs WHERE server_id=?',(sid,)).fetchone()[0]}
        db.execute(f'UPDATE vps_rotations SET {field}=? WHERE id=?',(json.dumps(state),r['id']))
        db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now+1,sid))
        message=('B 已接替：复测原承载机国内 TCP 和业务端口，确认故障前不更换原机 IP' if force else _carrier_fault_reason(db,r,now)+'；请求业务复测，不能仅凭心跳超时更换 IP')
        if r['phase']=='active':db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,now,r['id']))
        _event(db,r['id'],sid,message,now)
        return None
    runs=db.execute("SELECT * FROM detection_runs WHERE server_id=? AND status NOT IN ('creating','pending','queued','issued') ORDER BY id DESC LIMIT ?",(sid,max(1,plan['failure_threshold']))).fetchall()
    def valid(run):
        return (run['id']>state['floor'] and run['created']>=state['after'] and 0<=now-run['updated']<=90
                and run['ip']==address and run['port']==port and run['source_id']==plan['source_id'] and run['nodes']==plan['nodes'])
    if not runs or not valid(runs[0]):
        _request_probe(db,sid,now)
        return None
    if state.get('run')==runs[0]['id'] and 0<=now-state.get('checked',0)<=10:
        return bool(state.get('confirmed'))
    try:
        rows=json.loads(runs[0]['details']);nodes=set(map(str,json.loads(plan['nodes'])))
        def all_failed(run):
            details=json.loads(run['details'])
            return bool(nodes) and len(details)==len(nodes) and {str(x['node_id']) for x in details}==nodes and all(x['state']=='unreachable' for x in details)
        confirmation=detection_recheck.confirmed(db,plan,runs[0])
        failed=confirmation is not False and all_failed(runs[0]) and (confirmation is True or (len(runs)>=plan['failure_threshold'] and all(valid(x) and all_failed(x) and detection_recheck.confirmed(db,plan,x) is not False for x in runs)))
        domestic_ok=bool(nodes) and len(rows)==len(nodes) and {str(x['node_id']) for x in rows}==nodes and all(x['state']=='reachable' for x in rows)
    except (ValueError,TypeError,KeyError,AttributeError):return None
    if not failed and not domestic_ok:
        db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,sid));return None
    port_ok=False
    try:
        with socket.create_connection((address,port),timeout=4):port_ok=True
    except OSError:pass
    confirmed=bool(failed or (domestic_ok and not port_ok))
    if state.get('run')!=runs[0]['id'] or state.get('confirmed')!=confirmed:
        state.update(run=runs[0]['id'],confirmed=confirmed,checked=now)
        db.execute(f'UPDATE vps_rotations SET {field}=? WHERE id=?',(json.dumps(state),r['id']))
        message=(('原承载机复测确认故障：立即换 IP 并复检' if confirmed else '原承载机复测正常：保留原 IP，验证可接回后切回') if force else ('心跳超时复测确认业务不通：允许故障修复' if confirmed else '心跳超时但国内拨测及业务端口均通：不触发故障换 IP'))
        if r['phase']=='active':db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,now,r['id']))
        _event(db,r['id'],sid,message,now)
    else:
        state['checked']=now
        db.execute(f'UPDATE vps_rotations SET {field}=? WHERE id=?',(json.dumps(state),r['id']))
    if not confirmed and not force:
        db.execute('UPDATE vps_rotations SET emergency_probe_after=NULL WHERE id=?',(r['id'],))
    return confirmed


def _confirmed_offline(db,r,now):
    return _offline(db,r['active_server_id'],now,r['offline_after_s']) and (_fixed(r) or _heartbeat_confirmed(db,r,now))

def _carrier_alert_status(status):
    status=status or ''
    return (status.startswith('轮换暂缓：当前承载异常') or
            (status.startswith('轮换暂缓：等待换下 VPS #') and '本次故障后的新一轮探测' in status))

def _carrier_fault_reason(db,r,now):
    sid=r['active_server_id']
    if _offline(db,sid,now,r['offline_after_s']):
        node=db.execute('SELECT seen FROM servers WHERE id=?',(sid,)).fetchone()
        age=f'已 {max(0,now-node["seen"])} 秒未收到上报' if node and node['seen'] else '尚无有效心跳'
        return f'心跳超时：{age}，阈值 {r["offline_after_s"]} 秒；不能据此认定业务不通或被墙'
    if _failed_ip(db,sid,now):
        run=db.execute("SELECT ip,port FROM detection_runs WHERE server_id=? AND status NOT IN ('creating','pending','queued','issued') ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
        return f'国内 TCP 检测不通：{run["ip"]}:{run["port"]}，所选节点已满足当前故障确认条件'
    if _carrier_suspect(db,sid,now):return '当前承载首轮 TCP 全部不通，网站校验／独立复检尚未完成；先复检备用机，不据此更换原机 IP'
    return '本次故障接替来源待核对，当前没有可确认的心跳超时或国内 TCP 不通证据'

def _original_emergency_probe(db,r,target,now):
    """Require a new probe round after the incident, not a cached healthy result."""
    after=r['emergency_probe_after']
    if after is None:
        # One second boundary prevents a pre-incident result from the same second
        # being reused. Persist before returning to the asynchronous worker.
        after=now+1
        db.execute('UPDATE vps_rotations SET emergency_probe_after=? WHERE id=?',(after,r['id']))
        db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(after,target))
        reason=('定时轮换已到期，备用机仍在排空' if r['phase']=='draining' and r['next_switch_at']<=now
                and not _offline(db,r['active_server_id'],now,r['offline_after_s']) and not _carrier_suspect(db,r['active_server_id'],now)
                else _carrier_fault_reason(db,r,now))
        _event(db,r['id'],r['active_server_id'],'请求接替前复检：'+reason,now)
        db.commit()
        raise IntegrationError(('定时接替等待复检：' if reason.startswith('定时轮换') else '当前承载异常，原因：')+reason+'；已请求刚换下 VPS #'+str(target)+' 加测一轮；通过后立即接替')
    last=db.execute("SELECT id,created FROM detection_runs WHERE server_id=? AND status NOT IN ('creating','pending','queued','issued') ORDER BY id DESC LIMIT 1",(target,)).fetchone()
    try:floor=json.loads(r['urgent_probe_floors'] or '{}').get(str(target))
    except (ValueError,TypeError):floor=None
    # A task ID reserved after the incident floor proves freshness even when
    # submission and completion happen inside the same timestamp second.
    post_incident=last and type(floor)is int and last['id']>floor
    if not last or (last['created']<after and not post_incident):
        db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(max(after,now),target))
        db.commit()
        raise IntegrationError('等待换下 VPS #'+str(target)+' 完成本次故障后的新一轮探测')


def _draining_fault_takeover(db,r,target,now):
    """Only a current carrier fault may reuse an unissued draining standby IP."""
    return (not _fixed(r) and r['phase']=='draining' and r['drain_server_id']==target
            and r['action_started'] is None and r['new_ip'] is None
            and not _pending_action(db,target) and not _pending_action(db,r['active_server_id'])
            and (_offline(db,r['active_server_id'],now,r['offline_after_s'])
                 or _carrier_suspect(db,r['active_server_id'],now)))


def _dns_switch(connect,cipher,rotation,now,emergency=False,offline=False):
    """Move every binding in a visible multi-record plan at one handoff."""
    with connect() as db:
        row=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rotation,)).fetchone()
        if not row:return
        group=[dict(x) for x in rotation_groups.members(db,row)]
    if len(group)<2:
        return _dns_switch_single(connect,cipher,rotation,now,emergency,offline)
    active=group[0]['active_server_id']
    if any(r['active_server_id']!=active or (r['phase']!='active' and not (emergency and r['phase']=='draining')) for r in group):
        raise IntegrationError('同一轮换计划的线路状态不一致，暂停切换并等待计划同步')
    if not emergency and any(not r['enabled'] or r['next_switch_at']>now for r in group):
        raise IntegrationError('同一轮换计划的线路尚未同时到达切换时间')
    prepared=[_dns_switch_single(connect,cipher,m['id'],now,emergency,offline,prepare=True) for m in group]
    if any(item is None for item in prepared):return
    intent=json.dumps({'kind':'group_switch_v1','members':prepared})
    with connect() as db:
        for member in group:
            db.execute('UPDATE vps_rotations SET dns_intent=? WHERE id=?',(intent,member['id']))
        db.commit()
    _reconcile_group_switch(connect,cipher,rotation,now)


def _dns_switch_single(connect,cipher,rotation,now,emergency=False,offline=False,prepare=False):
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rotation,)).fetchone()
        if not r or (not r['enabled'] and not emergency):return
        target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
        reuse_draining=emergency and _draining_fault_takeover(db,r,target,now)
        if not emergency and (r['phase']!='active' or r['next_switch_at']>now):return
        if emergency and r['phase'] in ('waiting_ip','waiting_probe'):raise IntegrationError('备用机正在换 IP 或复检，暂不能安全切回')
        binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
        if not binding:raise IntegrationError('轮换 DNS 绑定已删除')
        conn=load_connection(db,cipher,binding['connection_id'])
        target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
        if not reuse_draining and not _fixed(r) and r['phase']=='draining' and r['drain_server_id']==target:
            raise IntegrationError('旧 VPS 尚未完成排空、换 IP 和复检，不能重新承载')
        _validated_plan(db,target,r['owner_id'])
        if not _fixed(r) and r['reused_server_id']==target:
            address,_,_=_fresh_ip(db,target,now,cipher)
            if address==r['reused_ip']:
                message='年轻 IP 复用已取消；旧候选必须先换 IP 并复检，暂不切换解析'
                db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,drain_started=?,drain_grace_s=0,old_ip=?,new_ip=NULL,action_started=NULL,reboot_command_id=NULL,last_sample_at=NULL,low_samples=0,emergency=0,drain_base_attempt=action_attempts,preload_base_attempt=NULL,status=?,updated=? WHERE id=?",(target,now,address,message,now,rotation))
                _event(db,rotation,target,message,now)
                return
        if emergency and not _fixed(r):_original_emergency_probe(db,r,target,now)
        _fixed_ready(db,cipher,r,target,now,allow_draining=reuse_draining)
        if offline:old_ip,port=binding['expected_ip'],binding['port']
        else:old_ip,port,_=_fresh_ip(db,r['active_server_id'],now,cipher)
        target_ip,target_port,_=_fresh_ip(db,target,now,cipher)
        if target_port!=port or target_ip==old_ip:raise IntegrationError('备用 VPS 端口或公网 IP 无效')
        last=db.execute('SELECT updated FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1',(target,)).fetchone()
        if not last or now-last['updated']>90:raise IntegrationError('备用机探测结果超过 90 秒，等待切换前的新探测')
        reason=boce_dns_gate(db,target,target_ip,port,require_plan=True)
        if reason:raise IntegrationError('备用 VPS 尚未通过当前 IP 的 BOCE 检查：'+reason)
        if binding['expected_ip']!=old_ip:raise IntegrationError('DNS 记录和当前承载 VPS IP 不一致，已停止轮换')
        record=get_dns_record(conn,binding);validate_dns_record(record,binding,conn)
        try:
            with socket.create_connection((target_ip,port),timeout=4):pass
        except OSError:raise IntegrationError('备用 VPS 的业务 TCP 端口不可达，未切换 DNS') from None
        ttl=record.get('ttl',record.get('TTL',300))
        try:ttl=int(ttl)
        except (TypeError,ValueError):ttl=300
        if ttl<=1:ttl=300
        if ttl>604800:raise IntegrationError('DNS TTL 超过 7 天，已停止轮换')
        immediate_repair=not _fixed(r) and emergency
        grace=0 if immediate_repair or (emergency and not offline) else ttl+60
        submitted=int(time.time())
        if prepare:
            return dict(rotation=rotation,target=target,old_ip=old_ip,target_ip=target_ip,
                        ttl=ttl,submitted=submitted,emergency=emergency,offline=offline,
                        reuse_draining=reuse_draining,proxied=bool(record.get('proxied',False)))
        if _fixed(r):
            if r['dns_intent']:raise IntegrationError('上一次 DNS 写入结果未确认，暂停新切换')
            intent={'from':old_ip,'to':target_ip,'target':target,'submitted':submitted,'ttl':ttl,'emergency':bool(emergency),'offline':bool(offline)}
            db.execute('UPDATE vps_rotations SET dns_intent=? WHERE id=?',(json.dumps(intent),rotation))
            db.commit() # Durable intent survives provider timeouts and worker exits.
        update_dns_record(conn,binding,record,target_ip)
        updated=get_dns_record(conn,binding)
        expected=dict(binding,expected_ip=target_ip)
        validate_dns_record(updated,expected,conn)
        if _fixed(r):db.execute('UPDATE vps_rotations SET dns_intent=NULL WHERE id=?',(rotation,))
        _finish_dns_switch(db,r,binding,rotation,target,old_ip,target_ip,ttl,submitted,now,
                           emergency,offline,reuse_draining,bool(record.get('proxied',False)))


def _finish_dns_switch(db,r,binding,rotation,target,old_ip,target_ip,ttl,submitted,now,
                       emergency,offline,reuse_draining,proxied):
    immediate_repair=not _fixed(r) and emergency
    grace=0 if immediate_repair or (emergency and not offline) else ttl+60
    record_switch(db,rotation,binding,old_ip,target_ip,submitted,int(time.time()),ttl,proxied)
    if reuse_draining:
        _drain_timing(db,r,now,'skipped')
        _event(db,rotation,target,'故障应急接替：备用机现有 IP 已通过本次复检，跳过换 IP 接替；正常定时轮换仍须排空、换 IP 和复检',now)
    rotation_timing.change(db,rotation,target,target_ip,int(time.time()),'fault_switch' if emergency else 'scheduled_switch')
    message=f"DNS 已从 {old_ip} 切换到 {target_ip}；等待旧 VPS #{r['active_server_id']} 连接降到阈值以下"
    if offline:message=f'承载 VPS 离线，DNS 已从 {old_ip} 切到 {target_ip}；旧机等待恢复，未执行换 IP'
    if immediate_repair:message=f'DNS 已从 {old_ip} 切换到 {target_ip}；先复测原承载机，确认故障后跳过 TTL 与连接排空换 IP；通过后立即切回'
    db.execute('UPDATE dns_bindings SET expected_ip=?,status=?,updated=? WHERE id=?',(target_ip,message,now,binding['id']))
    db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,target))
    if _fixed(r) and target==r['other_server_id'] and not _fixed_failure(db,r['primary_server_id'],now):
        # Scheduled takeover never drains or refreshes the fixed primary.
        message=f'所选线路解析已切入轮换 VPS #{target}；主 VPS 保持原 IP；到时切回主 VPS'
        db.execute("UPDATE vps_rotations SET active_server_id=?,phase='active',drain_server_id=NULL,emergency=0,status=?,next_switch_at=?,updated=? WHERE id=?",(target,message,now+r['interval_s'],now,rotation))
        db.execute('UPDATE dns_bindings SET status=? WHERE id=?',(message,binding['id']))
        _event(db,rotation,target,message,now)
        return
    db.execute("UPDATE vps_rotations SET active_server_id=?,phase='draining',emergency_probe_after=NULL,drain_server_id=?,drain_started=?,drain_grace_s=?,old_ip=?,new_ip=NULL,action_started=NULL,reboot_command_id=NULL,last_sample_at=NULL,low_samples=0,status=?,next_switch_at=?,updated=? WHERE id=?",(target,r['active_server_id'],now,grace,old_ip,message,now+r['interval_s']-r['lead_s'],now,rotation))
    db.execute('UPDATE vps_rotations SET emergency=?,low_samples=? WHERE id=?',(int(emergency and not offline),2 if emergency and not offline else 0,rotation))
    if immediate_repair:
        db.execute('UPDATE vps_rotations SET emergency=1,low_samples=2,drain_grace_s=0 WHERE id=?',(rotation,))
    if _fixed(r):
        delay=r['interval_s'] if target==r['other_server_id'] else 0
        db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(now+delay,rotation))
        if r['active_server_id']==r['other_server_id'] and not (emergency and not offline):
            db.execute('UPDATE vps_rotations SET emergency=0,low_samples=0,drain_grace_s=? WHERE id=?',(ttl+60,rotation))
    if emergency:db.execute('UPDATE vps_rotations SET fault_recovery=1 WHERE id=?',(rotation,))
    db.execute('UPDATE vps_rotations SET repair_check_required=?,repair_check=NULL WHERE id=?',(int(emergency and not _fixed(r)),rotation))
    db.execute('UPDATE vps_rotations SET standby_ready_at=NULL,standby_ready_server=NULL,preload_refresh_deadline=NULL,preload_base_attempt=NULL,reused_ip=NULL,reused_server_id=NULL,drain_base_attempt=action_attempts WHERE id=?',(rotation,))
    _drain_timing(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rotation,)).fetchone(),now,start=True)
    _event(db,rotation,r['active_server_id'],message,now)

def _reconcile_group_switch(connect,cipher,rid,now):
    """Recover partial writes before failover, scheduling, or IP actions run."""
    with connect() as db:
        row=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not row or not row['dns_intent']:return False
        intent=json.loads(row['dns_intent'])
        if intent.get('kind')!='group_switch_v1':return False
        group=rotation_groups.members(db,row)
        if any(not r['enabled'] for r in group):return True
        if {r['id'] for r in group}!={m['rotation'] for m in intent['members']} or any(r['dns_intent']!=row['dns_intent'] for r in group):
            raise IntegrationError('多线路切换记录不完整，暂停并等待核对')
        prepared=[]
        # Verify record identities and the persisted target before any writes.
        for item in intent['members']:
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(item['rotation'],)).fetchone()
            binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
            if not binding:raise IntegrationError('多线路切换中的 DNS 绑定已删除')
            conn=load_connection(db,cipher,binding['connection_id'])
            record=get_dns_record(conn,binding)
            actual=record.get('content',record.get('Value'))
            validate_dns_record(record,dict(binding,expected_ip=actual),conn)
            # Revalidate the candidate before completing an interrupted handoff.
            address,port,_=_fresh_ip(db,item['target'],now,cipher)
            if address!=item['target_ip'] or port!=binding['port']:
                raise IntegrationError('多线路切换目标 IP 或端口已变化，暂停并等待核对')
            reason=boce_dns_gate(db,item['target'],address,port,require_plan=True)
            if reason:raise IntegrationError('多线路切换目标等待健康检查：'+reason)
            last=db.execute('SELECT updated FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1',(item['target'],)).fetchone()
            if not last or now-last['updated']>90:
                raise IntegrationError('多线路切换等待目标 VPS 的新探测')
            try:
                with socket.create_connection((address,port),timeout=4):pass
            except OSError:raise IntegrationError('多线路切换目标业务端口不可达，保留任务等待恢复') from None
            prepared.append((item,r,binding,conn,record,actual))
        for item,r,binding,conn,record,actual in prepared:
            if actual!=item['target_ip']:
                update_dns_record(conn,binding,record,item['target_ip'])
            latest=get_dns_record(conn,binding)
            validate_dns_record(latest,dict(binding,expected_ip=item['target_ip']),conn)
            if latest.get('content',latest.get('Value'))!=item['target_ip']:
                raise IntegrationError('多线路 DNS 写入尚未确认，保留切换任务等待重试')
        # No local carrier state advances until all authoritative records agree.
        for item,r,binding,conn,record,actual in prepared:
            _finish_dns_switch(db,r,binding,now=now,**item)
            db.execute('UPDATE vps_rotations SET dns_intent=NULL WHERE id=?',(r['id'],))
    return True


def _paused_failover(connect,cipher,rid,now):
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not r or r['enabled']:return
        if r['dns_intent']:
            db.commit();_reconcile_fixed_dns(connect,cipher,rid,now);return
        current=r['active_server_id']
        offline=_offline(db,current,now,r['offline_after_s'])
        failed=_fixed_failure(db,current,now) if _fixed(r) else (not _offline(db,current,now,r['offline_after_s']) and _carrier_suspect(db,current,now))
        if not offline and not failed:return
        target=r['other_server_id'] if current==r['primary_server_id'] else r['primary_server_id']
        _request_probe(db,target,now)
        if not _fixed(r) and r['phase']!='active':
            # Pausing the schedule must not starve an in-flight fault repair
            # by repeatedly trying to publish its unfinished standby.
            db.execute('UPDATE vps_rotations SET fault_recovery=1 WHERE id=?',(rid,))
            return
        db.commit()
        _fixed_ready(db,cipher,r,target,now)
        _dns_switch(connect,cipher,rid,now,emergency=True,offline=offline)


def db_failover_active(connect,rid):
    with connect() as db:return bool(db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=?',(rid,)).fetchone())


def _run_rotation(connect,cipher,rid,now):
    if _reconcile_group_switch(connect,cipher,rid,now):return
    with connect() as db:
        current=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
    if current and (current['enabled'] or current['failover_server_id'] or db_failover_active(connect,rid)):
        if failover.step(connect,cipher,rid,now):
            _sync_external_dns(connect,cipher,rid,now)
            return
    _sync_external_dns(connect,cipher,rid,now)
    with connect() as db:current=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
    if current and not current['enabled']:
        _paused_failover(connect,cipher,rid,now)
        with connect() as db:current=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not current or not current['fault_recovery']:return
    if current and current['enabled'] and _fixed(current):
        if _coordinate_fixed(connect,cipher,rid,now):return
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not r or (not r['enabled'] and not r['fault_recovery']):return
        r,drain_effective=rotation_schedule.sync(db,r,now)
        db.commit() # Release schedule sampling changes before a separate DNS handoff connection.
        # A recovered carrier ends this fault attempt. A later fault must request
        # another standby round, rather than reuse the previous incident's marker.
        stale_alert=r['phase']=='active' and _carrier_alert_status(r['status'])
        due_drain=not _fixed(r) and r['enabled'] and r['phase']=='draining' and r['next_switch_at']<=now
        if not due_drain and not _fixed(r) and (r['emergency_probe_after'] is not None or stale_alert) and not _offline(db,r['active_server_id'],now,r['offline_after_s']):
            try:
                address,port,_=_fresh_ip(db,r['active_server_id'],now,cipher)
                healthy=not boce_dns_gate(db,r['active_server_id'],address,port,require_plan=True)
            except IntegrationError:healthy=False
            if healthy:
                db.execute('UPDATE vps_rotations SET emergency_probe_after=NULL WHERE id=?',(rid,))
                message='当前承载机心跳及所选国内 TCP 检测已恢复正常；保留当前 DNS 和原轮换截止时间'
                if stale_alert:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,now,rid))
                _event(db,rid,r['active_server_id'],message,now)
                r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not _fixed(r) and r['phase']!='active' and (_offline(db,r['active_server_id'],now,r['offline_after_s']) or _carrier_suspect(db,r['active_server_id'],now)):
            # Only a current carrier fault permits freshly verified reuse of an
            # unissued draining standby; a scheduled deadline alone does not.
            target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
            after=r['emergency_probe_after']
            if after is None:
                after=now+1
                db.execute('UPDATE vps_rotations SET emergency_probe_after=? WHERE id=?',(after,rid))
                _event(db,rid,r['active_server_id'],'承载检测异常：'+_carrier_fault_reason(db,r,now)+'；优先请求备用机新一轮探测，就绪后接替',now)
            db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(max(now,after),target))
            # Urgent takeover uses emergency_probe_after, not the normal
            # deadline. A transient heartbeat gap must not shorten this tenure.
            if _draining_fault_takeover(db,r,target,now) and not _failed_ip(db,target,now):
                db.commit()
                _dns_switch(connect,cipher,rid,now,emergency=True,offline=_offline(db,r['active_server_id'],now,r['offline_after_s']))
                r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
            cancellable=(r['phase']=='draining' and r['drain_server_id']==target
                         and r['standby_ready_server']==target
                         and r['preload_base_attempt'] is not None
                         and r['action_attempts']==r['preload_base_attempt']
                         and r['action_started'] is None and r['reused_server_id'] is None)
            if cancellable:
                try:address,_,_=_fresh_ip(db,target,now,cipher)
                except IntegrationError:address=None
                if address==r['old_ip']:
                    db.execute("UPDATE vps_rotations SET phase='active',drain_server_id=NULL,drain_started=NULL,drain_grace_s=0,old_ip=NULL,new_ip=NULL,action_started=NULL,reboot_command_id=NULL,last_sample_at=NULL,low_samples=0,emergency=0,reused_ip=NULL,reused_server_id=NULL,status=?,updated=? WHERE id=?",('承载异常，取消尚未下发的可选补换；保留已完成换 IP 的备用机，等待新一轮探测后接替',now,rid))
                    _event(db,rid,target,'取消尚未下发的承载前补换：备用机保留已复检 IP，故障接替优先',now)
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
            db.commit() # DNS handoff reads through a separate connection.
        if not _fixed(r) and r['phase']=='active' and _offline(db,r['active_server_id'],now,r['offline_after_s']):
            target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
            if _offline(db,target,now,r['offline_after_s']):raise IntegrationError('当前机和备用机均离线，没有可用备用机；保持 DNS 并等待恢复')
            last=db.execute('SELECT MAX(created) FROM detection_runs WHERE server_id=?',(target,)).fetchone()[0]
            if last is None or now-last>=60:
                db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,target));db.commit()
            _dns_switch(connect,cipher,rid,now,emergency=True,offline=True)
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not _fixed(r) and r['phase']=='active' and not _offline(db,r['active_server_id'],now,r['offline_after_s']) and _carrier_suspect(db,r['active_server_id'],now):
            target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
            if not _failed_ip(db,target,now):
                last=db.execute('SELECT MAX(created) FROM detection_runs WHERE server_id=?',(target,)).fetchone()[0]
                if last is None or now-last>=60:
                    db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,target))
                    db.commit()
                _dns_switch(connect,cipher,rid,now,emergency=True)
                r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if r['phase']=='active':
            if _fixed(r) or not r['enabled']:return
            standby=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
            if _failed_ip(db,standby,now):
                address,_,_=_fresh_ip(db,standby,now,cipher)
                db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip=?,drain_started=?,drain_grace_s=0,emergency=1,low_samples=2,status=? WHERE id=?",(standby,address,now,'备用 IP 不通，保持当前 DNS 并主动修复备用机',rid))
                if _fixed(r) and standby==r['other_server_id']:db.execute('UPDATE vps_rotations SET emergency=0,low_samples=0,last_sample_at=NULL WHERE id=?',(rid,))
                return
            # Refresh an already prepared, idle standby once in the final five
            # minutes. Reuse the ordinary drain/action/probe gates, without DNS writes.
            ready=r['standby_ready_at']
            if (0<r['next_switch_at']-now<=300 and r['standby_ready_server']==standby
                    and ready is not None and ready<r['next_switch_at']-300
                    and r['preload_refresh_deadline']!=r['next_switch_at']):
                address,_,_=_fresh_ip(db,standby,now,cipher)
                message='承载前 5 分钟刷新备用 IP：重新确认连续两次 TCP 低于阈值，再换 IP 并复检；保留原定切换时间'
                db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,drain_started=?,drain_grace_s=0,old_ip=?,new_ip=NULL,action_started=NULL,reboot_command_id=NULL,last_sample_at=NULL,low_samples=0,emergency=0,drain_base_attempt=action_attempts,preload_base_attempt=action_attempts,preload_refresh_deadline=?,status=?,updated=? WHERE id=?",(standby,now,address,r['next_switch_at'],message,now,rid))
                _event(db,rid,standby,message,now)
                return
            if r['next_switch_at']-now<=max(60,r['lead_s']):
                for sid in (r['active_server_id'],standby):
                    last=db.execute('SELECT MAX(created) FROM detection_runs WHERE server_id=?',(sid,)).fetchone()[0]
                    if last is None or now-last>=60:db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,sid))
            if r['next_switch_at']<=now:
                db.commit()
                _dns_switch(connect,cipher,rid,now)
            return
        old=r['drain_server_id']
        if not old:return
        if r['phase']=='draining':
            _drain_timing(db,r,now)
            if not _fixed(r) and r['repair_check_required']:
                verdict=_heartbeat_confirmed(db,r,now,subject=old,subject_ip=r['old_ip'],force=True)
                if verdict is None:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('备用机已接替，等待原承载机本次业务复测；未确认故障，不更换 IP',now,rid));return
                if verdict is False:
                    ready=dict(r,phase='active',drain_server_id=None)
                    try:_fixed_ready(db,cipher,ready,old,now,verified_candidate=r['old_ip'])
                    except IntegrationError as e:
                        db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('原机业务复测正常，保留原 IP；等待可安全切回：'+str(e),now,rid));return
                    _drain_timing(db,r,now,'cancelled')
                    db.execute("UPDATE vps_rotations SET phase='active',drain_server_id=NULL,repair_check_required=0,repair_check=NULL,fault_recovery=0,emergency=0,next_switch_at=?,status=?,updated=? WHERE id=?",(now,'原机复测正常，保留原 IP 并立即切回',now,rid))
                    db.commit();_dns_switch(connect,cipher,rid,now);return
                db.execute('UPDATE vps_rotations SET emergency=1,low_samples=2,drain_grace_s=0 WHERE id=?',(rid,))
                r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
            if _fixed(r) and old==r['primary_server_id'] and not _fixed_failure(db,old,now):
                if _offline(db,old,now,r['offline_after_s']):
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('主 VPS 离线，等待恢复；未确认被墙，不更换主机 IP',now,rid));return
                address,port,_=_fresh_ip(db,old,now,cipher)
                reason=boce_dns_gate(db,old,address,port,require_plan=True)
                if reason:raise IntegrationError('等待主 VPS 恢复确认：'+reason)
                _drain_timing(db,r,now,'cancelled')
                db.execute("UPDATE vps_rotations SET phase='active',drain_server_id=NULL,emergency=0,next_switch_at=?,status=?,updated=? WHERE id=?",(now,'主 VPS 已恢复且保持原 IP，准备切回所选线路解析',now,rid));return
            if not r['emergency'] and (_fixed_failure(db,old,now) if _fixed(r) else _failed_ip(db,old,now)):
                db.execute('UPDATE vps_rotations SET emergency=1,low_samples=2,drain_grace_s=0 WHERE id=?',(rid,))
                r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
                _drain_timing(db,r,now)
            try:plan=_validated_plan(db,old,r['owner_id'])
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if now-(r['drain_started'] or now)<r['drain_grace_s']:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('等待 DNS TTL 到期后检查旧机连接',now,rid));return
            try:ip,port,metrics=_fresh_ip(db,old,now,cipher)
            except IntegrationError as e:
                proof=json.loads(r['repair_check'] or '{}')
                if (not _fixed(r) and r['repair_check_required'] and proof.get('confirmed') is True
                        and proof.get('sid')==old and proof.get('ip')==r['old_ip'] and 0<=now-proof.get('checked',0)<=90
                        and _offline(db,old,now,45) and plan.get('rotation_action')!='reboot' and plan.get('action_connection_id')):
                    ip,port,metrics=public_v4(r['old_ip']),db.execute('SELECT port FROM ip_monitors WHERE server_id=?',(old,)).fetchone()[0],{}
                else:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if ip!=r['old_ip']:
                _drain_timing(db,r,now,'unobserved')
                db.execute("UPDATE vps_rotations SET phase='waiting_probe',new_ip=?,action_started=COALESCE(action_started,?),status=?,updated=? WHERE id=?",(ip,now,'旧 VPS IP 已变化，等待 BOCE 复检',now,rid))
                _request_new_ip_probe(db,old,ip,port,now,urgent=bool(r['urgent_probe_floors']))
                return
            stamp=metrics.get('connections_sampled');count=metrics.get('tcp')
            if not r['emergency']:
                try:count,stamp=_rotation_tcp_count(metrics,now)
                except IntegrationError as e:
                    db.execute('UPDATE vps_rotations SET status=?,updated=?,low_samples=0,force_drain_samples=NULL WHERE id=?',(str(e),now,rid));return

            if not r['emergency'] and r['drain_schedule_after'] is not None and stamp<=r['drain_schedule_after']:
                db.execute('UPDATE vps_rotations SET status=? WHERE id=?',('时段或排空配置已变化，等待两次新的 TCP 采样',rid));return
            if not r['emergency'] and stamp>(r['last_sample_at'] or 0):
                threshold=drain_effective['threshold']
                lows=r['low_samples']+1 if count<threshold else 0
                db.execute('UPDATE vps_rotations SET low_samples=?,last_sample_at=?,status=?,updated=? WHERE id=?',(lows,stamp,f'旧 VPS 当前 {count} 条 TCP 连接；阈值 < {threshold}（{drain_effective["label"]}），连续低值采样 {lows}/2',now,rid))
                r=dict(r);r['low_samples']=lows
            forced=not r['emergency'] and _force_drain_ready(db,r,count,stamp,now) and r['low_samples']<2
            if r['low_samples']<2 and not forced:return
            if forced:
                try:_fixed_ready(db,cipher,r,r['active_server_id'],now)
                except IntegrationError as e:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('超时强制换 IP 暂缓：'+str(e),now,rid));return
            if not forced:_drain_timing(db,r,now,'completed',count if not r['emergency'] else None)
            if _fixed(r):
                try:_fixed_action_safe(db,cipher,r,old,now)
                except IntegrationError as e:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('换 IP 暂缓：'+str(e),now,rid));return
            if _pending_action(db,old) or _pending_action(db,r['active_server_id']):
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('承载机或旧 VPS 仍有重启或换 IP 任务；等待其完成，避免重复下发',now,rid));return
            binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
            connection=load_connection(db,cipher,binding['connection_id'])
            validate_dns_record(get_dns_record(connection,binding),binding,connection)
            plan=_validated_plan(db,old,r['owner_id'])
            if not plan or (plan.get('rotation_action')!='reboot' and not plan['action_connection_id']):
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('旧机连接已降至阈值，但未配置换 IP API',now,rid));return
            try:rotation_groups.action_guard(db,r,old,now)
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            from server_failover import before_action
            reason=before_action(db,old,now,cipher)
            if reason:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(reason,now,rid));return
            if forced:
                _drain_timing(db,r,now,'forced',count)
                _event(db,rid,old,f'排空超过 1 小时：连续两次 TCP < {r["force_drain_threshold"]}（当前 {count}）；按配置强制换 IP，剩余连接可能中断',now)
            if plan.get('rotation_action')=='reboot':
                message=queue_reboot(db,old,now,cipher)
                if not message.startswith('已排队'):
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,now,rid));return
                command=db.execute("SELECT id FROM commands WHERE server_id=? AND action='reboot' AND status='queued' ORDER BY id DESC LIMIT 1",(old,)).fetchone()
                db.execute("UPDATE vps_rotations SET phase='waiting_ip',repair_check_required=0,repair_check=NULL,action_started=?,reboot_command_id=?,action_attempts=action_attempts+1,status=?,updated=? WHERE id=?",(now,command['id'] if command else None,message+'；等待重启后的新 IP，原 IP 不变将核对完成状态后继续重试',now,rid));return
            try:action=load_connection(db,cipher,plan['action_connection_id'])
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            server=db.execute('SELECT name FROM servers WHERE id=?',(old,)).fetchone()
            db.execute('UPDATE vps_rotations SET phase=\'waiting_ip\',repair_check_required=0,repair_check=NULL,action_started=?,action_attempts=action_attempts+1,status=?,updated=? WHERE id=?',(now,'连接数达标，已发起旧 VPS 换 IP；等待新 IP',now,rid))
            item={'id':rid,'server_id':old,'ip':ip,'name':server['name'] if server else str(old)}
        elif r['phase']=='waiting_ip':
            try:ip,port,_=_fresh_ip(db,old,now,cipher)
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if ip!=r['old_ip']:
                db.execute("UPDATE vps_rotations SET phase='waiting_probe',new_ip=?,action_started=CASE WHEN mode='fixed_primary' THEN ? ELSE action_started END,status=?,updated=? WHERE id=?",(ip,now,'新 IP 已上报，等待所选检测点复检',now,rid))
                _request_new_ip_probe(db,old,ip,port,now,urgent=bool(r['urgent_probe_floors']))
                return
            if r['action_started'] and now-r['action_started']<60:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('换 IP 请求已发出，观察 60 秒内的 IP 变化',now,rid));return
            try:_validated_plan(db,old,r['owner_id'])
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            plan=_validated_plan(db,old,r['owner_id'])
            if plan.get('rotation_action')=='reboot':
                # Never overlap an issued/accepted reboot. A completed attempt may
                # retry the same IP after recovery, with all ordinary drain gates.
                job=None
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='commands'").fetchone():
                    if r['reboot_command_id']:
                        job=db.execute("SELECT id,status FROM commands WHERE id=? AND server_id=? AND action='reboot'",(r['reboot_command_id'],old)).fetchone()
                    elif r['action_started'] is not None:
                        # Adopt legacy in-flight tasks after an additive upgrade.
                        job=db.execute("SELECT id,status FROM commands WHERE server_id=? AND action='reboot' AND created>=? ORDER BY id DESC LIMIT 1",(old,r['action_started'])).fetchone()
                if not job or job['status'] not in ('completed','failed','expired','cancelled'):
                    message='未核实上次重启任务，暂不重复重启' if not job else '等待上次重启任务 #'+str(job['id'])+' 结束（'+job['status']+'）；恢复上报后再核对 IP'
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,now,rid));return
                if _fixed(r) and old==r['primary_server_id'] and not _fixed_failure(db,old,now):
                    db.execute("UPDATE vps_rotations SET phase='waiting_probe',new_ip=?,action_started=?,reboot_command_id=NULL,status=?,updated=? WHERE id=?",(ip,now,'主 VPS 当前 IP 已恢复，等待所选检测点复检，不继续重启主机',now,rid));return
                if _pending_action(db,old) or _pending_action(db,r['active_server_id']):
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('仍有未结束的重启或换 IP 动作，等待完成后重试',now,rid));return
                message='上次重启已结束但 IP 仍为 '+ip+'；重新检查承载机和连接数后继续重启，直到获得新 IP'
                db.execute("UPDATE vps_rotations SET phase='draining',low_samples=?,last_sample_at=NULL,action_started=NULL,reboot_command_id=NULL,status=?,updated=? WHERE id=?",(2 if r['emergency'] else 0,message,now,rid))
                _event(db,rid,old,message,now)
                return
            if _fixed(r):
                try:_fixed_action_safe(db,cipher,r,old,now)
                except IntegrationError as e:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('换 IP 暂缓：'+str(e),now,rid));return
            if not r['emergency']:
                db.execute("UPDATE vps_rotations SET phase='draining',emergency=0,low_samples=0,last_sample_at=NULL,action_started=NULL,status=?,updated=? WHERE id=?",('未观察到 IP 变化；重新确认轮换机连接数后再重试',now,rid));return
            try:rotation_groups.action_guard(db,r,old,now)
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            from server_failover import before_action
            reason=before_action(db,old,now,cipher)
            if reason:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(reason,now,rid));return
            action=load_connection(db,cipher,plan['action_connection_id']) if plan and plan['action_connection_id'] else None
            server=db.execute('SELECT name FROM servers WHERE id=?',(old,)).fetchone()
            if not action:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('等待有效的旧 VPS 换 IP API',now,rid));return
            db.execute('UPDATE vps_rotations SET action_started=?,action_attempts=action_attempts+1,status=?,updated=? WHERE id=?',(now,'未观察到 IP 变化，重试换 IP API',now,rid))
            item={'id':rid,'server_id':old,'ip':ip,'name':server['name'] if server else str(old)}
        elif r['phase']=='waiting_probe':
            try:ip,port,_=_fresh_ip(db,old,now,cipher)
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if ip==r['old_ip'] and not (_fixed(r) and old==r['primary_server_id']):
                message='候选 IP 已回退到旧 IP，换 IP 未完成；重新排空并重试，暂不加入轮换'
                db.execute("UPDATE vps_rotations SET phase='draining',new_ip=NULL,action_started=NULL,last_sample_at=NULL,low_samples=?,status=?,updated=? WHERE id=?",(2 if r['emergency'] else 0,message,now,rid))
                _event(db,rid,old,message,now)
                return
            if ip!=r['new_ip']:
                db.execute('UPDATE vps_rotations SET new_ip=?,action_started=?,status=?,updated=? WHERE id=?',(ip,now,'备用 VPS IP 再次变化，等待新一轮 BOCE 复检',now,rid));return
            try:_preferred_rotation_ip(db,old,ip)
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            plan=db.execute('SELECT port FROM ip_monitors WHERE server_id=?',(old,)).fetchone()
            _request_probe(db,old,now)
            reason=boce_dns_gate(db,old,ip,port,require_plan=True,min_created=r['action_started'])
            if reason:
                if (_fixed_failure(db,old,now) if _fixed(r) else _failed_ip(db,old,now)):
                    db.execute("UPDATE vps_rotations SET phase='draining',old_ip=?,emergency=1,low_samples=2,drain_grace_s=0,action_started=NULL,status=?,updated=? WHERE id=?",(ip,'新 IP 国内探测仍不通，继续换 IP',now,rid))

                else:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('新 IP 尚未通过 BOCE 复检：'+reason,now,rid))
                return
            try:
                with socket.create_connection((ip,port),timeout=4):pass
            except OSError:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('BOCE 已通过，但新 IP 业务端口仍不可达',now,rid));return
            # Repair time must not extend the current carrier's scheduled tenure.
            # Keep overdue deadlines due; verified candidates may switch in this pass.
            next_at=r['next_switch_at']
            if _fixed(r) or r['fault_recovery']:next_at=now
            message=f'旧 VPS #{old} 已换到 {ip}，业务端口及 BOCE 复检通过；备用机已就绪'
            message+=('；定时已暂停，等待手动启用' if not r['enabled'] else '；承载异常，准备紧急接替' if r['emergency_probe_after'] is not None else '；承载已到期，准备切换解析' if next_at<=now else '；等待计划切换时间')
            db.execute("UPDATE vps_rotations SET phase='active',emergency=0,drain_server_id=NULL,drain_started=NULL,drain_grace_s=0,old_ip=NULL,new_ip=NULL,action_started=NULL,reboot_command_id=NULL,last_sample_at=NULL,low_samples=0,next_switch_at=?,status=?,updated=? WHERE id=?",(next_at,message,now,rid))
            db.execute('UPDATE vps_rotations SET fault_recovery=0 WHERE id=?',(rid,))
            if not _fixed(r):db.execute('UPDATE vps_rotations SET standby_ready_at=?,standby_ready_server=?,reused_ip=NULL,reused_server_id=NULL,drain_base_attempt=NULL WHERE id=?',(now,old,rid))
            _event(db,rid,old,message,now)
            if not _fixed(r) and r['enabled'] and (next_at<=now or r['emergency_probe_after'] is not None):
                ready=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rotation_recovery_timings'").fetchone():record_progress(db,r,ready,now)
                db.commit()
                _dns_switch(connect,cipher,rid,now,emergency=r['emergency_probe_after'] is not None,offline=_offline(db,r['active_server_id'],now,r['offline_after_s']))
                return
            if _fixed(r) and old==r['other_server_id'] and r['enabled'] and r['active_server_id']==r['primary_server_id']:
                db.commit()
                _dns_switch(connect,cipher,rid,now,emergency=_fixed_failure(db,r['primary_server_id'],now))
            return
        else:
            db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('轮换状态异常，请暂停后检查',now,rid));return
    try:
        if action['kind']!='change_ip':raise IntegrationError('配置的连接不是换 IP API')
        message=invoke_change_ip_api(action,item['server_id'],item['name'],item['ip'])
        status=str(message)+'；等待 agent 上报新 IP'
    except ChangeIPUncertain as e:
        status='换 IP 请求结果不确定：'+str(e)+'；先等待 IP 上报核对'
    except IntegrationError as e:
        # A definite provider rejection is retried on the next worker pass.
        detail=str(e).replace(action.get('secret',''),'[已隐藏]') if action.get('secret') else str(e)
        with connect() as db:db.execute("UPDATE vps_rotations SET phase='draining',action_started=NULL,status=?,updated=? WHERE id=?",('换 IP 请求失败，将立即重试：'+detail[:700],int(time.time()),rid))
        return
    except Exception:
        status='换 IP 请求结果不确定；等待 IP 上报核对后再重试'
    if action.get('secret'):status=status.replace(action['secret'],'[已隐藏]')
    status=status[:800]
    with connect() as db:
        db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(status,int(time.time()),rid))
        _event(db,rid,item['server_id'],status,int(time.time()))

def _sync_external_dns(connect,cipher,rid,now,force=False):
    """Every five minutes enforce the selected record's effective carrier."""
    with connect() as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dns_bindings'").fetchone():return False
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not r or not r['enabled'] or r['dns_intent']:return False
        group=rotation_groups.members(db,r)
        root=group[0]
        if any(not member['enabled'] or member['dns_intent'] for member in group):return False
        lease=db.execute('SELECT * FROM vps_failover_leases WHERE binding_id=?',(r['binding_id'],)).fetchone()
        if lease and lease['intent']:return False
        target=root['active_server_id']
        realign=not lease and r['active_server_id']!=target
        if realign and (r['phase']!='active' or r['action_started'] is not None):
            # Finish observing issued work before changing this member's state.
            return False
        if not force and not (realign and r['external_dns_pending']) and r['external_dns_check_at'] is not None and now-r['external_dns_check_at']<300:
            if r['external_dns_pending']:raise IntegrationError('DNS 自动纠正待重试，暂缓后续轮换动作')
            return False
        db.execute('UPDATE vps_rotations SET external_dns_check_at=? WHERE id=?',(now,rid));db.commit()
        binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
        if not binding:raise IntegrationError('轮换 DNS 绑定已删除')
        if lease:
            target_ip=public_v4(lease['current_ip'])
        else:
            try:target_ip,port,_=_fresh_ip(db,target,now,cipher)
            except IntegrationError:
                # Missing carrier heartbeat must reach the existing emergency
                # takeover flow; periodic maintenance cannot block recovery.
                return False
            if port!=binding['port']:raise IntegrationError('承载 VPS 业务端口与 DNS 绑定不一致')
            if realign:
                # An identified split is recovery work, not another routine
                # five-minute poll. Persist the probe request before readiness
                # raises; otherwise rollback loses it and the next poll can
                # repeatedly miss the 90-second freshness window.
                db.execute('UPDATE vps_rotations SET external_dns_pending=1 WHERE id=?',(rid,))
                _request_probe(db,target,now)
                db.commit()
                _fixed_ready(db,cipher,dict(r,phase='active'),target,now,verified_candidate=target_ip)
        conn=load_connection(db,cipher,binding['connection_id'])
        record=get_dns_record(conn,binding)
        actual=public_v4(record.get('content',record.get('Value')))
        validate_dns_record(record,dict(binding,expected_ip=actual),conn)
        if actual!=target_ip:
            db.execute('UPDATE vps_rotations SET external_dns_pending=1 WHERE id=?',(rid,));db.commit()
            update_dns_record(conn,binding,record,target_ip)
            latest=get_dns_record(conn,binding)
            validate_dns_record(latest,dict(binding,expected_ip=target_ip),conn)
            if latest.get('content',latest.get('Value'))!=target_ip:
                raise IntegrationError('DNS 自动纠正尚未回读确认，将在下轮核对时重试')
            message=f'定期核对已纠正 DNS：{actual} → {target_ip}；保持当前承载与轮换计时'
            db.execute('UPDATE dns_bindings SET expected_ip=?,status=?,updated=? WHERE id=?',(target_ip,message,now,binding['id']))
            _event(db,rid,r['active_server_id'],message,now)
        else:
            db.execute('UPDATE dns_bindings SET expected_ip=? WHERE id=?',(target_ip,binding['id']))
        if realign:
            ttl=record.get('ttl',record.get('TTL',300))
            try:ttl=int(ttl)
            except (TypeError,ValueError):ttl=300
            ttl=300 if ttl<=1 else ttl
            _finish_dns_switch(db,r,binding,rid,target,binding['expected_ip'],target_ip,ttl,now,now,
                               False,False,False,bool(record.get('proxied',False)))
            _event(db,rid,target,f'历史分叉线路已核对并跟随计划 #{root["id"]} 的统一承载目标；保留计划截止时间，重新等待本线路 TTL 与连接排空',now)
        elif not lease and binding['expected_ip']!=target_ip:
            rotation_timing.change(db,rid,target,target_ip,now,'carrier_ip_observed')
        if realign:
            db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(root['next_switch_at'],rid))
        db.execute('UPDATE vps_rotations SET external_dns_pending=0 WHERE id=?',(rid,))
        return actual!=target_ip or realign


def expedite_recovery_probes(connect,cipher):
    """Claim one fresh round per incident/IP; accelerate existing result polling."""
    now=int(time.time());rotations=[];servers=set()
    with connect() as db:
        rows=db.execute('SELECT * FROM vps_rotations WHERE enabled=1 OR fault_recovery=1 OR urgent_probe_floors IS NOT NULL').fetchall()
        for r in rows:
            urgent=(r['phase'] in ('waiting_ip','waiting_probe') and r['drain_server_id']
                    and r['drain_server_id']!=r['active_server_id']
                    and (r['enabled'] or r['fault_recovery']) and not r['dns_intent']
                    and not db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=?',(r['id'],)).fetchone())
            if urgent:
                active=r['active_server_id']
                urgent=_offline(db,active,now,r['offline_after_s']) or (_fixed_failure(db,active,now) if _fixed(r) else _failed_ip(db,active,now))
                if not urgent and r['urgent_probe_floors']:
                    # A pending independent confirmation is not recovery.
                    # Keep the already established incident expedited until a
                    # current healthy result actually clears it.
                    try:
                        address,port,_=_fresh_ip(db,active,now,cipher)
                        urgent=bool(boce_dns_gate(db,active,address,port,require_plan=True))
                    except IntegrationError:urgent=True
            if not urgent:
                if r['urgent_probe_floors']:db.execute('UPDATE vps_rotations SET urgent_probe_floors=NULL WHERE id=?',(r['id'],))
                continue
            try:floors=json.loads(r['urgent_probe_floors'] or '{}')
            except (TypeError,ValueError):floors={}
            for sid in (r['active_server_id'],r['drain_server_id']):
                plan=db.execute('SELECT p.*,m.port,m.enabled AS monitor_enabled,s.enabled AS source_enabled FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(sid,)).fetchone()
                if not plan or not plan['automatic'] or not plan['monitor_enabled'] or not plan['source_enabled']:continue
                key=str(sid)
                if key not in floors:
                    floors[key]=db.execute('SELECT COALESCE(MAX(id),0) FROM detection_runs WHERE server_id=?',(sid,)).fetchone()[0]
                try:address,_,_=_fresh_ip(db,sid,now,cipher)
                except IntegrationError:continue
                pending=db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND status IN ('creating','pending','queued','issued')",(sid,)).fetchone()
                confirm=db.execute("SELECT 1 FROM detection_rechecks c JOIN detection_runs p ON p.id=c.parent_id WHERE p.server_id=? AND c.state IN ('queued','creating','pending')",(sid,)).fetchone()
                fresh=db.execute('SELECT 1 FROM detection_runs WHERE server_id=? AND id>? AND ip=? AND port=? AND source_id=? AND nodes=? LIMIT 1',(sid,floors[key],address,plan['port'],plan['source_id'],plan['nodes'])).fetchone()
                if not pending and not confirm and not fresh:
                    db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,sid))
                if pending or confirm or not fresh:
                    db.execute("UPDATE detection_runs SET poll_at=MIN(poll_at,?) WHERE server_id=? AND status='pending'",(now,sid))
                    db.execute("UPDATE detection_rechecks SET poll_at=MIN(poll_at,?) WHERE parent_id IN (SELECT id FROM detection_runs WHERE server_id=?) AND state='pending'",(now,sid))
                    servers.add(sid)
            db.execute('UPDATE vps_rotations SET urgent_probe_floors=? WHERE id=?',(json.dumps(floors),r['id']))
            rotations.append(r['id'])
    return rotations,sorted(servers)


def tick(connect,cipher,rotation_ids=None):
    now=int(time.time())
    with connect() as db:db_path=db.execute('PRAGMA database_list').fetchone()[2]
    path=Path(db_path).with_suffix('.rotation.lock')
    with open(str(path),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with connect() as db:ids=[r[0] for r in db.execute('SELECT id FROM vps_rotations ORDER BY id')]
        if rotation_ids is not None:ids=[rid for rid in ids if rid in rotation_ids]
        for rid in ids:
            try:
                with connect() as db:
                    before=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
                    rotation_timing.ensure_observed(db,before,int(time.time()))
                _run_rotation(connect,cipher,rid,int(time.time()))
                with connect() as db:
                    after=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
                    record_progress(db,before,after,int(time.time()))
                    if before and after and before["phase"]!=after["phase"]:
                        _event(db,rid,after["drain_server_id"],after["status"],int(time.time()))
            except IntegrationError as e:
                with connect() as db:
                    message='轮换暂缓：'+str(e);row=db.execute('SELECT status FROM vps_rotations WHERE id=?',(rid,)).fetchone()
                    if row and row['status']!=message:
                        db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,int(time.time()),rid))
                        _event(db,rid,None,message,int(time.time()))
            except OSError as e:
                with connect() as db:
                    message='轮换执行失败：'+str(e)[:200];row=db.execute('SELECT status FROM vps_rotations WHERE id=?',(rid,)).fetchone()
                    if row and row['status']!=message:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,int(time.time()),rid))

def register(app,connect,cipher,auth,body,error,audit):
    _client_rotation(app,connect,cipher,auth,body,error,audit)
