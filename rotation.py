"""Safe two-VPS DNS rotation with connection draining and IP refresh."""
import fcntl
import json
import socket
import time
from pathlib import Path

from flask import g, jsonify
from rotation_insights import record_switch, record_progress
import failover

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
        for name,definition in [('mode',"TEXT NOT NULL DEFAULT 'alternating'"),('takeover_s','INTEGER NOT NULL DEFAULT 600'),('first_switch_at','INTEGER'),('mobile_only_ack','INTEGER NOT NULL DEFAULT 0'),('dns_intent','TEXT')]:
            if name not in columns:db.execute(f'ALTER TABLE vps_rotations ADD COLUMN {name} {definition}')
        failover.initialize(db)


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


def _admin_user(db,uid):
    row=db.execute('SELECT role FROM users WHERE id=?',(uid,)).fetchone()
    return bool(row and row['role']=='admin')

def _owned_server(db,sid,uid):
    if _admin_user(db,uid):return db.execute('SELECT id,name,metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
    return db.execute('SELECT id,name,metrics,seen FROM servers WHERE id=? AND owner_id=?',(sid,uid)).fetchone()

def _rotation_json(db,row):
    if not row:return None
    data=dict(row)
    names=db.execute('SELECT id,name FROM servers WHERE id IN (?,?)',(data['primary_server_id'],data['other_server_id'])).fetchall()
    data['primary_name']=next((x['name'] for x in names if x['id']==data['primary_server_id']),str(data['primary_server_id']))
    data['other_name']=next((x['name'] for x in names if x['id']==data['other_server_id']),str(data['other_server_id']))
    active=db.execute('SELECT name FROM servers WHERE id=?',(data['active_server_id'],)).fetchone()
    data['active_name']=active['name'] if active else str(data['active_server_id'])
    backup=db.execute('SELECT name FROM servers WHERE id=?',(data['failover_server_id'],)).fetchone()
    data['failover_name']=backup['name'] if backup else None
    data['failover_binding_ids']=json.loads(data['failover_binding_ids'])
    data['failover_leases']=[dict(x) for x in db.execute('SELECT binding_id,current_ip,target_ip,intent FROM vps_failover_leases WHERE rotation_id=?',(data['id'],))]
    mobile_lease=next((x for x in data['failover_leases'] if x['binding_id']==data['binding_id']),None)
    data['mobile_effective_server_id']=data['failover_server_id'] if mobile_lease and not mobile_lease['intent'] else data['active_server_id']
    if mobile_lease:data['active_name']='解析待核对' if mobile_lease['intent'] else (data['failover_name'] or str(data['failover_server_id']))+'（故障转移）'
    data['events']=[dict(e) for e in db.execute('SELECT server_id,message,created FROM vps_rotation_events WHERE rotation_id=? ORDER BY id DESC LIMIT 50',(data['id'],))]
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
    def save_rotation(sid):
        if g.user['role'] not in ('admin','client'):return error('无权管理轮换',403)
        d=body();other=d.get('other_server_id');binding_id=d.get('binding_id');interval=d.get('interval_s',7200);threshold=d.get('connection_threshold',80);enabled=d.get('enabled');offline_after=d.get('offline_after_s',15);lead=d.get('lead_s',min(120,interval//4) if type(interval)is int else 0)
        if d.get('mode')=='fixed_primary':lead=0
        if type(other)is not int or other==sid or type(binding_id)is not int or type(interval)is not int or not 60<=interval<=604800 or type(threshold)is not int or not 1<=threshold<=10000 or type(offline_after)is not int or not 10<=offline_after<=120 or type(lead)is not int or not 0<=lead<interval or type(enabled)is not bool:return error('请检查备用 VPS、DNS 记录、轮换间隔、连接数阈值和开关')
        now=int(time.time())
        try:
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                if not _owned_server(db,sid,g.user['id']) or not _owned_server(db,other,g.user['id']):return error('两台 VPS 必须都分配给当前客户',404)
                existing=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? OR other_server_id=? OR binding_id=?',(sid,sid,binding_id)).fetchall()
                if len(existing)>1:return error('VPS 或 DNS 记录已用于其他轮换任务',409)
                rotation=existing[0] if existing else None
                if rotation and g.user['role']!='admin' and rotation['owner_id']!=g.user['id']:return error('轮换计划不属于当前客户',403)
                effective_uid=rotation['owner_id'] if rotation else g.user['id']
                mode=d.get('mode',rotation['mode'] if rotation else 'alternating')
                takeover=d.get('takeover_s',rotation['takeover_s'] if rotation else 600)
                first=d.get('first_switch_at',rotation['first_switch_at'] if rotation else None)
                ack=d.get('mobile_only_ack',bool(rotation['mobile_only_ack']) if rotation else False)
                if mode not in ('alternating','fixed_primary') or type(takeover)is not int or not 60<=takeover<=604800 or (mode=='fixed_primary' and takeover>=interval) or (first is not None and (type(first)is not int or not 0<=first<=253402300799)) or type(ack)is not bool:
                    return error('请检查轮换模式、接替时长（必须短于周期）和首次切入时间')
                if mode=='fixed_primary' and not ack:return error('请确认所选记录仅服务移动线路，或为移动专用域名；不可选择所有运营商共用记录')
                if rotation and mode!=rotation['mode'] and (rotation['enabled'] or rotation['phase']!='active' or rotation['active_server_id']!=sid or rotation['dns_intent']):
                    return error('切换模式前请暂停任务，并确认流程已完成且解析已回到主 VPS',409)

                if rotation and (rotation['primary_server_id']!=sid or rotation['other_server_id']!=other or rotation['binding_id']!=binding_id):return error('已有轮换任务绑定了不同的 VPS 或 DNS 记录；请先暂停原任务',409)
                if rotation and rotation['phase']!='active' and (rotation['other_server_id']!=other or rotation['binding_id']!=binding_id):return error('正在排空旧 VPS 或等待换 IP 完成，暂不能更换轮换对象',409)
                failover_changed=rotation and any(k in d and d[k]!=(json.loads(rotation[k]) if k=='failover_binding_ids' else rotation[k]) for k in ('failover_server_id','failover_binding_ids','failover_recovery_s'))
                if rotation and failover_changed and db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=?',(rotation['id'],)).fetchone():raise IntegrationError('A 故障转移正在接替，解析切回前不能修改备用机或接替记录')
                if rotation and not enabled and (rotation['enabled'] or mode==rotation['mode']) and not failover_changed:
                    db.execute("UPDATE vps_rotations SET enabled=0,status='轮换已暂停',updated=? WHERE id=?",(now,rotation['id']))
                    audit(db,'暂停双 VPS 定时轮换 #'+str(rotation['id']))
                    return jsonify(ok=True,rotation=_rotation_json(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rotation['id'],)).fetchone()))
                conflicts=db.execute('SELECT id FROM vps_rotations WHERE enabled=1 AND (primary_server_id IN (?,?) OR other_server_id IN (?,?)) AND id<>?',(sid,other,sid,other,rotation['id'] if rotation else -1)).fetchone()
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
                if mode=='fixed_primary' and (not rotation or not rotation['enabled']) and (_pending_action(db,sid) or _pending_action(db,other)):return error('机器存在未完成的重启或换 IP 动作，完成核对后再启用固定主机模式',409)
                active_ip=(a['ip'] if not rotation or rotation['active_server_id']==sid else b['ip'])
                connection=load_connection(db,cipher,binding['connection_id'])
                record=get_dns_record(connection,dict(binding))
                validate_dns_record(record,dict(binding),connection)
                if record.get('content',record.get('Value'))!=active_ip or binding['expected_ip']!=active_ip:return error('DNS 当前解析必须指向轮换任务当前承载 VPS 的新鲜公网 IP')
                db.execute('UPDATE dns_bindings SET automatic=0 WHERE id=?',(binding_id,))
                if rotation:
                    db.execute('UPDATE vps_rotations SET interval_s=?,connection_threshold=?,enabled=?,status=?,next_switch_at=CASE WHEN ? THEN ? ELSE next_switch_at END,updated=? WHERE id=?',(interval,threshold,int(enabled),'轮换已开启' if enabled else '轮换已暂停',int(enabled),now+interval-lead,now,rotation['id']))
                    rid=rotation['id']
                else:
                    rid=db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,interval_s,connection_threshold,phase,next_switch_at,status,updated) VALUES(?,?,?,?,?,1,?,?,'active',?,'轮换已开启',?)",(g.user['id'],sid,other,binding_id,sid,interval,threshold,now+interval-lead,now)).lastrowid
                db.execute('UPDATE vps_rotations SET lead_s=?,offline_after_s=? WHERE id=?',(lead,offline_after,rid))
                db.execute('UPDATE vps_rotations SET mode=?,takeover_s=?,first_switch_at=?,mobile_only_ack=? WHERE id=?',(mode,takeover,first,int(ack),rid))
                if mode=='fixed_primary' and (not rotation or not rotation['enabled'] or rotation['mode']!=mode):
                    due=first if first and first>now else now+interval
                    if rotation and rotation['active_server_id']==other:due=now+takeover
                    db.execute('UPDATE vps_rotations SET next_switch_at=?,lead_s=0 WHERE id=?',(due,rid))
                elif mode=='fixed_primary':
                    db.execute('UPDATE vps_rotations SET next_switch_at=?,lead_s=0 WHERE id=?',(rotation['next_switch_at'],rid))

                if not enabled:db.execute("UPDATE vps_rotations SET enabled=0,status='轮换已暂停' WHERE id=?",(rid,))
                failover.configure(db,cipher,rid,d,now)
                audit(db,'配置双 VPS 定时轮换 #'+str(rid))
                return jsonify(ok=True,rotation=_rotation_json(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()))
        except IntegrationError as e:return error(str(e),409)

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
            binding=db.execute('SELECT b.*,c.owner_id AS credential_owner FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE b.id=? AND b.server_id=?',(bid,sid)).fetchone()
            try:
                if not binding or binding['credential_owner']!=(None if _admin_user(db,effective_uid) else effective_uid):raise IntegrationError('请选择主 VPS 自有 DNS 绑定')
                conn=load_connection(db,cipher,binding['connection_id']);record=get_dns_record(conn,binding);validate_dns_record(record,binding,conn)
                ttl=int(record.get('ttl',record.get('TTL',300)) or 300);ttl=300 if ttl<=1 else ttl;recommended=ttl+60
                checks.append({'name':'DNS 记录','ok':True,'message':'记录身份与当前值核对通过；启用后接管单机自动解析，本次未修改 DNS；建议提前至少 '+str(recommended)+' 秒'})
            except IntegrationError as e:checks.append({'name':'DNS 记录','ok':False,'message':str(e)})
        return jsonify(ok=all(x['ok'] for x in checks),checks=checks,recommended_lead_s=recommended)
    app.add_url_rule('/api/client/servers/<int:sid>/rotation/readiness','client_rotation_readiness',readiness,methods=['POST'])

    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_get_vps_rotation',get_rotation,methods=['GET'])
    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_save_vps_rotation',save_rotation,methods=['PUT'])

    @auth()
    def delete_rotation(sid):
        if g.user['role'] not in ('admin','client'):return error('无权管理轮换',403)
        with connect() as db:
            if not _owned_server(db,sid,g.user['id']):return error('服务器不存在',404)
            rotation=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? AND (? OR owner_id=?)',(sid,int(g.user['role']=='admin'),g.user['id'])).fetchone()
            if not rotation:return error('轮换计划不存在',404)
            if rotation['enabled'] or rotation['phase']!='active' or rotation['dns_intent'] or db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=?',(rotation['id'],)).fetchone():return error('请先暂停轮换；正在排空或换 IP 的流程完成后才能删除',409)
            failover.stop_probe(db,rotation['id'],remove=True)
            db.execute('DELETE FROM vps_rotations WHERE id=?',(rotation['id'],));audit(db,'删除双 VPS 轮换计划 #'+str(rotation['id']))
        return jsonify(ok=True)
    delete_rotation.__name__='client_delete_vps_rotation'
    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_delete_vps_rotation',delete_rotation,methods=['DELETE'])
    @app.get('/api/admin/rotations')
    @auth(admin=True)
    def admin_rotations():
        with connect() as db:
            return jsonify(rotations=[dict(_rotation_json(db,r),owner_role=db.execute('SELECT role FROM users WHERE id=?',(r['owner_id'],)).fetchone()['role']) for r in db.execute('SELECT * FROM vps_rotations ORDER BY id DESC')],servers=[dict(x) for x in db.execute('SELECT id,name FROM servers')],bindings=[dict(x) for x in db.execute('SELECT b.id,b.server_id,b.domain,b.rr,b.line,b.expected_ip,c.owner_id AS credential_owner FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id')],dns_connections=[dict(x) for x in db.execute("SELECT id,name,kind,json_extract(config,'$.zone_name') AS zone_name FROM ip_connections WHERE owner_id IS NULL AND kind IN ('alidns','cloudflare')")])
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
    plan=db.execute('SELECT p.source_id,p.nodes,p.interval_s,m.port FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(sid,)).fetchone()
    node=db.execute('SELECT metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
    if not plan or not node or not node['seen'] or now-node['seen']>45:return False
    try:address=candidate_ip(db,{'server_id':sid,'source_id':None},None)
    except IntegrationError:return False
    run=db.execute("SELECT * FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
    if not run or run['source_id']!=plan['source_id'] or run['nodes']!=plan['nodes'] or run['ip']!=address or run['port']!=plan['port'] or now-run['updated']>max(120,plan['interval_s']*2):return False
    try:
        rows=json.loads(run['details']);nodes=json.loads(plan['nodes'])
        return bool(nodes) and len(rows)==len(nodes) and {str(x.get('node_id')) for x in rows}==set(map(str,nodes)) and all(x.get('state')=='unreachable' for x in rows)
    except (TypeError,ValueError,AttributeError):return False

def _pending_action(db,sid,verified_candidate=None):
    """A queued/issued action may execute after an apparently healthy probe."""
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='commands'").fetchone():
        if db.execute("SELECT 1 FROM commands WHERE server_id=? AND action='reboot' AND status IN ('queued','issued','accepted','unconfirmed') LIMIT 1",(sid,)).fetchone():return True
    if verified_candidate is not None:
        return bool(db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND action_status IN ('queued','issued','submitted','uncertain','verifying') AND (action_status<>'verifying' OR action_candidate IS NULL OR action_candidate<>?) LIMIT 1",(sid,verified_candidate)).fetchone())
    return bool(db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND action_status IN ('queued','issued','submitted','uncertain','verifying') LIMIT 1",(sid,)).fetchone())


def _fixed_failure(db,sid,now):
    """Only the configured nodes/IP/port count, using the configured failure threshold."""
    if not _failed_ip(db,sid,now):return False
    plan=db.execute('SELECT p.source_id,p.nodes,p.failure_threshold,p.interval_s,p.automatic,m.port,m.enabled AS monitor_enabled,s.enabled AS source_enabled FROM detection_plans p JOIN ip_monitors m ON m.server_id=p.server_id JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(sid,)).fetchone()
    if not plan or not plan['automatic'] or not plan['monitor_enabled'] or not plan['source_enabled']:return False
    threshold=max(1,plan['failure_threshold'])
    runs=db.execute('SELECT * FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT ?',(sid,threshold)).fetchall()
    if len(runs)!=threshold:return False
    nodes=set(map(str,json.loads(plan['nodes'])))
    if not nodes:return False
    address=runs[0]['ip']
    for run in runs:
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


def _fixed_ready(db,cipher,r,sid,now,verified_candidate=None):
    if r['phase'] in ('waiting_ip','waiting_probe') and r['drain_server_id']==sid:raise IntegrationError('目标 VPS 的换 IP / 复检尚未结束，不能接替')
    if _pending_action(db,sid,verified_candidate):raise IntegrationError('目标 VPS 有未结束的重启或换 IP 动作，不能接替')
    ip,port,metrics=_fresh_ip(db,sid,now,cipher)
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
    if old==r['active_server_id']:raise IntegrationError('此 VPS 当前仍承载移动解析，禁止换 IP')
    active=r['active_server_id']
    _request_probe(db,active,now)
    if _pending_action(db,active):raise IntegrationError('承载 VPS 有未完成动作，禁止同时更换两台 IP')
    both_failed=_fixed_failure(db,active,now) and _fixed_failure(db,old,now)
    if not both_failed:_fixed_ready(db,cipher,r,active,now)
    if _pending_action(db,old):raise IntegrationError('此 VPS 已有未完成动作，禁止重复换 IP')


def _begin_fixed_repair(db,cipher,r,sid,now,message):
    ip,_,_=_fresh_ip(db,sid,now,cipher)
    emergency=int(sid==r['primary_server_id'])
    db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,drain_started=?,drain_grace_s=0,old_ip=?,new_ip=NULL,action_started=NULL,last_sample_at=NULL,low_samples=?,emergency=?,status=?,updated=? WHERE id=?",(sid,now,ip,2 if emergency else 0,emergency,message,now,r['id']))
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
        emergency=int(target==r['other_server_id'] and not normal_takeover)
        phase='active' if normal_takeover else 'draining'
        delay=r['takeover_s'] if target==r['other_server_id'] else r['interval_s']-r['takeover_s']
        message='已回读确认此前 DNS 切换结果，恢复固定主机协调流程'
        record_switch(db,rid,binding,intent['from'],intent['to'],intent['submitted'],now,ttl,bool(record.get('proxied',False)))
        db.execute('UPDATE dns_bindings SET expected_ip=?,status=?,updated=? WHERE id=?',(intent['to'],message,now,binding['id']))
        db.execute('UPDATE vps_rotations SET active_server_id=?,phase=?,drain_server_id=?,drain_started=?,drain_grace_s=?,old_ip=?,new_ip=NULL,action_started=NULL,last_sample_at=NULL,low_samples=?,emergency=?,next_switch_at=?,dns_intent=NULL,status=?,updated=? WHERE id=?',(target,phase,None if normal_takeover else old,None if normal_takeover else now,0 if emergency or normal_takeover else ttl+60,None if normal_takeover else intent['from'],2 if emergency else 0,emergency,now+delay,message,now,rid))
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
            message='所选检测点确认主 VPS 不通，移动保持轮换机，协调主 VPS 自动换 IP' if target==a else '轮换 VPS 所选检测点不通，保持当前解析，等待连接阈值后修复'
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

def _dns_switch(connect,cipher,rotation,now,emergency=False,offline=False):
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rotation,)).fetchone()
        if not r or not r['enabled']:return
        if not emergency and (r['phase']!='active' or r['next_switch_at']>now):return
        if emergency and r['phase'] in ('waiting_ip','waiting_probe'):raise IntegrationError('备用机正在换 IP 或复检，暂不能安全切回')
        binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
        if not binding:raise IntegrationError('轮换 DNS 绑定已删除')
        conn=load_connection(db,cipher,binding['connection_id'])
        target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
        _validated_plan(db,target,r['owner_id'])
        if _fixed(r):_fixed_ready(db,cipher,r,target,now)
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
        grace=0 if emergency and not offline else ttl+60
        submitted=int(time.time())
        if _fixed(r):
            if r['dns_intent']:raise IntegrationError('上一次 DNS 写入结果未确认，暂停新切换')
            intent={'from':old_ip,'to':target_ip,'target':target,'submitted':submitted,'ttl':ttl}
            db.execute('UPDATE vps_rotations SET dns_intent=? WHERE id=?',(json.dumps(intent),rotation))
            db.commit() # Durable intent survives provider timeouts and worker exits.
        update_dns_record(conn,binding,record,target_ip)
        updated=get_dns_record(conn,binding)
        expected=dict(binding,expected_ip=target_ip)
        validate_dns_record(updated,expected,conn)
        if _fixed(r):db.execute('UPDATE vps_rotations SET dns_intent=NULL WHERE id=?',(rotation,))
        record_switch(db,rotation,binding,old_ip,target_ip,submitted,int(time.time()),ttl,bool(record.get('proxied',False)))
        message=f"DNS 已从 {old_ip} 切换到 {target_ip}；等待旧 VPS #{r['active_server_id']} 连接降到阈值以下"
        if offline:message=f'承载 VPS 离线，DNS 已从 {old_ip} 切到 {target_ip}；旧机等待恢复，未执行换 IP'
        db.execute('UPDATE dns_bindings SET expected_ip=?,status=?,updated=? WHERE id=?',(target_ip,message,now,binding['id']))
        if _fixed(r) and target==r['other_server_id'] and not _fixed_failure(db,r['primary_server_id'],now):
            # Scheduled takeover never drains or refreshes the fixed primary.
            message=f'移动解析已切入轮换 VPS #{target}；主 VPS 保持原 IP；到时切回主 VPS'
            db.execute("UPDATE vps_rotations SET active_server_id=?,phase='active',drain_server_id=NULL,emergency=0,status=?,next_switch_at=?,updated=? WHERE id=?",(target,message,now+r['takeover_s'],now,rotation))
            db.execute('UPDATE dns_bindings SET status=? WHERE id=?',(message,binding['id']))
            _event(db,rotation,target,message,now)
            return
        db.execute("UPDATE vps_rotations SET active_server_id=?,phase='draining',drain_server_id=?,drain_started=?,drain_grace_s=?,old_ip=?,new_ip=NULL,action_started=NULL,last_sample_at=NULL,low_samples=0,status=?,next_switch_at=?,updated=? WHERE id=?",(target,r['active_server_id'],now,grace,old_ip,message,now+r['interval_s']-r['lead_s'],now,rotation))
        db.execute('UPDATE vps_rotations SET emergency=?,low_samples=? WHERE id=?',(int(emergency and not offline),2 if emergency and not offline else 0,rotation))
        if _fixed(r):
            delay=r['takeover_s'] if target==r['other_server_id'] else r['interval_s']-r['takeover_s']
            db.execute('UPDATE vps_rotations SET next_switch_at=? WHERE id=?',(now+delay,rotation))
            if r['active_server_id']==r['other_server_id']:
                db.execute('UPDATE vps_rotations SET emergency=0,low_samples=0,drain_grace_s=? WHERE id=?',(ttl+60,rotation))
        _event(db,rotation,r['active_server_id'],message,now)

def db_failover_active(connect,rid):
    with connect() as db:return bool(db.execute('SELECT 1 FROM vps_failover_leases WHERE rotation_id=?',(rid,)).fetchone())


def _run_rotation(connect,cipher,rid,now):
    with connect() as db:
        current=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
    if current and (current['enabled'] or current['failover_server_id'] or db_failover_active(connect,rid)):
        if failover.step(connect,cipher,rid,now):return
    if current and current['enabled'] and _fixed(current):
        if _coordinate_fixed(connect,cipher,rid,now):return
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not r or not r['enabled']:return
        if not _fixed(r) and r['phase'] in ('active','draining') and _offline(db,r['active_server_id'],now,r['offline_after_s']):
            target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
            if _offline(db,target,now,r['offline_after_s']):raise IntegrationError('当前机和备用机均离线，没有可用备用机；保持 DNS 并等待恢复')
            last=db.execute('SELECT MAX(created) FROM detection_runs WHERE server_id=?',(target,)).fetchone()[0]
            if last is None or now-last>=60:
                db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,target));db.commit()
            _dns_switch(connect,cipher,rid,now,emergency=True,offline=True)
            r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not _fixed(r) and r['phase'] in ('active','draining') and _failed_ip(db,r['active_server_id'],now):
            target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
            if not _failed_ip(db,target,now):
                last=db.execute('SELECT MAX(created) FROM detection_runs WHERE server_id=?',(target,)).fetchone()[0]
                if last is None or now-last>=60:
                    db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=?',(now,target))
                    db.commit()
                _dns_switch(connect,cipher,rid,now,emergency=True)
                r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if r['phase']=='active':
            if _fixed(r):return
            standby=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
            if _failed_ip(db,standby,now):
                address,_,_=_fresh_ip(db,standby,now,cipher)
                db.execute("UPDATE vps_rotations SET phase='draining',drain_server_id=?,old_ip=?,drain_started=?,drain_grace_s=0,emergency=1,low_samples=2,status=? WHERE id=?",(standby,address,now,'备用 IP 不通，保持当前 DNS 并主动修复备用机',rid))
                if _fixed(r) and standby==r['other_server_id']:db.execute('UPDATE vps_rotations SET emergency=0,low_samples=0,last_sample_at=NULL WHERE id=?',(rid,))
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
            if _fixed(r) and old==r['primary_server_id'] and not _fixed_failure(db,old,now):
                if _offline(db,old,now,r['offline_after_s']):
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('主 VPS 离线，等待恢复；未确认被墙，不更换主机 IP',now,rid));return
                address,port,_=_fresh_ip(db,old,now,cipher)
                reason=boce_dns_gate(db,old,address,port,require_plan=True)
                if reason:raise IntegrationError('等待主 VPS 恢复确认：'+reason)
                db.execute("UPDATE vps_rotations SET phase='active',drain_server_id=NULL,emergency=0,next_switch_at=?,status=?,updated=? WHERE id=?",(now,'主 VPS 已恢复且保持原 IP，准备切回移动解析',now,rid));return
            if not _fixed(r) and not r['emergency'] and _failed_ip(db,old,now):
                db.execute('UPDATE vps_rotations SET emergency=1,low_samples=2,drain_grace_s=0 WHERE id=?',(rid,))
                r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
            try:_validated_plan(db,old,r['owner_id'])
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if now-(r['drain_started'] or now)<r['drain_grace_s']:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('等待 DNS TTL 到期后检查旧机连接',now,rid));return
            try:ip,port,metrics=_fresh_ip(db,old,now,cipher)
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if ip!=r['old_ip']:
                db.execute("UPDATE vps_rotations SET phase='waiting_probe',new_ip=?,action_started=COALESCE(action_started,?),status=?,updated=? WHERE id=?",(ip,now,'旧 VPS IP 已变化，等待 BOCE 复检',now,rid));return
            stamp=metrics.get('connections_sampled');count=metrics.get('tcp')
            if _fixed(r) and old==r['other_server_id']:
                try:count,stamp=_rotation_tcp_count(metrics,now)
                except IntegrationError as e:
                    db.execute('UPDATE vps_rotations SET status=?,updated=?,low_samples=0 WHERE id=?',(str(e),now,rid));return

            if not r['emergency'] and (type(count)is not int or type(stamp)is not int or not 0<=now-stamp<=45):
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('等待旧 VPS 新鲜 TCP 连接数',now,rid));return
            if not r['emergency'] and stamp>(r['last_sample_at'] or 0):
                lows=r['low_samples']+1 if count<r['connection_threshold'] else 0
                db.execute('UPDATE vps_rotations SET low_samples=?,last_sample_at=?,status=?,updated=? WHERE id=?',(lows,stamp,f'旧 VPS 当前 {count} 条 TCP 连接；阈值 < {r["connection_threshold"]}，连续低值采样 {lows}/2',now,rid))
                r=dict(r);r['low_samples']=lows
            if r['low_samples']<2:return
            if _fixed(r):
                try:_fixed_action_safe(db,cipher,r,old,now)
                except IntegrationError as e:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('换 IP 暂缓：'+str(e),now,rid));return
            pending=db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND action_status IN ('queued','issued','submitted','uncertain','verifying') LIMIT 1",(old,)).fetchone()
            if pending:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('连接数已达标，但旧 VPS 另有换 IP 任务处理中；等待其完成',now,rid));return
            plan=_validated_plan(db,old,r['owner_id'])
            if not plan or (plan.get('rotation_action')!='reboot' and not plan['action_connection_id']):
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('旧机连接已降至阈值，但未配置换 IP API',now,rid));return
            if plan.get('rotation_action')=='reboot':
                message=queue_reboot(db,old,now)
                if not message.startswith('已排队'):
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(message,now,rid));return
                db.execute("UPDATE vps_rotations SET phase='waiting_ip',action_started=?,action_attempts=action_attempts+1,status=?,updated=? WHERE id=?",(now,message+'；等待重启后的新 IP',now,rid));return
            try:action=load_connection(db,cipher,plan['action_connection_id'])
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            server=db.execute('SELECT name FROM servers WHERE id=?',(old,)).fetchone()
            db.execute('UPDATE vps_rotations SET phase=\'waiting_ip\',action_started=?,action_attempts=action_attempts+1,status=?,updated=? WHERE id=?',(now,'连接数达标，已发起旧 VPS 换 IP；等待新 IP',now,rid))
            item={'id':rid,'server_id':old,'ip':ip,'name':server['name'] if server else str(old)}
        elif r['phase']=='waiting_ip':
            try:ip,port,_=_fresh_ip(db,old,now,cipher)
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if ip!=r['old_ip']:
                db.execute("UPDATE vps_rotations SET phase='waiting_probe',new_ip=?,action_started=CASE WHEN mode='fixed_primary' THEN ? ELSE action_started END,status=?,updated=? WHERE id=?",(ip,now,'新 IP 已上报，等待所选检测点复检',now,rid));return
            if r['action_started'] and now-r['action_started']<60:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('换 IP 请求已发出，观察 60 秒内的 IP 变化',now,rid));return
            try:_validated_plan(db,old,r['owner_id'])
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            plan=_validated_plan(db,old,r['owner_id'])
            if plan.get('rotation_action')=='reboot':
                # Never repeatedly reboot a machine that has not obtained a new IP.
                # Keep the healthy active VPS serving while the operator investigates.
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('重启后尚未观察到新 IP；保留当前解析，等待上报或人工检查，不重复重启' + ('；动作已超过 180 秒，请检查供应商和 agent' if _fixed(r) and r['action_started'] and now-r['action_started']>=180 else ''),now,rid));return
            if _fixed(r):
                try:_fixed_action_safe(db,cipher,r,old,now)
                except IntegrationError as e:
                    db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('换 IP 暂缓：'+str(e),now,rid));return
            if _fixed(r) and old==r['other_server_id']:
                db.execute("UPDATE vps_rotations SET phase='draining',emergency=0,low_samples=0,last_sample_at=NULL,action_started=NULL,status=?,updated=? WHERE id=?",('未观察到 IP 变化；重新确认轮换机连接数后再重试',now,rid));return
            action=load_connection(db,cipher,plan['action_connection_id']) if plan and plan['action_connection_id'] else None
            server=db.execute('SELECT name FROM servers WHERE id=?',(old,)).fetchone()
            if not action:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('等待有效的旧 VPS 换 IP API',now,rid));return
            db.execute('UPDATE vps_rotations SET action_started=?,action_attempts=action_attempts+1,status=?,updated=? WHERE id=?',(now,'未观察到 IP 变化，重试换 IP API',now,rid))
            item={'id':rid,'server_id':old,'ip':ip,'name':server['name'] if server else str(old)}
        elif r['phase']=='waiting_probe':
            try:ip,port,_=_fresh_ip(db,old,now,cipher)
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if ip!=r['new_ip']:
                db.execute('UPDATE vps_rotations SET new_ip=?,action_started=?,status=?,updated=? WHERE id=?',(ip,now,'备用 VPS IP 再次变化，等待新一轮 BOCE 复检',now,rid));return
            plan=db.execute('SELECT port FROM ip_monitors WHERE server_id=?',(old,)).fetchone()
            if _fixed(r):_request_probe(db,old,now)
            reason=boce_dns_gate(db,old,ip,port,require_plan=True,min_created=r['action_started'])
            if reason:
                if (_fixed_failure(db,old,now) if _fixed(r) else _failed_ip(db,old,now)):
                    db.execute("UPDATE vps_rotations SET phase='draining',old_ip=?,emergency=1,low_samples=2,drain_grace_s=0,action_started=NULL,status=?,updated=? WHERE id=?",(ip,'新 IP 国内探测仍不通，继续换 IP',now,rid))
                    if _fixed(r) and old==r['other_server_id']:db.execute('UPDATE vps_rotations SET emergency=0,low_samples=0,last_sample_at=NULL WHERE id=?',(rid,))
                else:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('新 IP 尚未通过 BOCE 复检：'+reason,now,rid))
                return
            try:
                with socket.create_connection((ip,port),timeout=4):pass
            except OSError:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('BOCE 已通过，但新 IP 业务端口仍不可达',now,rid));return
            next_at=r['next_switch_at'] if r['next_switch_at']>now else now+max(60,r['interval_s']-r['lead_s'])
            if _fixed(r) and old==r['primary_server_id']:next_at=min(r['next_switch_at'],now)
            message=f'旧 VPS #{old} 已换到 {ip}，业务端口及 BOCE 复检通过；已重新加入轮换'
            db.execute("UPDATE vps_rotations SET phase='active',emergency=0,drain_server_id=NULL,drain_started=NULL,drain_grace_s=0,old_ip=NULL,new_ip=NULL,action_started=NULL,last_sample_at=NULL,low_samples=0,next_switch_at=?,status=?,updated=? WHERE id=?",(next_at,message,now,rid))
            _event(db,rid,old,message,now);return
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

def tick(connect,cipher):
    now=int(time.time())
    with connect() as db:db_path=db.execute('PRAGMA database_list').fetchone()[2]
    path=Path(db_path).with_suffix('.rotation.lock')
    with open(str(path),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with connect() as db:ids=[r[0] for r in db.execute('SELECT id FROM vps_rotations WHERE enabled=1 OR failover_server_id IS NOT NULL OR EXISTS(SELECT 1 FROM vps_failover_leases l WHERE l.rotation_id=vps_rotations.id) ORDER BY id')]
        for rid in ids:
            try:
                with connect() as db:before=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
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
