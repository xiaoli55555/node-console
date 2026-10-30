"""Safe two-VPS DNS rotation with connection draining and IP refresh."""
import fcntl
import json
import socket
import time
from pathlib import Path

from flask import g, jsonify

from detectors import boce_dns_gate
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
    with connect() as db:db.executescript(SCHEMA)

def _owned_server(db,sid,uid):
    return db.execute('SELECT id,name,metrics,seen FROM servers WHERE id=? AND owner_id=?',(sid,uid)).fetchone()

def _rotation_json(db,row):
    if not row:return None
    data=dict(row)
    names=db.execute('SELECT id,name FROM servers WHERE id IN (?,?)',(data['primary_server_id'],data['other_server_id'])).fetchall()
    data['primary_name']=next((x['name'] for x in names if x['id']==data['primary_server_id']),str(data['primary_server_id']))
    data['other_name']=next((x['name'] for x in names if x['id']==data['other_server_id']),str(data['other_server_id']))
    active=db.execute('SELECT name FROM servers WHERE id=?',(data['active_server_id'],)).fetchone()
    data['active_name']=active['name'] if active else str(data['active_server_id'])
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
    if not plan or plan['owner_id']!=uid or plan['source_owner']!=uid or plan['source_server']!=sid or not plan['source_enabled'] or not plan['automatic'] or not plan['monitor_enabled']:
        raise IntegrationError('两台 VPS 都要配置并开启各自的 BOCE 定时探测和 IP 监控')
    if plan['response_mode']!='change_api' or not plan['action_connection_id']:
        raise IntegrationError('两台 VPS 都要分别保存自己的换 IP API，并选择“调用换 IP API”')
    action=db.execute('SELECT id,kind,owner_id,server_id FROM ip_connections WHERE id=?',(plan['action_connection_id'],)).fetchone()
    if not action or action['kind']!='change_ip' or action['owner_id']!=uid or action['server_id']!=sid:
        raise IntegrationError('换 IP API 必须是当前客户为对应 VPS 保存的专属连接')
    return plan

def _client_rotation(app,connect,cipher,auth,body,error,audit):
    @auth()
    def get_rotation(sid):
        if g.user['role']!='client':return error('此功能仅供客户账号使用',403)
        with connect() as db:
            if not _owned_server(db,sid,g.user['id']):return error('服务器不存在',404)
            rotation=db.execute('SELECT * FROM vps_rotations WHERE owner_id=? AND (primary_server_id=? OR other_server_id=?) ORDER BY id LIMIT 1',(g.user['id'],sid,sid)).fetchone()
            return jsonify(rotation=_rotation_json(db,rotation))
    get_rotation.__name__='client_get_vps_rotation'

    @auth()
    def save_rotation(sid):
        if g.user['role']!='client':return error('此功能仅供客户账号使用',403)
        d=body();other=d.get('other_server_id');binding_id=d.get('binding_id');interval=d.get('interval_s',7200);threshold=d.get('connection_threshold',80);enabled=d.get('enabled')
        if type(other)is not int or other==sid or type(binding_id)is not int or type(interval)is not int or not 600<=interval<=86400 or type(threshold)is not int or not 1<=threshold<=10000 or type(enabled)is not bool:return error('请检查备用 VPS、DNS 记录、轮换间隔、连接数阈值和开关')
        now=int(time.time())
        try:
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                if not _owned_server(db,sid,g.user['id']) or not _owned_server(db,other,g.user['id']):return error('两台 VPS 必须都分配给当前客户',404)
                existing=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? OR other_server_id=? OR binding_id=?',(sid,sid,binding_id)).fetchall()
                if len(existing)>1:return error('VPS 或 DNS 记录已用于其他轮换任务',409)
                rotation=existing[0] if existing else None
                if rotation and (rotation['primary_server_id']!=sid or rotation['other_server_id']!=other or rotation['binding_id']!=binding_id):return error('已有轮换任务绑定了不同的 VPS 或 DNS 记录；请先暂停原任务',409)
                if rotation and rotation['phase']!='active' and (rotation['other_server_id']!=other or rotation['binding_id']!=binding_id):return error('正在排空旧 VPS 或等待换 IP 完成，暂不能更换轮换对象',409)
                if rotation and not enabled:
                    db.execute("UPDATE vps_rotations SET enabled=0,status='轮换已暂停',updated=? WHERE id=?",(now,rotation['id']))
                    audit(db,'暂停双 VPS 定时轮换 #'+str(rotation['id']))
                    return jsonify(ok=True,rotation=_rotation_json(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rotation['id'],)).fetchone()))
                conflicts=db.execute('SELECT id FROM vps_rotations WHERE enabled=1 AND (primary_server_id IN (?,?) OR other_server_id IN (?,?)) AND id<>?',(sid,other,sid,other,rotation['id'] if rotation else -1)).fetchone()
                if enabled and conflicts:return error('其中一台 VPS 已参加其他启用中的轮换任务',409)
                binding=db.execute('SELECT b.*,c.kind,c.owner_id AS connection_owner,c.server_id AS connection_server FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE b.id=?',(binding_id,)).fetchone()
                if not binding or binding['server_id']!=sid or binding['connection_owner']!=g.user['id'] or binding['connection_server']!=sid:return error('请为当前 VPS 选择一条自己的 DNS 记录',404)
                if binding['automatic']:return error('请先暂停这条 DNS 记录原有的自动解析，再交由双 VPS 轮换管理',409)
                _validated_plan(db,sid,g.user['id']);_validated_plan(db,other,g.user['id'])
                if _validated_plan(db,sid,g.user['id'])['monitor_port']!=binding['port']:return error('DNS 记录端口和主 VPS 监控端口不一致，请重新保存检测端口',409)
                a=_server_snapshot(db,sid,now,cipher);b=_server_snapshot(db,other,now,cipher)
                if a['port']!=b['port'] or a['port']!=binding['port']:return error('两台 VPS 的业务 TCP 检测端口必须相同')
                if a['ip']==b['ip']:return error('两台 VPS 当前公网 IP 相同，不能进行轮换')
                active_ip=(a['ip'] if not rotation or rotation['active_server_id']==sid else b['ip'])
                connection=load_connection(db,cipher,binding['connection_id'])
                record=get_dns_record(connection,dict(binding))
                validate_dns_record(record,dict(binding),connection)
                if record.get('content',record.get('Value'))!=active_ip or binding['expected_ip']!=active_ip:return error('DNS 当前解析必须指向轮换任务当前承载 VPS 的新鲜公网 IP')
                if rotation:
                    db.execute('UPDATE vps_rotations SET interval_s=?,connection_threshold=?,enabled=?,status=?,next_switch_at=CASE WHEN ? THEN MAX(next_switch_at,?) ELSE next_switch_at END,updated=? WHERE id=?',(interval,threshold,int(enabled),'轮换已开启' if enabled else '轮换已暂停',int(enabled),now+interval,now,rotation['id']))
                    rid=rotation['id']
                else:
                    rid=db.execute("INSERT INTO vps_rotations(owner_id,primary_server_id,other_server_id,binding_id,active_server_id,enabled,interval_s,connection_threshold,phase,next_switch_at,status,updated) VALUES(?,?,?,?,?,1,?,?,'active',?,'轮换已开启',?)",(g.user['id'],sid,other,binding_id,sid,interval,threshold,now+interval,now)).lastrowid
                audit(db,'配置双 VPS 定时轮换 #'+str(rid))
                return jsonify(ok=True,rotation=_rotation_json(db,db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()))
        except IntegrationError as e:return error(str(e),409)

    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_get_vps_rotation',get_rotation,methods=['GET'])
    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_save_vps_rotation',save_rotation,methods=['PUT'])

    @auth()
    def delete_rotation(sid):
        if g.user['role']!='client':return error('此功能仅供客户账号使用',403)
        with connect() as db:
            if not _owned_server(db,sid,g.user['id']):return error('服务器不存在',404)
            rotation=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? AND owner_id=?',(sid,g.user['id'])).fetchone()
            if not rotation:return error('轮换计划不存在',404)
            if rotation['enabled'] or rotation['phase']!='active':return error('请先暂停轮换；正在排空或换 IP 的流程完成后才能删除',409)
            db.execute('DELETE FROM vps_rotations WHERE id=?',(rotation['id'],));audit(db,'删除双 VPS 轮换计划 #'+str(rotation['id']))
        return jsonify(ok=True)
    delete_rotation.__name__='client_delete_vps_rotation'
    app.add_url_rule('/api/client/servers/<int:sid>/rotation','client_delete_vps_rotation',delete_rotation,methods=['DELETE'])

def _event(db,rid,sid,message,now):
    db.execute('INSERT INTO vps_rotation_events(rotation_id,server_id,message,created) VALUES(?,?,?,?)',(rid,sid,message,now))
    db.execute('DELETE FROM vps_rotation_events WHERE id NOT IN (SELECT id FROM vps_rotation_events ORDER BY id DESC LIMIT 500)')

def _fresh_ip(db,sid,now,cipher):
    server=db.execute('SELECT metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
    monitor=db.execute('SELECT source_id,port,enabled FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
    if not server or not monitor or not monitor['enabled'] or not server['seen'] or not 0<=now-server['seen']<=45:raise IntegrationError('等待 VPS agent 新鲜上报')
    address=candidate_ip(db,{'server_id':sid,'source_id':monitor['source_id']},cipher)
    return public_v4(address),monitor['port'],json.loads(server['metrics'] or '{}')

def _dns_switch(connect,cipher,rotation,now):
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rotation,)).fetchone()
        if not r or not r['enabled'] or r['phase']!='active' or r['next_switch_at']>now:return
        binding=db.execute('SELECT * FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
        if not binding:raise IntegrationError('轮换 DNS 绑定已删除')
        conn=load_connection(db,cipher,binding['connection_id'])
        target=r['other_server_id'] if r['active_server_id']==r['primary_server_id'] else r['primary_server_id']
        _validated_plan(db,target,r['owner_id'])
        old_ip,port,_=_fresh_ip(db,r['active_server_id'],now,cipher)
        target_ip,target_port,_=_fresh_ip(db,target,now,cipher)
        if target_port!=port or target_ip==old_ip:raise IntegrationError('备用 VPS 端口或公网 IP 无效')
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
        grace=ttl+60
        update_dns_record(conn,binding,record,target_ip)
        updated=get_dns_record(conn,binding)
        expected=dict(binding,expected_ip=target_ip)
        validate_dns_record(updated,expected,conn)
        message=f"DNS 已从 {old_ip} 切换到 {target_ip}；等待旧 VPS #{r['active_server_id']} 连接降到阈值以下"
        db.execute('UPDATE dns_bindings SET expected_ip=?,status=?,updated=? WHERE id=?',(target_ip,message,now,binding['id']))
        db.execute("UPDATE vps_rotations SET active_server_id=?,phase='draining',drain_server_id=?,drain_started=?,drain_grace_s=?,old_ip=?,new_ip=NULL,action_started=NULL,last_sample_at=NULL,low_samples=0,status=?,next_switch_at=?,updated=? WHERE id=?",(target,r['active_server_id'],now,grace,old_ip,message,now+r['interval_s'],now,rotation))
        _event(db,rotation,r['active_server_id'],message,now)

def _run_rotation(connect,cipher,rid,now):
    with connect() as db:
        r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
        if not r or not r['enabled']:return
        if r['phase']=='active':
            if r['next_switch_at']<=now:_dns_switch(connect,cipher,rid,now)
            return
        old=r['drain_server_id']
        if not old:return
        if r['phase']=='draining':
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
            if type(count)is not int or type(stamp)is not int or now-stamp>45:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('等待旧 VPS 新鲜 TCP 连接数',now,rid));return
            if stamp>(r['last_sample_at'] or 0):
                lows=r['low_samples']+1 if count<r['connection_threshold'] else 0
                db.execute('UPDATE vps_rotations SET low_samples=?,last_sample_at=?,status=?,updated=? WHERE id=?',(lows,stamp,f'旧 VPS 当前 {count} 条 TCP 连接；阈值 < {r["connection_threshold"]}，连续低值采样 {lows}/2',now,rid))
                r=dict(r);r['low_samples']=lows
            if r['low_samples']<2:return
            pending=db.execute("SELECT 1 FROM detection_runs WHERE server_id=? AND action_status IN ('queued','issued','submitted','uncertain','verifying') LIMIT 1",(old,)).fetchone()
            if pending:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('连接数已达标，但旧 VPS 另有换 IP 任务处理中；等待其完成',now,rid));return
            plan=db.execute('SELECT action_connection_id FROM detection_plans WHERE server_id=?',(old,)).fetchone()
            if not plan or not plan['action_connection_id']:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('旧机连接已降至阈值，但未配置换 IP API',now,rid));return
            try:action=load_connection(db,cipher,plan['action_connection_id'])
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            server=db.execute('SELECT name FROM servers WHERE id=?',(old,)).fetchone()
            db.execute('UPDATE vps_rotations SET phase=\'waiting_ip\',action_started=?,action_attempts=action_attempts+1,status=?,updated=? WHERE id=?',(now,'连接数达标，已发起旧 VPS 换 IP；等待新 IP',now,rid))
            item={'id':rid,'server_id':old,'ip':ip,'name':server['name'] if server else str(old)}
        elif r['phase']=='waiting_ip':
            try:ip,port,_=_fresh_ip(db,old,now,cipher)
            except IntegrationError as e:db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            if ip!=r['old_ip']:
                db.execute("UPDATE vps_rotations SET phase='waiting_probe',new_ip=?,status=?,updated=? WHERE id=?",(ip,'新 IP 已上报，等待 BOCE 国内复检',now,rid));return
            if r['action_started'] and now-r['action_started']<60:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('换 IP 请求已发出，观察 60 秒内的 IP 变化',now,rid));return
            try:_validated_plan(db,old,r['owner_id'])
            except IntegrationError as e:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',(str(e),now,rid));return
            plan=db.execute('SELECT action_connection_id FROM detection_plans WHERE server_id=?',(old,)).fetchone()
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
            reason=boce_dns_gate(db,old,ip,port,require_plan=True,min_created=r['action_started'])
            if reason:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('新 IP 尚未通过 BOCE 复检：'+reason,now,rid));return
            try:
                with socket.create_connection((ip,port),timeout=4):pass
            except OSError:
                db.execute('UPDATE vps_rotations SET status=?,updated=? WHERE id=?',('BOCE 已通过，但新 IP 业务端口仍不可达',now,rid));return
            next_at=max(r['next_switch_at'],now+r['interval_s'])
            message=f'旧 VPS #{old} 已换到 {ip}，业务端口及 BOCE 复检通过；已重新加入轮换'
            db.execute("UPDATE vps_rotations SET phase='active',drain_server_id=NULL,drain_started=NULL,drain_grace_s=0,old_ip=NULL,new_ip=NULL,action_started=NULL,last_sample_at=NULL,low_samples=0,next_switch_at=?,status=?,updated=? WHERE id=?",(next_at,message,now,rid))
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
        with connect() as db:ids=[r[0] for r in db.execute('SELECT id FROM vps_rotations WHERE enabled=1 ORDER BY id')]
        for rid in ids:
            try:_run_rotation(connect,cipher,rid,int(time.time()))
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
