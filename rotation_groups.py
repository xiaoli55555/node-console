"""One plan can own several records; fixed plans may share only their primary."""
import json
from ip_dns import IntegrationError


def forced_drain_satisfied(r,now):
    try:
        state=json.loads(r['force_drain_samples'] or '{}')
        return bool(r['force_drain_threshold'] and r['drain_started'] is not None
                    and now-r['drain_started']>=3600 and state['started']==r['drain_started']
                    and state['threshold']==r['force_drain_threshold'] and state['count']>=2
                    and r['drain_started']+3600<=state['stamp']<=now and now-state['stamp']<=45)
    except (KeyError,IndexError,TypeError,ValueError):return False


def members(db,r):
    return db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? AND other_server_id=? AND owner_id=? AND mode=? ORDER BY id',(r['primary_server_id'],r['other_server_id'],r['owner_id'],r['mode'])).fetchall()


def roots(db):
    return db.execute('SELECT * FROM vps_rotations WHERE id IN (SELECT MIN(id) FROM vps_rotations GROUP BY primary_server_id,other_server_id,owner_id,mode) ORDER BY id DESC').fetchall()


def compatible(db,sid,other,mode,uid,rid=None):
    for p in db.execute('SELECT * FROM vps_rotations WHERE id<>? AND (primary_server_id IN (?,?) OR other_server_id IN (?,?))',(rid or -1,sid,other,sid,other)):
        same_pair=p['primary_server_id']==sid and p['other_server_id']==other and p['owner_id']==uid
        if same_pair:continue
        if mode=='fixed_primary' and p['mode']=='fixed_primary' and p['primary_server_id']==sid and p['owner_id']==uid and p['other_server_id']!=other:continue
        raise IntegrationError('仅固定主机模式可共用同一主 VPS；轮换机不能跨计划复用，也不能交叉占用 A/B')


def action_guard(db,r,sid,now):
    peers=db.execute('SELECT * FROM vps_rotations WHERE primary_server_id=? OR other_server_id=?',(sid,sid)).fetchall()
    if len(peers)<2:return
    for p in peers:
        if p['dns_intent']:raise IntegrationError('共享机器仍有解析切换待核对，暂停换 IP')
        if p['active_server_id']==sid:
            lease=db.execute('SELECT 1 FROM vps_failover_leases l JOIN dns_bindings b ON b.id=l.binding_id WHERE l.binding_id=? AND l.intent IS NULL AND l.current_ip=b.expected_ip',(p['binding_id'],)).fetchone()
            if not lease:raise IntegrationError('等待所有关联线路移出此 VPS 后再换 IP')
    for p in peers:
        if p['drain_server_id']==sid and p['phase']=='draining' and not p['emergency'] and ((p['low_samples']<2 and not forced_drain_satisfied(p,now)) or now-(p['drain_started'] or now)<p['drain_grace_s']):raise IntegrationError('等待关联记录的 TTL 排空及连续 TCP 低值采样')
    inflight=[p['id'] for p in peers if p['drain_server_id']==sid and p['phase']=='waiting_ip' and p['action_started'] is not None]
    if inflight:
        if r['id']!=min(inflight):raise IntegrationError('共享 VPS 已由计划 #'+str(min(inflight))+' 发起换 IP，等待该动作完成')
        return
    candidates=[p['id'] for p in peers if p['drain_server_id']==sid and p['phase'] in ('draining','waiting_ip','waiting_probe') and (p['enabled'] or p['fault_recovery'])]
    if candidates and r['id']!=min(candidates):raise IntegrationError('共享换 IP 动作由计划 #'+str(min(candidates))+' 统一执行，等待新 IP 上报')


def target_guard(db,r,sid):
    pending=db.execute("SELECT id FROM vps_rotations WHERE id<>? AND drain_server_id=? AND phase='waiting_ip' AND action_started IS NOT NULL ORDER BY id LIMIT 1",(r['id'],sid)).fetchone()
    if pending:raise IntegrationError('共享 VPS 正由计划 #'+str(pending['id'])+' 换 IP，等待完成后再解析到它')
