"""Frozen incident evidence; never participates in detection or recovery decisions."""
import ipaddress
import json


def _json(value,default):
    try:return json.loads(value) if value else default
    except (ValueError,TypeError):return default


def snapshot(db,sid,ip,now):
    tables={x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    start=None;boundary=False
    if 'ip_events' in tables:
        for row in db.execute('SELECT addresses,observed FROM ip_events WHERE server_id=? AND observed<=? ORDER BY id DESC',(sid,now)):
            ips=set()
            for value in _json(row['addresses'],[]):
                try:address=ipaddress.ip_address(value)
                except (ValueError,TypeError):continue
                if address.version==4:ips.add(str(address))
            if not ips:continue
            if ips!={ip}:boundary=True;break
            start=row['observed']
    contexts=[];known=False;uncertain=False
    if 'dns_bindings' in tables:
        for b in db.execute('SELECT * FROM dns_bindings').fetchall():
            owner=b['server_id'];role='direct_dns';plan=None;pending=False
            r=None
            if 'vps_rotations' in tables:
                r=db.execute('SELECT * FROM vps_rotations WHERE binding_id=?',(b['id'],)).fetchone()
                if r:
                    owner=r['active_server_id'];role='rotation';plan=r['id']
                    pending=bool(r['dns_intent'] or r['external_dns_pending'])
            if 'vps_failover_leases' in tables:
                lease=db.execute('SELECT l.*,r.failover_server_id FROM vps_failover_leases l JOIN vps_rotations r ON r.id=l.rotation_id WHERE l.binding_id=?',(b['id'],)).fetchone()
                if lease:owner=lease['failover_server_id'];role='rotation_failover';pending=bool(lease['intent']);plan=lease['rotation_id']
            if 'server_failover_leases' in tables:
                lease=db.execute('SELECT l.*,f.backup_id FROM server_failover_leases l JOIN server_failovers f ON f.server_id=l.server_id WHERE l.binding_id=?',(b['id'],)).fetchone()
                if lease:owner=lease['backup_id'];role='server_failover';pending=bool(lease['target_ip'])
            relevant=owner==sid or b['server_id']==sid or (r and sid in (r['primary_server_id'],r['other_server_id']))
            if not relevant:continue
            known=True
            if pending:uncertain=True
            if owner==sid and (pending or b['expected_ip']==ip):
                period=None
                if not pending and 'rotation_carrier_periods' in tables:
                    period=db.execute('SELECT p.* FROM rotation_carrier_periods p JOIN vps_rotations r ON r.id=p.rotation_id WHERE r.binding_id=? AND p.server_id=? AND p.ip=? AND p.finished IS NULL ORDER BY p.id DESC LIMIT 1',(b['id'],sid,ip)).fetchone()
                contexts.append({'binding_id':b['id'],'rotation_id':plan,'domain':b['domain'],'rr':b['rr'],'line':b['line'],'ip':b['expected_ip'],'role':role,'pending':pending,
                                 'carrier_observed_since':period['started'] if period else None,'carrier_age_s':max(0,now-period['started']) if period else None,'carrier_start_censored':bool(period['censored']) if period else True})
    state='serving' if any(not x['pending'] for x in contexts) else ('unknown' if uncertain or not known else 'standby')
    return {'captured_at':now,'ip_observed_since':start,'ip_start_censored':not boundary if start is not None else True,
            'ip_age_s':max(0,now-start) if start is not None else None,'carrier_state':state,'bindings':contexts}


def store(db,incident_id,sid,ip,now,first=None):
    row=db.execute('SELECT evidence,confirmed_at FROM detection_incidents WHERE id=?',(incident_id,)).fetchone()
    evidence=_json(row['evidence'],{})
    if 'first' not in evidence:
        evidence['first']=first or snapshot(db,sid,ip,now)
        evidence['last_pass']=last_pass(db,sid,ip,db.execute('SELECT port FROM detection_incidents WHERE id=?',(incident_id,)).fetchone()['port'],evidence['first']['captured_at'])
    if row['confirmed_at'] is not None and 'confirmed' not in evidence:
        evidence['confirmed']=snapshot(db,sid,ip,now)
    db.execute('UPDATE detection_incidents SET evidence=? WHERE id=?',(json.dumps(evidence),incident_id))


def serialize(item,now):
    item=dict(item);item['nodes']=_json(item['nodes'],[]);item['details']=_json(item['details'],[])
    item['evidence']=_json(item.get('evidence'),{})
    item['duration_s']=max(0,(item['closed_at'] or now)-item['first_failed'])
    return item


AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS detection_coverage_gaps(
 id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 ip TEXT, source_id INTEGER, started INTEGER NOT NULL, finished INTEGER,
 reason TEXT NOT NULL, evidence TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS detection_gap_open ON detection_coverage_gaps(server_id) WHERE finished IS NULL;
"""

def coverage_gap(db,sid,now,reason):
    # Observational only. Never changes probe or rotation state.
    if any(x in reason for x in ('已有检测任务','独立复测进行中','尚未到下一次')):return
    m=db.execute('SELECT current_ip FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
    p=db.execute('SELECT source_id FROM detection_plans WHERE server_id=?',(sid,)).fetchone()
    ip=m['current_ip'] if m else None
    old=db.execute('SELECT * FROM detection_coverage_gaps WHERE server_id=? AND finished IS NULL',(sid,)).fetchone()
    if old and old['ip']==ip and old['reason']==reason:return
    if old:db.execute('UPDATE detection_coverage_gaps SET finished=? WHERE id=?',(now,old['id']))
    evidence=snapshot(db,sid,ip,now) if ip else {'carrier_state':'unknown'}
    db.execute('INSERT INTO detection_coverage_gaps(server_id,ip,source_id,started,reason,evidence) VALUES(?,?,?,?,?,?)',(sid,ip,p['source_id'] if p else None,now,reason,json.dumps(evidence)))

def coverage_result(db,run,rows,now):
    expected={str(x) for x in _json(run['nodes'],[])}
    valid=bool(expected) and len(rows)==len(expected) and {str(x.get('node_id')) for x in rows}==expected and all(x.get('state') in ('reachable','unreachable') for x in rows)
    if not valid:
        coverage_gap(db,run['server_id'],now,'检测结果缺失或未知，不能判定目标正常或不通')
        return
    # Only a current-plan result closes an observed coverage gap.
    db.execute('UPDATE detection_coverage_gaps SET finished=? WHERE server_id=? AND finished IS NULL AND ip=? AND source_id=? AND started<=?',(now,run['server_id'],run['ip'],run['source_id'],run['created']))

def last_pass(db,sid,ip,port,before):
    for row in db.execute('SELECT id,updated,details FROM detection_runs WHERE server_id=? AND ip=? AND port=? AND updated<=? ORDER BY updated DESC,id DESC',(sid,ip,port,before)):
        details=_json(row['details'],[])
        if details and all(x.get('state')=='reachable' for x in details):return {'run_id':row['id'],'observed_at':row['updated']}
    return None
