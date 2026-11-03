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
    if 'first' not in evidence:evidence['first']=first or snapshot(db,sid,ip,now)
    if row['confirmed_at'] is not None and 'confirmed' not in evidence:
        evidence['confirmed']=snapshot(db,sid,ip,now)
    db.execute('UPDATE detection_incidents SET evidence=? WHERE id=?',(json.dumps(evidence),incident_id))


def serialize(item,now):
    item=dict(item);item['nodes']=_json(item['nodes'],[]);item['details']=_json(item['details'],[])
    item['evidence']=_json(item.get('evidence'),{})
    item['duration_s']=max(0,(item['closed_at'] or now)-item['first_failed'])
    return item
