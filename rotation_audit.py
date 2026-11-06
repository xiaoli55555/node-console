"""Database-only, allowlisted event evidence; never copy provider messages or secrets."""
import json
import math
import os
import re


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS rotation_audit(
        event_id INTEGER PRIMARY KEY REFERENCES vps_rotation_events(id) ON DELETE CASCADE,
        rotation_id INTEGER NOT NULL, incident_id TEXT NOT NULL, kind TEXT NOT NULL,
        created INTEGER NOT NULL, evidence TEXT NOT NULL)''')
    db.execute('CREATE INDEX IF NOT EXISTS rotation_audit_incident ON rotation_audit(incident_id,event_id)')
    db.execute('CREATE INDEX IF NOT EXISTS rotation_audit_plan ON rotation_audit(rotation_id,event_id)')
    db.execute('CREATE INDEX IF NOT EXISTS rotation_events_created ON vps_rotation_events(created)')


def parsed(value,default):
    try:return json.loads(value or '')
    except (ValueError,TypeError):return default


def number(value):return value if type(value) is int or (type(value) is float and math.isfinite(value)) else None


def code_version():
    value=os.environ.get('APP_COMMIT','unknown')
    return value if re.fullmatch(r'[a-fA-F0-9]{7,40}',value) else 'unknown'


def nodes(value):
    rows=parsed(value,[])
    if not isinstance(rows,list):return []
    return [dict(node_id=str(x.get('node_id',''))[:80],state=x['state'],latency_ms=number(x.get('latency_ms')))
            for x in rows if isinstance(x,dict) and x.get('state') in ('reachable','unreachable','unknown')]


def read(db,event_id):
    row=db.execute('SELECT incident_id,kind,evidence FROM rotation_audit WHERE event_id=?',(event_id,)).fetchone()
    return dict(incident_id=row['incident_id'],kind=row['kind'],evidence=parsed(row['evidence'],{})) if row else None


def capture(db,event_id,rid,sid,now,kind='state_observed',trigger=None,transition=None):
    r=db.execute('SELECT * FROM vps_rotations WHERE id=?',(rid,)).fetchone()
    if not r:return
    r=dict(r)
    previous=db.execute('SELECT * FROM rotation_audit WHERE rotation_id=? ORDER BY event_id DESC LIMIT 1',(rid,)).fetchone()
    prior=parsed(previous['evidence'],{}) if previous else {}
    fields='phase active_server_id next_switch_at drain_server_id drain_started drain_grace_s old_ip new_ip action_attempts action_started low_samples emergency fault_recovery dns_intent offline_after_s interval_s lead_s standby_ready_at preload_refresh_deadline'.split()
    state={k:(bool(r.get(k)) if k=='dns_intent' else r.get(k)) for k in fields}
    incident=previous['incident_id'] if previous else f'{rid}:{event_id}'
    # A recovery return belongs to the preceding emergency chain, not a new fault.
    if kind=='handoff_source_observed' and trigger!='fault_restore':incident=f'{rid}:{event_id}'
    from rotation_schedule import effective
    evidence={'schema_version':1,'code_version':code_version(),
              'previous_state':prior.get('state'),'previous_event_id':previous['event_id'] if previous else None,
              'elapsed_since_previous_event_s':max(0,now-previous['created']) if previous else None,
              'state':state,'trigger':trigger or 'unknown','servers':[],'drain_effective':effective(r,now),
              'dns_values_source':'panel_last_confirmed_not_live_provider'}
    evidence['decision_checks']={}
    for key in ('heartbeat_check','repair_check'):
        check=parsed(r.get(key),{})
        if isinstance(check,dict):
            evidence['decision_checks'][key]={k:check.get(k) for k in ('sid','ip','after','floor','run','confirmed','checked') if k in check}
    if transition:
        evidence['transition']={k:transition.get(k) for k in ('binding_id','from_server_id','to_server_id','from_ip','to_ip','submitted_at','confirmed_at','ttl_s')}
    peers=db.execute('SELECT id,binding_id,active_server_id,next_switch_at,phase,dns_intent FROM vps_rotations WHERE primary_server_id=? AND other_server_id=? AND owner_id=? AND mode=? ORDER BY id',(r['primary_server_id'],r['other_server_id'],r['owner_id'],r['mode'])).fetchall()
    evidence['group_states']=[{k:(bool(x[k]) if k=='dns_intent' else x[k]) for k in x.keys()} for x in peers]
    binding=db.execute('SELECT id,server_id,expected_ip,port,updated FROM dns_bindings WHERE id=?',(r['binding_id'],)).fetchone()
    evidence['dns_binding']=dict(binding) if binding else None
    leases=db.execute('SELECT binding_id,current_ip,target_ip,updated,intent FROM vps_failover_leases WHERE rotation_id=?',(rid,)).fetchall()
    evidence['failover_leases']=[dict(binding_id=x['binding_id'],current_ip=x['current_ip'],target_ip=x['target_ip'],updated=x['updated'],write_pending=bool(x['intent'])) for x in leases]
    server_ids={x for x in (sid,r.get('active_server_id'),r.get('drain_server_id'),r.get('primary_server_id'),r.get('other_server_id'),r.get('failover_server_id')) if x}
    for server_id in sorted(server_ids):
        s=db.execute('SELECT seen,metrics FROM servers WHERE id=?',(server_id,)).fetchone()
        if not s:continue
        m=parsed(s['metrics'],{});m=m if isinstance(m,dict) else {}
        monitor=db.execute('SELECT current_ip,port,checked FROM ip_monitors WHERE server_id=?',(server_id,)).fetchone()
        plan=db.execute('SELECT source_id,nodes,automatic,interval_s,daily_limit,checked,next_at FROM detection_plans WHERE server_id=?',(server_id,)).fetchone()
        p=db.execute('SELECT id,source_id,ip,port,status,created,updated,details FROM detection_runs WHERE server_id=? ORDER BY id DESC LIMIT 1',(server_id,)).fetchone()
        probe=None
        if p:
            probe={k:p[k] for k in ('id','source_id','ip','port','created','updated')}
            recheck=db.execute('SELECT state,stage,reference_passed,reference_checked,confirm_source_id,applied,details,reference_details FROM detection_rechecks WHERE parent_id=?',(p['id'],)).fetchone()
            probe['recheck']={**{k:recheck[k] for k in ('state','stage','reference_passed','reference_checked','confirm_source_id','applied')},'nodes':nodes(recheck['details']),'reference_nodes':nodes(recheck['reference_details'])} if recheck else None
            probe['nodes']=nodes(p['details'])
            probe['result_state']=p['status'] if p['status'] in ('creating','pending','queued','issued') else 'completed_with_nodes' if probe['nodes'] else 'unknown_or_error'
            probe['age_s']=now-p['updated']
            probe['matches_current_target']=bool(monitor and p['ip']==monitor['current_ip'] and p['port']==monitor['port'])
        import tcp_history
        tcp_gate=tcp_history.gate(db,server_id,m,now,seen=s['seen'])
        tcp_sample=db.execute('SELECT id,received_at,addresses,address_source FROM tcp_samples WHERE server_id=? ORDER BY id DESC LIMIT 1',(server_id,)).fetchone() if db.execute("SELECT 1 FROM sqlite_master WHERE name='tcp_samples'").fetchone() else None
        evidence['servers'].append({'tcp_observed_ips':parsed(tcp_sample['addresses'],[]) if tcp_sample else [],'tcp_reported_at':tcp_sample['received_at'] if tcp_sample else None,'tcp_gate':tcp_gate,'tcp_sample_id':tcp_sample['id'] if tcp_sample else None,'server_id':server_id,'heartbeat_age_s':max(0,now-s['seen']) if s['seen'] else None,
                                   'tcp':number(m.get('tcp')),'connections_sampled':number(m.get('connections_sampled')),
                                   'monitor':dict(monitor) if monitor else None,'probe_plan':dict(plan) if plan else None,'probe':probe})
    db.execute('INSERT INTO rotation_audit VALUES(?,?,?,?,?,?)',(event_id,rid,incident,kind,now,json.dumps(evidence)))
