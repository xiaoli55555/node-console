"""Admin rotation DNS picker: read provider records, explicitly save a local binding."""
import re
import sqlite3
from flask import jsonify
import ip_dns as dns


def domain_name(value):
    if not isinstance(value,str):raise dns.IntegrationError('请选择或填写主域名')
    try:value=value.strip().rstrip('.').encode('idna').decode().lower()
    except UnicodeError:raise dns.IntegrationError('主域名格式无效') from None
    if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')):raise dns.IntegrationError('主域名格式无效')
    return value


def records(connection,domain):
    if connection['kind']=='cloudflare':
        if domain!=connection['config'].get('zone_name'):raise dns.IntegrationError('请选择当前 Cloudflare 连接已授权的 Zone')
        rows=dns.cloudflare_records(connection)
        return rows,len(rows)>=500
    result=[];truncated=False
    for page in range(1,11):
        data=dns.alidns(connection,'DescribeDomainRecords',DomainName=domain,PageNumber=page,PageSize=100,TypeKeyWord='A')
        rows=data.get('DomainRecords',{}).get('Record',[])
        if not isinstance(rows,list):raise dns.IntegrationError('DNS 记录列表格式异常')
        result.extend(rows)
        total=int(data.get('TotalCount') or len(result))
        if page*100>=total or not rows:break
        if page==10:truncated=True
    return [r for r in result if isinstance(r,dict) and r.get('Type')=='A' and r.get('Status')=='ENABLE'],truncated


def register(app,connect,cipher,auth,body,error,audit):
    def connection(db,cid):
        row=db.execute("SELECT 1 FROM ip_connections WHERE id=? AND kind IN ('alidns','cloudflare') AND owner_id IS NULL",(cid,)).fetchone()
        if not row:raise dns.IntegrationError('请选择后台 DNS API 连接')
        return dns.load_connection(db,cipher,cid)

    @app.get('/api/admin/rotation-dns/<int:cid>/domains')
    @auth(admin=True)
    def domains(cid):
        try:
            with connect() as db:c=connection(db,cid)
            if c['kind']=='cloudflare':return jsonify(domains=[c['config']['zone_name']],truncated=False)
            values=[];truncated=False
            for page in range(1,6):
                data=dns.alidns(c,'DescribeDomains',PageNumber=page,PageSize=100)
                rows=data.get('Domains',{}).get('Domain',[])
                if not isinstance(rows,list):raise dns.IntegrationError('域名列表格式异常')
                values.extend(domain_name(x['DomainName']) for x in rows if isinstance(x,dict) and x.get('DomainName'))
                if page*100>=int(data.get('TotalCount') or len(values)) or not rows:break
                if page==5:truncated=True
            return jsonify(domains=sorted(set(values)),truncated=truncated)
        except (dns.IntegrationError,KeyError,TypeError,ValueError) as e:return error(str(e) if isinstance(e,dns.IntegrationError) else 'DNS 域名列表格式异常')

    @app.post('/api/admin/rotation-dns/<int:cid>/records')
    @auth(admin=True)
    def read_records(cid):
        try:
            domain=domain_name(body().get('domain'))
            with connect() as db:c=connection(db,cid)
            rows,truncated=records(c,domain)
            return jsonify(domain=domain,records=[{k:r.get(k) for k in ('RecordId','RR','Type','Line','Value','TTL','Status','Proxied')} for r in rows],truncated=truncated)
        except (dns.IntegrationError,TypeError,ValueError) as e:return error(str(e) if isinstance(e,dns.IntegrationError) else 'DNS 记录格式异常')

    @app.post('/api/admin/servers/<int:sid>/rotation/dns-binding')
    @auth(admin=True)
    def choose_record(sid):
        d=body();cid=d.get('connection_id');rid=d.get('record_id')
        if type(cid)is not int or not isinstance(rid,str) or not 1<=len(rid)<=100:return error('请选择 DNS 连接和具体记录')
        try:
            domain=domain_name(d.get('domain'))
            with connect() as db:c=connection(db,cid)
            rows,_=records(c,domain)
            record=next((r for r in rows if str(r.get('RecordId'))==rid),None)
            if not record:raise dns.IntegrationError('域名下未找到所选启用中的 A 记录，请重新读取')
            if not isinstance(record.get('RR'),str) or not 1<=len(record['RR'])<=253 or not isinstance(record.get('Line'),str) or not 1<=len(record['Line'])<=100:raise dns.IntegrationError('所选记录的主机名或线路格式异常')
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                monitor=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
                if not monitor:raise dns.IntegrationError('请先为主 VPS 开启 IP 监控')
                current=dns.candidate_ip(db,{'server_id':sid,'source_id':monitor['source_id']},cipher)
                address=dns.public_v4(record['Value'])
                if address!=current:raise dns.IntegrationError('这条线路当前解析不是主 VPS 的新鲜公网 IP，不能选用；请核对机器与线路')
                binding={'record_id':rid,'rr':str(record['RR']),'line':str(record['Line']),'domain':domain,'expected_ip':address}
                fresh=dns.get_dns_record(c,binding);dns.validate_dns_record(fresh,binding,c)
                existing=db.execute('SELECT * FROM dns_bindings WHERE connection_id=? AND record_id=?',(cid,rid)).fetchone()
                if existing:
                    if existing['server_id']!=sid:raise dns.IntegrationError('该记录已绑定其他 VPS，不能在这里抢占')
                    if db.execute('SELECT 1 FROM vps_rotations WHERE binding_id=?',(existing['id'],)).fetchone():raise dns.IntegrationError('该记录已用于轮换，请从原计划编辑')
                    if (existing['domain'],existing['rr'],existing['line'],existing['expected_ip'])!=(domain,binding['rr'],binding['line'],address):raise dns.IntegrationError('已有绑定与当前记录不一致，请先核对原绑定')
                    bid=existing['id']
                else:
                    bid=db.execute('INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic) VALUES(?,?,?,?,?,?,?,?,0)',(sid,cid,domain,rid,binding['rr'],binding['line'],address,monitor['port'])).lastrowid
                audit(db,'后台轮换选择 DNS 记录（仅面板绑定，未修改 DNS） #'+str(bid))
                return jsonify(ok=True,binding={'id':bid,'server_id':sid,**binding,'credential_owner':None},message='已选用此记录，仅保存面板绑定；未修改供应商 DNS')
        except sqlite3.IntegrityError:return error('此记录已被其他操作绑定，请刷新后重试',409)
        except (dns.IntegrationError,TypeError,ValueError,KeyError) as e:return error(str(e) if isinstance(e,dns.IntegrationError) else 'DNS 记录格式异常',409)
