"""Admin rotation DNS picker: read provider records, explicitly save a local binding."""
import re
import sqlite3
import time
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
        d=body();cid=d.get('connection_id');ids=d.get('record_ids',[d.get('record_id')])
        if type(cid)is not int or not isinstance(ids,list) or not 1<=len(ids)<=50 or any(not isinstance(rid,str) or not 1<=len(rid)<=100 for rid in ids) or len(set(ids))!=len(ids):return error('请选择 DNS 连接和 1～50 条不同的记录')
        try:
            domain=domain_name(d.get('domain'))
            with connect() as db:c=connection(db,cid)
            rows,_=records(c,domain)
            selected=[]
            for rid in ids:
                record=next((r for r in rows if str(r.get('RecordId'))==rid),None)
                if not record:raise dns.IntegrationError('域名下未找到所选启用中的 A 记录，请重新读取')
                if not isinstance(record.get('RR'),str) or not 1<=len(record['RR'])<=253 or not isinstance(record.get('Line'),str) or not 1<=len(record['Line'])<=100:raise dns.IntegrationError('所选记录的主机名或线路格式异常')
                selected.append(record)
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                monitor=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
                if not monitor:raise dns.IntegrationError('请先为主 VPS 开启 IP 监控')
                current=dns.candidate_ip(db,{'server_id':sid,'source_id':monitor['source_id']},cipher)
                prepared=[]
                for record in selected:
                    rid=str(record['RecordId']);address=dns.public_v4(record['Value'])
                    if address!=current:raise dns.IntegrationError(f'所选线路当前解析不是主 VPS 的新鲜公网 IP：记录 {record["RR"]}.{domain} · {record["Line"]} 当前为 {address}，所选主 VPS 当前为 {current}。请只选择本次需要轮换的线路；已有轮换中的记录请从原计划编辑。')
                    binding={'record_id':rid,'rr':str(record['RR']),'line':str(record['Line']),'domain':domain,'expected_ip':address}
                    fresh=dns.get_dns_record(c,binding);dns.validate_dns_record(fresh,binding,c)
                    existing=db.execute('SELECT * FROM dns_bindings WHERE connection_id=? AND record_id=?',(cid,rid)).fetchone()
                    if existing:
                        owner=db.execute('SELECT id FROM vps_rotations WHERE binding_id=?',(existing['id'],)).fetchone()
                        if owner:raise dns.IntegrationError('该记录仍由轮换计划 #'+str(owner['id'])+' 管理；暂停不释放记录，请先删除该计划')
                        from failover import guarded
                        if guarded(db,existing['id']):raise dns.IntegrationError('该记录仍由故障转移接管，不能重新绑定')
                        if existing['server_id']!=sid and existing['automatic']:raise dns.IntegrationError('该记录仍开启另一台 VPS 的自动解析，请先停用后再重新选择')
                        if (existing['domain'],existing['rr'],existing['line'])!=(domain,binding['rr'],binding['line']):raise dns.IntegrationError('已有绑定的域名、主机名或线路身份不一致，请先核对')
                    prepared.append((existing,binding))
                chosen=[]
                for existing,binding in prepared:
                    bid=existing['id'] if existing else db.execute('INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic) VALUES(?,?,?,?,?,?,?,?,0)',(sid,cid,domain,binding['record_id'],binding['rr'],binding['line'],current,monitor['port'])).lastrowid
                    if existing:
                        db.execute("UPDATE dns_bindings SET server_id=?,expected_ip=?,port=?,source_id=NULL,automatic=0,candidate=NULL,candidate_since=NULL,status='记录已重新选用，等待新轮换配置',updated=? WHERE id=?",(sid,current,monitor['port'],int(time.time()),bid))
                    chosen.append({'id':bid,'server_id':sid,**binding,'credential_owner':None})
                    audit(db,'后台轮换选择 DNS 记录（仅面板绑定，未修改 DNS） #'+str(bid))
                return jsonify(ok=True,binding=chosen[0],bindings=chosen,message='已选用 '+str(len(chosen))+' 条记录，仅保存面板绑定；未修改供应商 DNS')
        except sqlite3.IntegrityError:return error('此记录已被其他操作绑定，请刷新后重试',409)
        except (dns.IntegrationError,TypeError,ValueError,KeyError) as e:return error(str(e) if isinstance(e,dns.IntegrationError) else 'DNS 记录格式异常',409)
