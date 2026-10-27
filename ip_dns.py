"""Admin-only API connections and explicit, compare-before-write DNS bindings.

The worker synchronizes observed IP changes; it does not diagnose censorship or reboot.
"""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from flask import jsonify

SCHEMA = '''
CREATE TABLE IF NOT EXISTS ip_connections(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
 config TEXT NOT NULL, secret TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dns_bindings(
 id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 connection_id INTEGER NOT NULL REFERENCES ip_connections(id), source_id INTEGER REFERENCES ip_connections(id),
 domain TEXT NOT NULL, record_id TEXT NOT NULL, rr TEXT NOT NULL, line TEXT NOT NULL,
 expected_ip TEXT NOT NULL, port INTEGER NOT NULL, automatic INTEGER NOT NULL DEFAULT 0,
 candidate TEXT, candidate_since INTEGER, status TEXT NOT NULL DEFAULT '等待检查', updated INTEGER,
 UNIQUE(connection_id,record_id));
CREATE TABLE IF NOT EXISTS ip_monitors(
 server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
 port INTEGER NOT NULL DEFAULT 443, enabled INTEGER NOT NULL DEFAULT 1, source_id INTEGER REFERENCES ip_connections(id),
 current_ip TEXT, previous_ip TEXT, status TEXT NOT NULL DEFAULT '等待检测', checked INTEGER);
CREATE TABLE IF NOT EXISTS dns_events(
 id INTEGER PRIMARY KEY, binding_id INTEGER, message TEXT NOT NULL, created INTEGER NOT NULL);
'''

class IntegrationError(ValueError):
    pass

def public_v4(value):
    try:
        ip=ipaddress.ip_address(value)
        if ip.version==4 and ip.is_global:return str(ip)
    except (ValueError,TypeError):pass
    raise IntegrationError('必须填写公网 IPv4 地址')

def endpoint(url):
    p=urllib.parse.urlsplit(url)
    if p.scheme!='https' or not p.hostname or p.username or p.password or p.fragment:
        raise IntegrationError('API 地址必须为 HTTPS，不含账号密码或片段；凭证请填在密钥栏')
    try:port=p.port or 443
    except ValueError:raise IntegrationError('API 端口无效')
    if port!=443:raise IntegrationError('API 连接仅支持 HTTPS 443 端口')
    return p

def request_json(url, headers=None, payload=None):
    """Resolve once, reject non-public addresses, pin TLS socket; never follow redirects."""
    p=endpoint(url)
    try:
        addresses=socket.getaddrinfo(p.hostname,443,type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(x[4][0]).is_global for x in addresses):
            raise IntegrationError('API 地址必须解析到公网地址')
        conn=http.client.HTTPSConnection(p.hostname,timeout=8)
        raw=socket.create_connection((addresses[0][4][0],443),timeout=8)
        try:conn.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=p.hostname)
        except Exception:raw.close();raise
        try:
            path=urllib.parse.urlunsplit(('', '', p.path or '/', p.query, ''))
            conn.request('POST' if payload is not None else 'GET',path,body=payload,headers=headers or {})
            response=conn.getresponse()
            if response.status!=200:raise IntegrationError('上游接口返回 HTTP '+str(response.status))
            data=response.read(262145)
            if len(data)>262144:raise IntegrationError('接口响应过大')
            return json.loads(data)
        finally:conn.close()
    except IntegrationError:raise
    except Exception:raise IntegrationError('接口连接、TLS 校验或 JSON 解析失败；请检查地址及凭证') from None

def field(data,path):
    try:
        for part in path.split('.'):
            data=data[int(part)] if isinstance(data,list) else data[part]
        return data
    except (KeyError,IndexError,TypeError,ValueError):raise IntegrationError('响应中找不到配置的 IP 字段')

def provider_ip(connection):
    config=connection['config']
    headers={'Accept':'application/json'}
    if connection['secret']:headers[config['header']]=config['prefix']+connection['secret']
    return public_v4(field(request_json(config['url'],headers),config['ip_path']))

def alidns(connection,action,**kwargs):
    params={'AccessKeyId':connection['config']['access_key_id'],'Action':action,'Format':'JSON',
            'SignatureMethod':'HMAC-SHA1','SignatureNonce':secrets.token_hex(16),'SignatureVersion':'1.0',
            'Timestamp':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),'Version':'2015-01-09',**kwargs}
    quote=lambda x:urllib.parse.quote(str(x),safe='~')
    canonical='&'.join(quote(k)+'='+quote(params[k]) for k in sorted(params))
    signed='POST&%2F&'+quote(canonical)
    params['Signature']=base64.b64encode(hmac.new((connection['secret']+'&').encode(),signed.encode(),hashlib.sha1).digest()).decode()
    data=request_json('https://alidns.aliyuncs.com/',{'Content-Type':'application/x-www-form-urlencoded'},urllib.parse.urlencode(params))
    if 'Code' in data:raise IntegrationError('阿里云 API 失败：'+str(data['Code'])[:100])
    return data

def init_schema(connect):
    with connect() as db:db.executescript(SCHEMA)

def load_connection(db,cipher,cid):
    row=db.execute('SELECT * FROM ip_connections WHERE id=?',(cid,)).fetchone()
    if not row:raise IntegrationError('API 连接不存在')
    d=dict(row);d['config']=json.loads(d['config']);d['secret']=cipher.decrypt(d['secret'].encode()).decode()
    return d

def validate_record(record,binding):
    for key,value in [('RecordId',binding['record_id']),('RR',binding['rr']),('Line',binding['line']),('Type','A')]:
        if str(record.get(key,''))!=str(value):raise IntegrationError('解析记录身份或线路已变化，已停止修改')
    if record.get('Status')!='ENABLE':raise IntegrationError('解析记录未启用，已停止修改')
    if record.get('Value')!=binding['expected_ip']:raise IntegrationError('记录值已被其他操作修改，请核对并重新保存绑定')

def candidate_ip(db,binding,cipher):
    if binding['source_id']:
        source=load_connection(db,cipher,binding['source_id'])
        if source['kind']!='provider':raise IntegrationError('IP 来源连接类型无效')
        return provider_ip(source)
    node=db.execute('SELECT metrics,seen FROM servers WHERE id=?',(binding['server_id'],)).fetchone()
    if not node or not node['seen'] or time.time()-node['seen']>90:raise IntegrationError('agent 离线或上报过期，暂停同步')
    metrics=json.loads(node['metrics'] or '{}')
    # Interface addresses, not NAT egress (which could be a proxy exit).
    ips=[]
    for value in metrics.get('public_ips',[]):
        try:ips.append(public_v4(value))
        except IntegrationError:pass
    if len(ips)!=1:raise IntegrationError('agent 必须上报唯一的网卡公网 IPv4，不能猜测目标地址')
    return ips[0]

def run_binding(connect,cipher,bid,apply=False):
    # The process lock serializes workers AND admin-triggered updates across gunicorn processes.
    import fcntl
    with connect() as db:db_path=db.execute('PRAGMA database_list').fetchone()[2]
    with open(str(Path(db_path).with_suffix('.dns.lock')),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try:
            with connect() as db:
                row=db.execute('SELECT * FROM dns_bindings WHERE id=?',(bid,)).fetchone()
                if not row:raise IntegrationError('绑定不存在')
                b=dict(row);connection=load_connection(db,cipher,b['connection_id'])
                record=alidns(connection,'DescribeDomainRecordInfo',RecordId=b['record_id'])
                validate_record(record,b)
                new_ip=candidate_ip(db,b,cipher);now=int(time.time())
                changed=new_ip!=b['expected_ip']
                if not changed:status='IP 未变化，解析一致'
                else:
                    if b['candidate']!=new_ip:
                        db.execute('UPDATE dns_bindings SET candidate=?,candidate_since=? WHERE id=?',(new_ip,now,bid))
                        b['candidate_since']=now
                    if apply and now-(b['candidate_since'] or now)>=60:
                        try:
                            with socket.create_connection((new_ip,b['port']),timeout=4):pass
                        except OSError:raise IntegrationError('新 IP 业务 TCP 端口不可达，暂停同步')
                        # Re-read immediately before writing, preserving TTL/line/weight behavior.
                        record=alidns(connection,'DescribeDomainRecordInfo',RecordId=b['record_id']);validate_record(record,b)
                        args={'RecordId':b['record_id'],'RR':b['rr'],'Type':'A','Value':new_ip,'Line':b['line'],'TTL':record['TTL']}
                        alidns(connection,'UpdateDomainRecord',**args)
                        verify=alidns(connection,'DescribeDomainRecordInfo',RecordId=b['record_id'])
                        check=dict(b,expected_ip=new_ip);validate_record(verify,check)
                        db.execute('UPDATE dns_bindings SET expected_ip=?,candidate=NULL,candidate_since=NULL WHERE id=?',(new_ip,bid))
                        status=b['expected_ip']+' → '+new_ip+'；解析已更新并回读验证（客户端缓存仍需等待 TTL）'
                    else:status=b['expected_ip']+' → '+new_ip+'；旧解析核对通过，需新 IP 稳定至少 60 秒再同步'
                if not changed:db.execute('UPDATE dns_bindings SET candidate=NULL,candidate_since=NULL WHERE id=?',(bid,))
                db.execute('UPDATE dns_bindings SET status=?,updated=? WHERE id=?',(status,now,bid))
                db.execute('INSERT INTO dns_events(binding_id,message,created) VALUES(?,?,?)',(bid,status,now))
                db.execute('DELETE FROM dns_events WHERE id NOT IN (SELECT id FROM dns_events ORDER BY id DESC LIMIT 500)')
                return {'ok':True,'candidate':new_ip,'status':status}
        except IntegrationError as e:
            with connect() as db:
                db.execute('UPDATE dns_bindings SET status=?,updated=?,candidate=NULL,candidate_since=NULL WHERE id=?',(str(e),int(time.time()),bid))
                db.execute('INSERT INTO dns_events(binding_id,message,created) VALUES(?,?,?)',(bid,str(e),int(time.time())))
            raise

def check_monitor(connect,sid,cipher=None):
    with connect() as db:
        m=db.execute('SELECT * FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
        if not m:raise IntegrationError('此 VPS 未加入监控')
        if not m['enabled']:raise IntegrationError('此 VPS 已暂停监控')
        current=None
        try:
            current=candidate_ip(db,{'server_id':sid,'source_id':m['source_id']},cipher)
            try:
                with socket.create_connection((current,m['port']),timeout=4):pass
                status='控制端 TCP 可达'
            except OSError:status='控制端 TCP 不通（尚不能判定被墙）'
        except IntegrationError as e:status=str(e)
        previous=m['current_ip'] if current and m['current_ip'] and current!=m['current_ip'] else m['previous_ip']
        if current and m['current_ip'] and current!=m['current_ip']:
            db.execute('INSERT INTO dns_events(binding_id,message,created) VALUES(NULL,?,?)',('VPS #'+str(sid)+' IP 变化：'+m['current_ip']+' → '+current,int(time.time())))
        db.execute('UPDATE ip_monitors SET current_ip=?,previous_ip=?,status=?,checked=? WHERE server_id=?',(current or m['current_ip'],previous,status,int(time.time()),sid))
        return {'ok':True,'ip':current,'previous_ip':previous,'status':status}

def register(app,connect,cipher,auth,body,error,audit):
    def safe_config(c):
        d=dict(c);d['configured']=bool(d.pop('secret'));d['config']=json.loads(d['config']);return d

    @app.get('/api/ip-dns')
    @auth(admin=True)
    def overview():
        with connect() as db:
            return jsonify(connections=[safe_config(r) for r in db.execute('SELECT * FROM ip_connections')],
                bindings=[dict(r) for r in db.execute('SELECT * FROM dns_bindings')],
                events=[dict(r) for r in db.execute('SELECT * FROM dns_events ORDER BY id DESC LIMIT 50')],
                servers=[dict(r) for r in db.execute('SELECT id,name FROM servers')],
                monitors=[dict(r) for r in db.execute('SELECT ip_monitors.*,servers.name,servers.seen FROM ip_monitors JOIN servers ON servers.id=ip_monitors.server_id')])

    @app.post('/api/ip-dns/monitors')
    @auth(admin=True)
    def save_monitors():
        d=body();ids=d.get('server_ids',[]);port=d.get('port',443)
        if not isinstance(ids,list) or not ids or len(ids)>100 or any(type(i)is not int for i in ids) or type(port)is not int or not 1<=port<=65535:return error('请选择 VPS 并填写有效 TCP 端口')
        with connect() as db:
            if any(not db.execute('SELECT 1 FROM servers WHERE id=?',(sid,)).fetchone() for sid in ids):return error('部分服务器已不存在')
            for sid in set(ids):db.execute('INSERT OR IGNORE INTO ip_monitors(server_id,port) VALUES(?,?)',(sid,port))
            audit(db,'添加 VPS IP 监控：'+','.join(map(str,sorted(set(ids)))))
        return jsonify(ok=True)

    @app.patch('/api/ip-dns/monitors/<int:sid>')
    @auth(admin=True)
    def edit_monitor(sid):
        d=body();port=d.get('port');enabled=d.get('enabled');source=d.get('source_id') or None
        if type(port)is not int or not 1<=port<=65535 or type(enabled)is not bool:return error('检测配置无效')
        with connect() as db:
            if source:
                try:
                    if load_connection(db,cipher,source)['kind']!='provider':return error('请选择服务器 API')
                except IntegrationError as e:return error(str(e))
            if not db.execute('UPDATE ip_monitors SET port=?,enabled=?,source_id=? WHERE server_id=?',(port,int(enabled),source,sid)).rowcount:return error('监控不存在')
            audit(db,'修改 VPS IP 监控 #'+str(sid))
        return jsonify(ok=True)

    @app.delete('/api/ip-dns/monitors/<int:sid>')
    @auth(admin=True)
    def delete_monitor(sid):
        with connect() as db:
            if db.execute('SELECT 1 FROM dns_bindings WHERE server_id=? AND automatic=1',(sid,)).fetchone():return error('请先关闭该 VPS 的自动解析同步，再移出监控')
            db.execute('DELETE FROM ip_monitors WHERE server_id=?',(sid,));audit(db,'移出 VPS IP 监控 #'+str(sid))
        return jsonify(ok=True)

    @app.post('/api/ip-dns/monitors/<int:sid>/check')
    @auth(admin=True)
    def test_monitor(sid):
        try:return jsonify(check_monitor(connect,sid,cipher))
        except IntegrationError as e:return error(str(e))

    @app.post('/api/ip-dns/connections')
    @auth(admin=True)
    def save_connection():
        d=body()
        try:
            kind=d.get('kind');name=d.get('name','').strip();config=d.get('config',{});secret=d.get('secret','')
            if kind not in ('alidns','provider') or not 1<=len(name)<=80 or not isinstance(config,dict) or not isinstance(secret,str) or len(secret)>4096:raise IntegrationError('API 配置格式无效')
            if kind=='alidns':
                key=config.get('access_key_id','').strip()
                if not key or len(key)>128:raise IntegrationError('请填写 AccessKey ID')
                config={'access_key_id':key}
            else:
                url=config.get('url','');endpoint(url)
                header=config.get('header','Authorization');prefix=config.get('prefix','Bearer ');path=config.get('ip_path','data.ip')
                import re
                if not re.fullmatch(r'[A-Za-z0-9-]{1,64}',header) or header.lower() in ('host','content-length','connection','transfer-encoding') or any(x in prefix+secret for x in '\r\n') or len(prefix)>64 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}',path):raise IntegrationError('认证头或字段路径格式无效')
                if len(url)>2048:raise IntegrationError('API 地址过长')
                config={'url':url,'header':header,'prefix':prefix,'ip_path':path}
            with connect() as db:
                cid=d.get('id')
                if cid:
                    old=load_connection(db,cipher,cid)
                    if old['kind']!=kind:raise IntegrationError('不能更改已有连接类型')
                    if not secret and old['config']!=config:raise IntegrationError('修改接口地址或账号时，请重新填写密钥')
                    secret=secret or old['secret']
                if kind=='alidns' and not secret:raise IntegrationError('请填写 AccessKey Secret')
                encrypted=cipher.encrypt(secret.encode()).decode()
                if cid:db.execute('UPDATE ip_connections SET name=?,config=?,secret=? WHERE id=?',(name,json.dumps(config),encrypted,cid))
                else:cid=db.execute('INSERT INTO ip_connections(name,kind,config,secret) VALUES(?,?,?,?)',(name,kind,json.dumps(config),encrypted)).lastrowid
                audit(db,'保存 IP/DNS API 连接 #'+str(cid))
            return jsonify(ok=True,id=cid)
        except (IntegrationError,AttributeError,TypeError) as e:return error(str(e) if isinstance(e,IntegrationError) else 'API 配置格式无效')

    @app.post('/api/ip-dns/connections/<int:cid>/test')
    @auth(admin=True)
    def test_connection(cid):
        try:
            with connect() as db:c=load_connection(db,cipher,cid)
            if c['kind']=='alidns':
                domain=body().get('domain','').strip()
                if not domain:raise IntegrationError('请填写要测试的主域名')
                data=alidns(c,'DescribeDomainRecords',DomainName=domain,PageSize=100)
                records=data.get('DomainRecords',{}).get('Record',[])
                # Return enough identity information for explicit bindings; never return credentials.
                return jsonify(ok=True,records=[{k:r.get(k) for k in ('RecordId','RR','Type','Line','Value','TTL','Status')} for r in records],total=data.get('TotalCount'),page_size=100)
            return jsonify(ok=True,ip=provider_ip(c))
        except IntegrationError as e:return error(str(e))

    @app.post('/api/ip-dns/bindings')
    @auth(admin=True)
    def save_binding():
        import re,sqlite3
        d=body()
        try:
            domain=d.get('domain','').strip().lower();rr=d.get('rr','').strip();line=d.get('line','').strip();rid=str(d.get('record_id','')).strip()
            if not re.fullmatch(r'[a-z0-9.-]{3,253}',domain) or not rr or len(rr)>253 or not line or len(line)>100 or not rid or len(rid)>100:raise IntegrationError('请完整填写主域名、主机记录、线路代码和 RecordId')
            ip=public_v4(d.get('expected_ip'));port=d.get('port',443)
            if type(port)is not int or not 1<=port<=65535 or type(d.get('automatic',False))is not bool:raise IntegrationError('端口或自动开关格式无效')
            with connect() as db:
                if not db.execute('SELECT 1 FROM servers WHERE id=?',(d.get('server_id'),)).fetchone():raise IntegrationError('请选择服务器')
                if not db.execute('SELECT 1 FROM ip_monitors WHERE server_id=?',(d.get('server_id'),)).fetchone():raise IntegrationError('请先将此 VPS 加入监控')
                c=load_connection(db,cipher,d.get('connection_id'))
                if c['kind']!='alidns':raise IntegrationError('请选择阿里云连接')
                source=d.get('source_id') or None
                if source and load_connection(db,cipher,source)['kind']!='provider':raise IntegrationError('IP 来源类型错误')
                # Domain-scoped lookup proves the RecordId belongs to the requested domain.
                data=alidns(c,'DescribeDomainRecords',DomainName=domain,RRKeyWord=rr,PageSize=100)
                found=next((r for r in data.get('DomainRecords',{}).get('Record',[]) if str(r.get('RecordId'))==rid),None)
                if not found:raise IntegrationError('主域名下未找到该 RecordId（接口最多检查前 100 条匹配记录）')
                validate_record(found,{'record_id':rid,'rr':rr,'line':line,'expected_ip':ip})
                values=(d['server_id'],c['id'],source,domain,rid,rr,line,ip,port,int(d.get('automatic',False)))
                if d.get('id'):
                    if not db.execute('UPDATE dns_bindings SET server_id=?,connection_id=?,source_id=?,domain=?,record_id=?,rr=?,line=?,expected_ip=?,port=?,automatic=?,candidate=NULL,candidate_since=NULL,status=\'等待检查\' WHERE id=?',values+(d['id'],)).rowcount:raise IntegrationError('绑定不存在')
                    bid=d['id']
                else:bid=db.execute('INSERT INTO dns_bindings(server_id,connection_id,source_id,domain,record_id,rr,line,expected_ip,port,automatic) VALUES(?,?,?,?,?,?,?,?,?,?)',values).lastrowid
                audit(db,'保存 DNS 绑定 #'+str(bid))
            return jsonify(ok=True,id=bid)
        except sqlite3.IntegrityError:return error('解析记录已绑定或连接配置已失效')
        except (IntegrationError,AttributeError,TypeError) as e:return error(str(e) if isinstance(e,IntegrationError) else '绑定配置格式无效')

    @app.delete('/api/ip-dns/<kind>/<int:ident>')
    @auth(admin=True)
    def delete_item(kind,ident):
        import sqlite3
        if kind not in ('connections','bindings'):return error('类型无效')
        try:
            with connect() as db:
                db.execute('DELETE FROM '+('ip_connections' if kind=='connections' else 'dns_bindings')+' WHERE id=?',(ident,));audit(db,'删除 IP/DNS '+kind+' #'+str(ident))
            return jsonify(ok=True)
        except sqlite3.IntegrityError:return error('该连接仍被解析绑定使用，请先删除绑定')

    @app.post('/api/ip-dns/bindings/<int:bid>/check')
    @auth(admin=True)
    def check_binding(bid):
        try:
            with connect() as db:audit(db,'检查 DNS 绑定 #'+str(bid)+(' 并请求同步' if body().get('apply')is True else ''))
            return jsonify(run_binding(connect,cipher,bid,body().get('apply')is True))
        except IntegrationError as e:return error(str(e))
