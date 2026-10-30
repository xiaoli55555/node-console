"""Admin-only API connections and explicit, compare-before-write DNS bindings.

The worker synchronizes observed IP changes; it does not diagnose censorship or reboot.
"""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from flask import g, jsonify

SCHEMA = '''
CREATE TABLE IF NOT EXISTS ip_connections(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
 config TEXT NOT NULL, secret TEXT NOT NULL,
 owner_id INTEGER,
 server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS dns_bindings(
 id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
 connection_id INTEGER NOT NULL REFERENCES ip_connections(id), source_id INTEGER REFERENCES ip_connections(id),
 domain TEXT NOT NULL, record_id TEXT NOT NULL, rr TEXT NOT NULL, line TEXT NOT NULL,
 expected_ip TEXT NOT NULL, port INTEGER NOT NULL, automatic INTEGER NOT NULL DEFAULT 0,
 candidate TEXT, candidate_since INTEGER, status TEXT NOT NULL DEFAULT '等待检查', updated INTEGER,
 verify_new_ip INTEGER NOT NULL DEFAULT 1,
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

class ChangeIPUncertain(IntegrationError):
    """Provider may have accepted a request whose response was lost."""
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

def request_json(url, headers=None, payload=None, method=None):
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
            conn.request(method or ('POST' if payload is not None else 'GET'),path,body=payload,headers=headers or {})
            response=conn.getresponse()
            if not 200<=response.status<300:raise IntegrationError('上游接口返回 HTTP '+str(response.status))
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

def invoke_change_ip_api(connection,server_id,server_name,current_ip):
    """Call an explicitly configured HTTPS JSON action API; never execute shell commands."""
    config=connection['config']
    if config.get('provider')=='moonvm':
        product=str(config.get('product',''));token=connection.get('secret','')
        if not product.isdigit() or not token:raise IntegrationError('MoonVM API 配置无效，请重新保存完整 API 链接')
        url='https://store.moonvm.com/ddns.php?'+urllib.parse.urlencode({'product':product,'flag':'changeip','iptoken':token})
        response=request_moonvm(url,token)
        return 'MoonVM 已接受换 IP 请求；请等待新 IP 上报。'+(('上游响应：'+response) if response else '')
    try:template=json.loads(config['body_json'])
    except (KeyError,TypeError,ValueError):raise IntegrationError('换 IP API 请求 JSON 无效') from None
    values={'server_id':str(server_id),'server_name':str(server_name),'current_ip':str(current_ip)}
    def expand(value):
        if isinstance(value,str):
            for key,item in values.items():value=value.replace('{{'+key+'}}',item)
            return value
        if isinstance(value,list):return [expand(x) for x in value]
        if isinstance(value,dict):return {k:expand(v) for k,v in value.items()}
        return value
    headers={'Accept':'application/json','Content-Type':'application/json'}
    if connection['secret']:headers[config['header']]=config['prefix']+connection['secret']
    try:response=request_json(config['url'],headers,json.dumps(expand(template),ensure_ascii=False,separators=(',',':')))
    except IntegrationError as e:raise ChangeIPUncertain(str(e)) from None
    if isinstance(response,dict) and response.get('success') is False:raise IntegrationError('换 IP API 返回失败；请核对供应商 API 参数')
    return '换 IP API 已接受请求；等待服务器上报新 IP 后进行国内复检'

def parse_moonvm_url(url):
    """Accept only MoonVM's generated change-IP link; never request it while saving."""
    try:p=urllib.parse.urlsplit(url)
    except (TypeError,ValueError):raise IntegrationError('请粘贴完整的 MoonVM API 链接') from None
    try:port=p.port
    except ValueError:raise IntegrationError('MoonVM API 端口格式错误') from None
    if p.scheme!='https' or p.hostname!='store.moonvm.com' or port not in (None,443) or p.path!='/ddns.php' or p.username or p.password or p.fragment:
        raise IntegrationError('链接格式不正确：请粘贴 store.moonvm.com/ddns.php 生成的完整链接')
    try:q=urllib.parse.parse_qs(p.query,keep_blank_values=True,strict_parsing=True)
    except ValueError:raise IntegrationError('MoonVM API 链接参数格式错误') from None
    product=q.get('product',[]);flag=q.get('flag',[]);token=q.get('iptoken',[])
    if len(product)!=1 or not product[0].isdigit() or len(flag)!=1 or flag[0]!='changeip' or len(token)!=1 or not re.fullmatch(r'[A-Za-z0-9_-]{8,512}',token[0]):
        raise IntegrationError('链接缺少有效的产品编号、changeip 标记或 iptoken')
    return product[0],token[0]

def request_moonvm(url,token):
    """Perform the fixed MoonVM HTTPS GET only when an automatic action is issued."""
    p=endpoint(url)
    if p.hostname!='store.moonvm.com' or p.path!='/ddns.php':raise IntegrationError('MoonVM API 地址无效')
    try:
        addresses=socket.getaddrinfo(p.hostname,443,type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(x[4][0]).is_global for x in addresses):raise IntegrationError('MoonVM API 地址解析异常')
        conn=http.client.HTTPSConnection(p.hostname,timeout=10)
        raw=socket.create_connection((addresses[0][4][0],443),timeout=10)
        try:conn.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=p.hostname)
        except Exception:raw.close();raise
        try:
            conn.request('GET',p.path+'?'+p.query,headers={'Accept':'text/plain, application/json'})
            response=conn.getresponse()
            if not 200<=response.status<300:raise IntegrationError('MoonVM API 返回 HTTP '+str(response.status))
            body=response.read(4097)
            if len(body)>4096:raise IntegrationError('MoonVM API 响应过大')
            result=body.decode('utf-8','replace').strip().replace(token,'[已隐藏]')
            if result[:1]=='{':
                try:data=json.loads(result)
                except ValueError:raise IntegrationError('MoonVM API 返回内容无法解析') from None
                if isinstance(data,dict) and (data.get('success') is False or data.get('status') in ('error','failed','fail')):raise IntegrationError('MoonVM API 返回失败：'+str(data.get('message') or data.get('error') or '请检查 MoonVM 控制台'))
            if any(word in result.lower() for word in ('invalid token','invalid iptoken','unauthorized','not found')):raise IntegrationError('MoonVM API 拒绝请求，请检查链接是否仍有效')
            return result[:300]
        finally:conn.close()
    except IntegrationError:raise
    except Exception:raise ChangeIPUncertain('MoonVM 请求结果不确定，先核对新 IP，避免重复请求') from None

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

def cloudflare_api(token,path,method='GET',payload=None):
    headers={'Accept':'application/json','Authorization':'Bearer '+token}
    body=None
    if payload is not None:
        headers['Content-Type']='application/json'
        body=json.dumps(payload,ensure_ascii=False,separators=(',',':'))
    data=request_json('https://api.cloudflare.com/client/v4'+path,headers,body,method=method)
    if not isinstance(data,dict) or data.get('success') is not True:
        errors=data.get('errors',[]) if isinstance(data,dict) else []
        detail='；'.join(str(x.get('message',''))[:120] for x in errors if isinstance(x,dict))
        raise IntegrationError('Cloudflare API 失败'+('：'+detail if detail else '，请检查 Token 权限和 Zone 配置'))
    return data

def cloudflare_find_zone(token,domain):
    domain=str(domain or '').strip().lower().rstrip('.')
    if not re.fullmatch(r'(?i)(?=.{3,253}$)[a-z0-9.-]+',domain):raise IntegrationError('请填写有效的 Cloudflare Zone 主域名')
    query=urllib.parse.urlencode({'name':domain,'status':'active','per_page':50})
    result=cloudflare_api(token,'/zones?'+query)['result']
    matches=[z for z in result if isinstance(z,dict) and z.get('name','').lower()==domain and z.get('status')=='active'] if isinstance(result,list) else []
    if len(matches)!=1:raise IntegrationError('Token 下未找到唯一的已激活 Cloudflare Zone；请确认 Zone 主域名及 Zone Read 权限')
    return matches[0]

def cloudflare_records(connection):
    zone=connection['config'].get('zone_id','')
    zone_name=connection['config'].get('zone_name','').lower()
    if not re.fullmatch(r'[a-f0-9]{32}',zone):raise IntegrationError('Cloudflare Zone ID 配置无效，请重新验证')
    all_records=[]
    for page in range(1,6):
        path='/zones/'+zone+'/dns_records?'+urllib.parse.urlencode({'type':'A','page':page,'per_page':100})
        data=cloudflare_api(connection['secret'],path)
        rows=data.get('result')
        if not isinstance(rows,list):raise IntegrationError('Cloudflare DNS 记录响应格式异常')
        all_records.extend(rows)
        info=data.get('result_info') or {}
        if page>=int(info.get('total_pages') or 1) or len(rows)<100:break
    records=[]
    suffix='.'+zone_name
    for r in all_records:
        if not isinstance(r,dict) or r.get('type')!='A' or not isinstance(r.get('name'),str):continue
        full=r['name'].lower().rstrip('.')
        if full!=zone_name and not full.endswith(suffix):continue
        rr='@' if full==zone_name else full[:-len(suffix)]
        try:address=public_v4(r.get('content'))
        except IntegrationError:continue
        records.append({'RecordId':r.get('id',''),'RR':rr,'Type':'A','Line':'default','Value':address,'TTL':r.get('ttl'),'Status':'ENABLE','Proxied':bool(r.get('proxied',False)),'Name':full})
    return records

def cloudflare_record(connection,record_id):
    zone=connection['config'].get('zone_id','')
    if not re.fullmatch(r'[a-f0-9]{32}',zone) or not re.fullmatch(r'[a-f0-9]{32}',str(record_id)):raise IntegrationError('Cloudflare Zone 或 DNS Record ID 格式无效')
    data=cloudflare_api(connection['secret'],'/zones/'+zone+'/dns_records/'+str(record_id))
    record=data.get('result')
    if not isinstance(record,dict):raise IntegrationError('Cloudflare DNS 记录不存在')
    return record

def validate_cloudflare_record(record,binding,connection):
    zone_name=connection['config'].get('zone_name','').lower()
    rr=binding['rr']
    expected_name=zone_name if rr in ('','@') else rr.lower()+'.'+zone_name
    if str(record.get('id',''))!=str(binding['record_id']) or record.get('type')!='A' or str(record.get('name','')).lower().rstrip('.')!=expected_name:
        raise IntegrationError('Cloudflare DNS 记录身份已变化，已停止修改')
    if record.get('content')!=binding['expected_ip']:
        raise IntegrationError('Cloudflare DNS 记录值已被其他操作修改，请核对并重新保存绑定')

def update_cloudflare_record(connection,record,new_ip):
    payload={key:record[key] for key in ('name','type','ttl','proxied','comment','tags','settings','private_routing') if key in record}
    payload['content']=new_ip
    data=cloudflare_api(connection['secret'],'/zones/'+connection['config']['zone_id']+'/dns_records/'+record['id'],'PUT',payload)
    updated=data.get('result')
    if not isinstance(updated,dict):raise IntegrationError('Cloudflare 更新 DNS 后未返回记录')
    return updated

def init_schema(connect):
    with connect() as db:
        db.executescript(SCHEMA)
        columns={r['name'] for r in db.execute('PRAGMA table_info(ip_connections)')}
        if 'owner_id' not in columns:db.execute('ALTER TABLE ip_connections ADD COLUMN owner_id INTEGER')
        if 'server_id' not in columns:db.execute('ALTER TABLE ip_connections ADD COLUMN server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE')
        columns={r['name'] for r in db.execute('PRAGMA table_info(dns_bindings)')}
        if 'verify_new_ip' not in columns:db.execute('ALTER TABLE dns_bindings ADD COLUMN verify_new_ip INTEGER NOT NULL DEFAULT 1')

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

def get_dns_record(connection,binding):
    if connection['kind']=='cloudflare':return cloudflare_record(connection,binding['record_id'])
    return alidns(connection,'DescribeDomainRecordInfo',RecordId=binding['record_id'])

def validate_dns_record(record,binding,connection):
    if connection['kind']=='cloudflare':return validate_cloudflare_record(record,binding,connection)
    return validate_record(record,binding)

def update_dns_record(connection,binding,record,new_ip):
    if connection['kind']=='cloudflare':return update_cloudflare_record(connection,record,new_ip)
    return alidns(connection,'UpdateDomainRecord',RecordId=binding['record_id'],RR=binding['rr'],Type='A',Value=new_ip,Line=binding['line'],TTL=record['TTL'])

def candidate_ip(db,binding,cipher):
    if binding['source_id']:
        source=load_connection(db,cipher,binding['source_id'])
        if source['kind']!='provider':raise IntegrationError('IP 来源连接类型无效')
        return provider_ip(source)
    node=db.execute('SELECT metrics,seen FROM servers WHERE id=?',(binding['server_id'],)).fetchone()
    if not node or not node['seen'] or time.time()-node['seen']>90:raise IntegrationError('agent 离线或上报过期，暂停同步')
    metrics=json.loads(node['metrics'] or '{}')
    # Prefer an address assigned directly to a network interface. If the host
    # has no globally-routable interface IPv4, fall back to the existing
    # external egress-IP sampler, but only when it reports exactly one fresh
    # public IPv4. The DNS worker still verifies that the service port is
    # reachable before any record update.
    ips=[]
    for value in metrics.get('public_ips',[]):
        try:ips.append(public_v4(value))
        except IntegrationError:pass
    ips=sorted(set(ips))
    if len(ips)==1:return ips[0]
    if len(ips)>1:raise IntegrationError('agent 上报了多个网卡公网 IPv4，无法确定目标地址')
    egress=[]
    for value in metrics.get('egress_ips') or []:
        try:egress.append(public_v4(value))
        except IntegrationError:pass
    egress=sorted(set(egress))
    try:egress_checked=int(metrics.get('egress_checked') or 0)
    except (TypeError,ValueError):egress_checked=0
    if len(egress)==1 and 0<=time.time()-egress_checked<=180:return egress[0]
    if len(egress)>1:raise IntegrationError('出口 IP 检测到多个公网 IPv4，无法确定目标地址')
    raise IntegrationError('未取得网卡公网 IPv4，也没有新鲜且唯一的出口公网 IPv4')

def boce_dns_gate(db,sid,address,port=None,require_plan=False,min_created=None):
    """Return a blocking reason, or None. No BOCE requests are made here."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detection_plans'").fetchone():return '请先配置并开启自动探测，才能验证新 IP' if require_plan else None
    plan=db.execute('SELECT p.*,s.kind,s.enabled AS source_enabled,m.port AS monitor_port FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(sid,)).fetchone()
    if not plan:return '请先配置并开启自动探测，才能验证新 IP' if require_plan else None
    if require_plan and not plan['automatic']:return '新 IP 国内探测未启动：请开启定时探测'
    if not plan['source_enabled']:return '等待新 IP 的 BOCE 国内复检：探测来源已暂停'
    target_port=plan['monitor_port']
    rows=db.execute("SELECT * FROM detection_runs WHERE server_id=? AND status NOT IN ('creating','pending','queued','issued') ORDER BY id DESC LIMIT 1",(sid,)).fetchall()
    if not rows:return '等待新 IP 的一次国内探测通过'
    now=int(time.time())
    recovery=db.execute("SELECT id,action_attempted FROM detection_runs WHERE server_id=? AND ip!=? AND action_attempts>0 AND action_status IN ('queued','issued','submitted','uncertain','verifying') ORDER BY id DESC LIMIT 1",(sid,address)).fetchone()
    for run in rows:
        if min_created is not None and run['created']<min_created:return '等待发现新 IP 后发起的一次全节点探测，旧结果不可复用'
        if recovery and (run['id']<=recovery['id'] or run['created']<(recovery['action_attempted'] or 0)):return '等待本次换 IP 后重新探测一次，旧结果不可复用'
        if run['source_id']!=plan['source_id'] or run['nodes']!=plan['nodes'] or run['ip']!=address or run['port']!=target_port or now-run['updated']>max(300,plan['interval_s']*3):return '等待新 IP 和当前端口的一次国内探测通过'
        try:details=json.loads(run['details']);nodes=json.loads(plan['nodes'])
        except (ValueError,TypeError):return '等待有效的 BOCE 国内复检结果'
        if not isinstance(details,list) or not isinstance(nodes,list) or not details or any(not isinstance(x,dict) for x in details) or len(details)!=len(nodes) or set(str(x.get('node_id')) for x in details)!=set(map(str,nodes)) or any(x.get('state')!='reachable' for x in details):return '新 IP 尚未通过全部所选 BOCE 国内节点，暂不更新 DNS'
    return None

def run_binding(connect,cipher,bid,apply=False):
    # The process lock serializes workers AND admin-triggered updates across gunicorn processes.
    import fcntl
    probe_passed=False
    with connect() as db:db_path=db.execute('PRAGMA database_list').fetchone()[2]
    with open(str(Path(db_path).with_suffix('.dns.lock')),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try:
            with connect() as db:
                row=db.execute('SELECT * FROM dns_bindings WHERE id=?',(bid,)).fetchone()
                if not row:raise IntegrationError('绑定不存在')
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_rotations'").fetchone() and db.execute('SELECT 1 FROM vps_rotations WHERE binding_id=?',(bid,)).fetchone():raise IntegrationError('此 DNS 记录由双 VPS 轮换独占管理，请在轮换设置中暂停或删除计划')
                from failover import guarded
                if guarded(db,bid):raise IntegrationError('此记录正由 A 故障转移接管，暂停单机自动解析同步')
                b=dict(row);connection=load_connection(db,cipher,b['connection_id'])
                record=get_dns_record(connection,b)
                validate_dns_record(record,b,connection)
                new_ip=candidate_ip(db,b,cipher);now=int(time.time())
                changed=new_ip!=b['expected_ip']
                if not changed:status='IP 未变化，解析一致'
                else:
                    if b['candidate']!=new_ip:
                        db.execute('UPDATE dns_bindings SET candidate=?,candidate_since=? WHERE id=?',(new_ip,now,bid))
                        b['candidate_since']=now
                    probe_reason=boce_dns_gate(db,b['server_id'],new_ip,b['port'],require_plan=True,min_created=b['candidate_since']) if apply and b['verify_new_ip'] else None
                    probe_passed=bool(apply and b['verify_new_ip'] and not probe_reason)
                    has_plan=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detection_plans'").fetchone() and db.execute('SELECT 1 FROM detection_plans WHERE server_id=?',(b['server_id'],)).fetchone()
                    stable_seconds=0 if (not b['verify_new_ip'] or (has_plan and not probe_reason)) else 60
                    if apply and not probe_reason and now-(b['candidate_since'] or now)>=stable_seconds:
                        try:
                            with socket.create_connection((new_ip,b['port']),timeout=4):pass
                        except OSError:raise IntegrationError('新 IP 业务 TCP 端口不可达，暂停同步')
                        # Re-read immediately before writing, preserving TTL/line/weight behavior.
                        record=get_dns_record(connection,b);validate_dns_record(record,b,connection)
                        update_dns_record(connection,b,record,new_ip)
                        verify=get_dns_record(connection,b)
                        check=dict(b,expected_ip=new_ip);validate_dns_record(verify,check,connection)
                        db.execute('UPDATE dns_bindings SET expected_ip=?,candidate=NULL,candidate_since=NULL WHERE id=?',(new_ip,bid))
                        status=b['expected_ip']+' → '+new_ip+'；解析已更新并回读验证（客户端缓存仍需等待 TTL）'
                    else:status=probe_reason or (b['expected_ip']+' → '+new_ip+'；旧解析核对通过，需新 IP 稳定至少 '+str(stable_seconds)+' 秒再同步')
                if not changed:db.execute('UPDATE dns_bindings SET candidate=NULL,candidate_since=NULL WHERE id=?',(bid,))
                db.execute('UPDATE dns_bindings SET status=?,updated=? WHERE id=?',(status,now,bid))
                db.execute('INSERT INTO dns_events(binding_id,message,created) VALUES(?,?,?)',(bid,status,now))
                db.execute('DELETE FROM dns_events WHERE id NOT IN (SELECT id FROM dns_events ORDER BY id DESC LIMIT 500)')
                return {'ok':True,'candidate':new_ip,'status':status}
        except IntegrationError as e:
            with connect() as db:
                if probe_passed:
                    # Once this IP passed its one required probe, transient DNS
                    # or TCP failures should retry the same verified candidate.
                    db.execute('UPDATE dns_bindings SET status=?,updated=? WHERE id=?',(str(e),int(time.time()),bid))
                else:db.execute('UPDATE dns_bindings SET status=?,updated=?,candidate=NULL,candidate_since=NULL WHERE id=?',(str(e),int(time.time()),bid))
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
            observed=int(time.time())
            db.execute('INSERT INTO dns_events(binding_id,message,created) VALUES(NULL,?,?)',('VPS #'+str(sid)+' IP 变化：'+m['current_ip']+' → '+current,observed))
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detection_plans'").fetchone():
                db.execute('UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=? AND automatic=1',(observed,sid))
        db.execute('UPDATE ip_monitors SET current_ip=?,previous_ip=?,status=?,checked=? WHERE server_id=?',(current or m['current_ip'],previous,status,int(time.time()),sid))
        return {'ok':True,'ip':current,'previous_ip':previous,'status':status}

def register(app,connect,cipher,auth,body,error,audit):
    def safe_config(c):
        d=dict(c);d['configured']=bool(d.pop('secret'));d['config']=json.loads(d['config']);return d

    @app.get('/api/ip-dns')
    @auth(admin=True)
    def overview():
        with connect() as db:
            return jsonify(connections=[safe_config(r) for r in db.execute('SELECT * FROM ip_connections WHERE owner_id IS NULL')],
                bindings=[dict(r) for r in db.execute('SELECT b.* FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE c.owner_id IS NULL')],
                events=[dict(r) for r in db.execute('SELECT * FROM dns_events ORDER BY id DESC LIMIT 50')],
                servers=[dict(r) for r in db.execute('SELECT id,name FROM servers')],
                monitors=[dict(r) for r in db.execute('SELECT ip_monitors.*,servers.name,servers.seen FROM ip_monitors JOIN servers ON servers.id=ip_monitors.server_id')])

    @app.get('/api/client/servers/<int:sid>/dns-bindings')
    @auth()
    def client_dns_bindings(sid):
        if g.user['role']!='client':return error('此功能仅供客户账号使用',403)
        with connect() as db:
            server=db.execute('SELECT id FROM servers WHERE id=? AND owner_id=?',(sid,g.user['id'])).fetchone()
            if not server:return error('服务器不存在',404)
            rows=db.execute('SELECT b.id,b.connection_id,b.domain,b.rr,b.line,b.expected_ip,b.candidate,b.port,b.automatic,b.verify_new_ip,b.status,b.updated,c.name AS connection_name,c.kind AS dns_provider,CASE WHEN c.owner_id=? AND c.server_id=b.server_id THEN 1 ELSE 0 END AS customer_owned,CASE WHEN EXISTS(SELECT 1 FROM vps_rotations r WHERE r.binding_id=b.id) OR EXISTS(SELECT 1 FROM vps_failover_leases l WHERE l.binding_id=b.id) THEN 1 ELSE 0 END AS rotation_managed FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE b.server_id=? ORDER BY b.id',(g.user['id'],sid)).fetchall()
            connections=[dict(r) for r in db.execute("SELECT id,name,kind,json_extract(config,'$.provider') AS provider,json_extract(config,'$.access_key_id') AS access_key_id,json_extract(config,'$.zone_name') AS zone_name FROM ip_connections WHERE owner_id=? AND server_id=? AND kind IN ('alidns','cloudflare','change_ip') ORDER BY id",(g.user['id'],sid))]
        return jsonify(bindings=[dict(r) for r in rows],connections=connections)

    def client_server(db,sid):
        if g.user['role']!='client':return None
        return db.execute('SELECT id,name FROM servers WHERE id=? AND owner_id=?',(sid,g.user['id'])).fetchone()

    def client_dns_connection(db,sid,cid):
        return db.execute("SELECT * FROM ip_connections WHERE id=? AND kind IN ('alidns','cloudflare') AND owner_id=? AND server_id=?",(cid,g.user['id'],sid)).fetchone()

    @app.patch('/api/client/servers/<int:sid>/monitor')
    @auth()
    def client_update_monitor(sid):
        if g.user['role']!='client':return error('此功能仅供客户账号使用',403)
        d=body();port=d.get('port');enabled=d.get('enabled',True)
        if type(port)is not int or not 1<=port<=65535 or type(enabled)is not bool:return error('请填写有效的 TCP 检测端口并选择监控开关')
        with connect() as db:
            if not client_server(db,sid):return error('服务器不存在',404)
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_rotations'").fetchone() and db.execute('SELECT 1 FROM vps_rotations WHERE enabled=1 AND (primary_server_id=? OR other_server_id=?)',(sid,sid)).fetchone():return error('轮换进行中，请先暂停后再修改监控端口或开关',409)
            current=db.execute('SELECT p.action_enabled,p.response_mode,p.owner_id,s.owner_id AS source_owner,s.server_id FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id WHERE p.server_id=?',(sid,)).fetchone()
            if current and current['action_enabled'] and current['response_mode'] in ('reboot','change_api') and (current['owner_id']!=g.user['id'] or current['source_owner']!=g.user['id'] or current['server_id']!=sid):return error('管理员自动处理策略正在运行，不能修改检测端口；请联系管理员',409)
            db.execute('INSERT INTO ip_monitors(server_id,port,enabled,source_id) VALUES(?,?,?,NULL) ON CONFLICT(server_id) DO UPDATE SET port=excluded.port,enabled=excluded.enabled,source_id=NULL',(sid,port,int(enabled)))
            db.execute('UPDATE dns_bindings SET port=?,automatic=CASE WHEN ? THEN automatic ELSE 0 END WHERE server_id=?',(port,int(enabled),sid))
            audit(db,'客户配置 VPS 检测端口 / 监控开关 #'+str(sid))
        return jsonify(ok=True,port=port,enabled=enabled)

    def dns_records(connection,domain):
        import re
        if not isinstance(domain,str) or not re.fullmatch(r'(?i)[a-z0-9.-]{3,253}',domain.strip()):raise IntegrationError('请填写有效的主域名')
        if connection['kind']=='cloudflare':
            if domain.strip().lower().rstrip('.')!=connection['config'].get('zone_name','').lower():raise IntegrationError('主域名必须与此 Cloudflare 连接验证的 Zone 一致')
            return cloudflare_records(connection)
        data=alidns(connection,'DescribeDomainRecords',DomainName=domain.strip().lower(),PageSize=100)
        records=data.get('DomainRecords',{}).get('Record',[])
        if not isinstance(records,list):raise IntegrationError('阿里云解析记录格式异常')
        return [{'RecordId':str(r.get('RecordId','')),'RR':str(r.get('RR','')),'Type':str(r.get('Type','')),'Line':str(r.get('Line','')),'Value':str(r.get('Value','')),'TTL':r.get('TTL'),'Status':str(r.get('Status',''))} for r in records if isinstance(r,dict)]

    @app.post('/api/client/servers/<int:sid>/dns-connections')
    @auth()
    def client_save_dns_connection(sid):
        d=body();kind=d.get('provider','alidns');name=d.get('name','阿里云 DNS' if kind=='alidns' else 'Cloudflare DNS');config=d.get('config') or {};secret=d.get('secret','');domain=d.get('domain','')
        if kind not in ('alidns','cloudflare'):return error('DNS 服务商无效')
        if not isinstance(config,dict):return error('DNS API 配置格式无效')
        key=config.get('access_key_id','')
        if not isinstance(name,str) or not 1<=len(name.strip())<=80 or not isinstance(secret,str) or len(secret)>4096:return error('请填写连接名称和有效 DNS 密钥')
        try:
            with connect() as db:
                if not client_server(db,sid):return error('服务器不存在',404)
                if not db.execute('SELECT 1 FROM ip_monitors WHERE server_id=?',(sid,)).fetchone():return error('服务器监控尚未初始化，请先在探测设置里保存检测端口',409)
                existing=db.execute('SELECT id FROM ip_connections WHERE kind=? AND owner_id=? AND server_id=?',(kind,g.user['id'],sid)).fetchone()
                if not secret and existing:
                    previous=load_connection(db,cipher,existing['id']);secret=previous['secret']
                if not secret or len(secret)<8:return error('请填写 AccessKey Secret' if kind=='alidns' else '请填写 Cloudflare API Token')
                if kind=='alidns':
                    if not isinstance(key,str) or not key.strip() or len(key)>128:return error('请填写有效 AccessKey ID')
                    connection_config={'access_key_id':key.strip()}
                else:
                    zone=cloudflare_find_zone(secret,domain)
                    connection_config={'zone_id':zone['id'],'zone_name':zone['name'].lower()}
                candidate={'id':existing['id'] if existing else 0,'name':name.strip(),'kind':kind,'config':connection_config,'secret':secret}
                records=dns_records(candidate,domain)
                encrypted=cipher.encrypt(secret.encode()).decode()
                if existing:
                    cid=existing['id'];db.execute('UPDATE ip_connections SET name=?,config=?,secret=? WHERE id=?',(name.strip(),json.dumps(candidate['config']),encrypted,cid))
                else:
                    cid=db.execute('INSERT INTO ip_connections(name,kind,config,secret,owner_id,server_id) VALUES(?,?,?,?,?,?)',(name.strip(),kind,json.dumps(candidate['config']),encrypted,g.user['id'],sid)).lastrowid
                audit(db,'客户保存 VPS 专属 '+('阿里云' if kind=='alidns' else 'Cloudflare')+' DNS 连接 #'+str(sid))
            return jsonify(ok=True,connection={'id':cid,'name':name.strip(),'kind':kind,'zone_name':connection_config.get('zone_name')},records=records),201
        except IntegrationError as e:return error(('阿里云' if kind=='alidns' else 'Cloudflare')+' 验证失败：'+str(e))

    @app.post('/api/client/servers/<int:sid>/change-ip-api')
    @auth()
    def client_save_change_ip_api(sid):
        if g.user['role']!='client':return error('此功能仅供客户账号使用',403)
        d=body();url=d.get('url','')
        if not isinstance(url,str):return error('请粘贴完整的 MoonVM 换 IP API 链接')
        try:
            product,secret=parse_moonvm_url(url.strip())
            with connect() as db:
                if not client_server(db,sid):return error('服务器不存在',404)
                old=db.execute("SELECT id FROM ip_connections WHERE kind='change_ip' AND owner_id=? AND server_id=?",(g.user['id'],sid)).fetchone()
                encrypted=cipher.encrypt(secret.encode()).decode()
                if old:
                    cid=old['id'];db.execute("UPDATE ip_connections SET name=?,config=?,secret=? WHERE id=?",('MoonVM 产品 '+product,json.dumps({'provider':'moonvm','product':product}),encrypted,cid))
                else:
                    cid=db.execute("INSERT INTO ip_connections(name,kind,config,secret,owner_id,server_id) VALUES(?,'change_ip',?,?,?,?)",('MoonVM 产品 '+product,json.dumps({'provider':'moonvm','product':product}),encrypted,g.user['id'],sid)).lastrowid
                audit(db,'客户保存 VPS 专属 MoonVM 换 IP API #'+str(sid))
            return jsonify(ok=True,connection={'id':cid,'name':'MoonVM 产品 '+product,'kind':'change_ip','provider':'moonvm'}),201
        except IntegrationError as e:return error(str(e))

    @app.delete('/api/client/servers/<int:sid>/dns-connections/<int:cid>')
    @auth()
    def client_delete_dns_connection(sid,cid):
        with connect() as db:
            if not client_server(db,sid):return error('服务器不存在',404)
            row=db.execute('SELECT id FROM ip_connections WHERE id=? AND kind IN (\'alidns\',\'cloudflare\',\'change_ip\') AND owner_id=? AND server_id=?',(cid,g.user['id'],sid)).fetchone()
            if not row:return error('连接不存在',404)
            if db.execute('SELECT 1 FROM dns_bindings WHERE connection_id=? LIMIT 1',(cid,)).fetchone():return error('仍有 DNS 记录使用此连接，请先删除 DNS 绑定',409)
            db.execute('UPDATE detection_plans SET action_enabled=0,response_mode=\'none\',action_connection_id=NULL WHERE server_id=? AND action_connection_id=?',(sid,cid))
            db.execute('DELETE FROM ip_connections WHERE id=?',(cid,));audit(db,'客户删除 VPS 专属 API 连接 #'+str(cid))
        return jsonify(ok=True)

    @app.post('/api/client/servers/<int:sid>/dns-connections/<int:cid>/records')
    @auth()
    def client_read_dns_records(sid,cid):
        try:
            with connect() as db:
                if not client_server(db,sid):return error('服务器不存在',404)
                row=client_dns_connection(db,sid,cid)
                if not row:return error('DNS 连接不存在',404)
                connection=dict(row);connection['config']=json.loads(row['config']);connection['secret']=cipher.decrypt(row['secret'].encode()).decode()
                return jsonify(records=dns_records(connection,body().get('domain','')))
        except IntegrationError as e:return error(str(e))

    @app.post('/api/client/servers/<int:sid>/dns-bindings')
    @auth()
    def client_save_dns_binding(sid):
        import re,sqlite3
        d=body()
        try:
            domain=d.get('domain','');rr=d.get('rr','');line=d.get('line','')
            if not all(isinstance(x,str) for x in (domain,rr,line)):raise IntegrationError('主域名、主机记录和线路格式无效')
            domain=domain.strip().lower();rr=rr.strip();line=line.strip();rid=str(d.get('record_id','')).strip();cid=d.get('connection_id')
            if not re.fullmatch(r'(?i)[a-z0-9.-]{3,253}',domain) or not rr or len(rr)>253 or not line or len(line)>100 or not rid or len(rid)>100 or type(cid)is not int:raise IntegrationError('请完整选择主域名、记录、线路和 DNS 连接')
            with connect() as db:
                server=client_server(db,sid)
                if not server:return error('服务器不存在',404)
                monitor=db.execute('SELECT port,enabled FROM ip_monitors WHERE server_id=?',(sid,)).fetchone()
                if not monitor:return error('请先保存 VPS 检测端口',409)
                c=client_dns_connection(db,sid,cid)
                if not c:raise IntegrationError('DNS 连接不属于当前客户或 VPS')
                connection=dict(c);connection['config']=json.loads(c['config']);connection['secret']=cipher.decrypt(c['secret'].encode()).decode()
                found=next((r for r in dns_records(connection,domain) if str(r['RecordId'])==rid),None)
                if not found:raise IntegrationError('DNS 主域名下未找到所选记录')
                if found['Type']!='A' or found['Status']!='ENABLE' or (found['RR'],found['Line'])!=(rr,line):raise IntegrationError('解析记录类型、线路或状态已改变，请重新读取')
                ip=public_v4(found['Value'])
                duplicate=db.execute('SELECT id FROM dns_bindings WHERE server_id=? AND record_id=?'+(' AND id<>?' if d.get('id') else ''),(sid,rid,d['id']) if d.get('id') else (sid,rid)).fetchone()
                if duplicate:raise IntegrationError('此 DNS 记录已绑定到这台 VPS，不能重复绑定')
                current=db.execute('SELECT metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
                if not current or not current['seen'] or time.time()-current['seen']>90:raise IntegrationError('VPS 上报已过期，暂时无法核对解析 IP')
                metrics=json.loads(current['metrics'] or '{}');addresses=set(metrics.get('public_ips') or [])
                if ip not in addresses:
                    egress=set(metrics.get('egress_ips') or []);checked=int(metrics.get('egress_checked') or 0)
                    if ip not in egress or time.time()-checked>180:raise IntegrationError('所选解析当前 IP 与该 VPS 新鲜上报的公网 IP 不一致，已阻止绑定')
                vals=(sid,cid,domain,rid,rr,line,ip,monitor['port'])
                existing=d.get('id')
                from failover import guarded
                if existing and guarded(db,existing):raise IntegrationError('此记录由 A 故障转移接管，切回前不能修改')
                if existing:
                    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_rotations'").fetchone() and db.execute('SELECT 1 FROM vps_rotations WHERE binding_id=?',(existing,)).fetchone():raise IntegrationError('此 DNS 记录由双 VPS 轮换独占管理，请先删除轮换计划')
                    changed=db.execute('UPDATE dns_bindings SET server_id=?,connection_id=?,source_id=NULL,domain=?,record_id=?,rr=?,line=?,expected_ip=?,port=?,automatic=0,verify_new_ip=1,candidate=NULL,candidate_since=NULL,status=\'等待检查\' WHERE id=? AND server_id=? AND id IN (SELECT b.id FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE c.owner_id=? AND c.server_id=?)',vals+(existing,sid,g.user['id'],sid)).rowcount
                    if not changed:raise IntegrationError('解析绑定不属于当前客户')
                    bid=existing
                else:
                    bid=db.execute('INSERT INTO dns_bindings(server_id,connection_id,domain,record_id,rr,line,expected_ip,port,automatic,verify_new_ip) VALUES(?,?,?,?,?,?,?,?,0,1)',vals).lastrowid
                audit(db,'客户保存 VPS 专属 DNS 绑定 #'+str(bid))
            return jsonify(ok=True,id=bid)
        except sqlite3.IntegrityError:return error('该 DNS 记录已绑定，请检查是否重复')
        except IntegrationError as e:return error(str(e))

    @app.delete('/api/client/dns-bindings/<int:bid>')
    @auth()
    def client_delete_dns_binding(bid):
        with connect() as db:
            row=db.execute('SELECT b.server_id FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE b.id=? AND c.owner_id=? AND c.server_id=b.server_id AND b.server_id IN (SELECT id FROM servers WHERE owner_id=?)',(bid,g.user['id'],g.user['id'])).fetchone()
            if not row:return error('解析绑定不存在',404)
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_rotations'").fetchone() and db.execute('SELECT 1 FROM vps_rotations WHERE binding_id=?',(bid,)).fetchone():return error('请先暂停并删除双 VPS 轮换计划',409)
            from failover import guarded
            if guarded(db,bid):return error('此记录由 A 故障转移接管，切回前不能删除',409)
            db.execute('DELETE FROM dns_bindings WHERE id=?',(bid,));audit(db,'客户删除 DNS 绑定 #'+str(bid))
        return jsonify(ok=True)

    @app.post('/api/client/dns-bindings/<int:bid>/check')
    @auth()
    def client_check_dns_binding(bid):
        with connect() as db:
            owned=db.execute('SELECT 1 FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE b.id=? AND c.owner_id=? AND c.server_id=b.server_id AND b.server_id IN (SELECT id FROM servers WHERE owner_id=?)',(bid,g.user['id'],g.user['id'])).fetchone()
            if not owned:return error('解析绑定不存在',404)
        try:return jsonify(run_binding(connect,cipher,bid,body().get('apply') is True))
        except IntegrationError as e:return error(str(e))

    @app.patch('/api/client/dns-bindings/<int:bid>')
    @auth()
    def client_toggle_dns_binding(bid):
        if g.user['role']!='client':return error('此功能仅供客户账号使用',403)
        d=body();enabled=d.get('automatic')
        if type(enabled)is not bool:return error('自动解析开关格式无效')
        with connect() as db:
            binding=db.execute('SELECT b.id,b.server_id,s.name FROM dns_bindings b JOIN servers s ON s.id=b.server_id WHERE b.id=? AND s.owner_id=?',(bid,g.user['id'])).fetchone()
            if not binding:return error('解析绑定不存在',404)
            if enabled and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vps_rotations'").fetchone() and db.execute('SELECT 1 FROM vps_rotations WHERE binding_id=?',(bid,)).fetchone():return error('此 DNS 记录由双 VPS 轮换独占管理',409)
            if enabled:
                plan=db.execute('SELECT p.automatic,s.enabled AS source_enabled,m.enabled AS monitor_enabled FROM detection_plans p JOIN detection_sources s ON s.id=p.source_id JOIN ip_monitors m ON m.server_id=p.server_id WHERE p.server_id=?',(binding['server_id'],)).fetchone()
                if not plan or not plan['automatic'] or not plan['source_enabled'] or not plan['monitor_enabled']:
                    return error('请先在本 VPS 的探测设置中启用定时探测，并确认监控和探测来源可用',409)
            db.execute('UPDATE dns_bindings SET automatic=?,verify_new_ip=1 WHERE id=?',(int(enabled),bid))
            audit(db,('客户开启' if enabled else '客户暂停')+'服务器 #'+str(binding['server_id'])+' DNS 自动解析 #'+str(bid))
        return jsonify(ok=True,automatic=enabled,verify_new_ip=True)

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
            if kind not in ('alidns','cloudflare','provider','change_ip') or not 1<=len(name)<=80 or not isinstance(config,dict) or not isinstance(secret,str) or len(secret)>4096:raise IntegrationError('API 配置格式无效')
            if kind=='alidns':
                key=config.get('access_key_id','').strip()
                if not key or len(key)>128:raise IntegrationError('请填写 AccessKey ID')
                config={'access_key_id':key}
            elif kind=='cloudflare':
                zone_name=config.get('zone_name','').strip().lower().rstrip('.')
                if not secret and d.get('id'):
                    with connect() as db:secret=load_connection(db,cipher,d['id'])['secret']
                if not secret:raise IntegrationError('请填写 Cloudflare API Token')
                zone=cloudflare_find_zone(secret,zone_name)
                config={'zone_id':zone['id'],'zone_name':zone['name'].lower()}
                cloudflare_records({'config':config,'secret':secret})
            elif kind=='provider':
                url=config.get('url','');endpoint(url)
                header=config.get('header','Authorization');prefix=config.get('prefix','Bearer ');path=config.get('ip_path','data.ip')
                import re
                if not re.fullmatch(r'[A-Za-z0-9-]{1,64}',header) or header.lower() in ('host','content-length','connection','transfer-encoding') or any(x in prefix+secret for x in '\r\n') or len(prefix)>64 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}',path):raise IntegrationError('认证头或字段路径格式无效')
                if len(url)>2048:raise IntegrationError('API 地址过长')
                config={'url':url,'header':header,'prefix':prefix,'ip_path':path}
            elif config.get('provider')=='moonvm':
                url=config.get('url','').strip()
                if url:
                    product,secret=parse_moonvm_url(url)
                    config={'provider':'moonvm','product':product}
                    name='MoonVM 产品 '+product
                elif d.get('id'):
                    with connect() as db:old=load_connection(db,cipher,d['id'])
                    if old['kind']!='change_ip' or old['config'].get('provider')!='moonvm':raise IntegrationError('请粘贴完整的 MoonVM API 链接')
                    config=old['config'];secret=secret or old['secret']
                else:raise IntegrationError('请粘贴完整的 MoonVM API 链接')
            else:
                url=config.get('url','');endpoint(url)
                header=config.get('header','Authorization');prefix=config.get('prefix','Bearer ');body_json=config.get('body_json','{}')
                import re
                if not re.fullmatch(r'[A-Za-z0-9-]{1,64}',header) or header.lower() in ('host','content-length','connection','transfer-encoding') or any(x in prefix+secret for x in '\r\n') or len(prefix)>64:raise IntegrationError('认证头或凭证前缀格式无效')
                if len(url)>2048 or not isinstance(body_json,str) or len(body_json)>6000:raise IntegrationError('API 地址或请求 JSON 过长')
                try:
                    parsed=json.loads(body_json)
                    if not isinstance(parsed,dict):raise ValueError()
                except ValueError:raise IntegrationError('换 IP API 请求体必须是有效 JSON 对象') from None
                config={'url':url,'header':header,'prefix':prefix,'body_json':body_json}
            with connect() as db:
                cid=d.get('id')
                if cid:
                    old=load_connection(db,cipher,cid)
                    if old.get('owner_id') is not None:return error('客户专属 API 连接不可由管理员 API 修改')
                    if old['kind']!=kind:raise IntegrationError('不能更改已有连接类型')
                    if not secret and old['config']!=config:raise IntegrationError('修改接口地址或账号时，请重新填写密钥')
                    secret=secret or old['secret']
                if kind in ('alidns','cloudflare') and not secret:raise IntegrationError('请填写 '+('AccessKey Secret' if kind=='alidns' else 'Cloudflare API Token'))
                encrypted=cipher.encrypt(secret.encode()).decode()
                if cid:db.execute('UPDATE ip_connections SET name=?,config=?,secret=? WHERE id=? AND owner_id IS NULL',(name,json.dumps(config),encrypted,cid))
                else:cid=db.execute('INSERT INTO ip_connections(name,kind,config,secret) VALUES(?,?,?,?)',(name,kind,json.dumps(config),encrypted)).lastrowid
                audit(db,'保存 IP/DNS API 连接 #'+str(cid))
            return jsonify(ok=True,id=cid)
        except (IntegrationError,AttributeError,TypeError) as e:return error(str(e) if isinstance(e,IntegrationError) else 'API 配置格式无效')

    @app.post('/api/ip-dns/connections/<int:cid>/test')
    @auth(admin=True)
    def test_connection(cid):
        try:
            with connect() as db:
                c=load_connection(db,cipher,cid)
                if c.get('owner_id') is not None:raise IntegrationError('客户专属 API 连接不可由管理员 API 操作')
            if c['kind']=='alidns':
                domain=body().get('domain','').strip()
                if not domain:raise IntegrationError('请填写要测试的主域名')
                data=alidns(c,'DescribeDomainRecords',DomainName=domain,PageSize=100)
                records=data.get('DomainRecords',{}).get('Record',[])
                # Return enough identity information for explicit bindings; never return credentials.
                return jsonify(ok=True,records=[{k:r.get(k) for k in ('RecordId','RR','Type','Line','Value','TTL','Status')} for r in records],total=data.get('TotalCount'),page_size=100)
            if c['kind']=='cloudflare':
                domain=(body().get('domain') or c['config'].get('zone_name','')).strip().lower()
                records=dns_records(c,domain)
                return jsonify(ok=True,records=records,total=len(records),page_size=500)
            if c['kind']=='provider':return jsonify(ok=True,ip=provider_ip(c))
            if c['config'].get('provider')=='moonvm':return jsonify(ok=True,test_supported=False,message='MoonVM API 已保存；为避免真的更换 IP，面板不会发送测试请求。')
            return jsonify(ok=True,test_supported=False,message='为避免误触发换 IP，不会发送测试请求；已验证 HTTPS 地址和请求 JSON 格式。')
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
            verify_new_ip=d.get('verify_new_ip',True)
            if type(port)is not int or not 1<=port<=65535 or type(d.get('automatic',False))is not bool or type(verify_new_ip)is not bool:raise IntegrationError('端口或自动开关格式无效')
            with connect() as db:
                if not db.execute('SELECT 1 FROM servers WHERE id=?',(d.get('server_id'),)).fetchone():raise IntegrationError('请选择服务器')
                if not db.execute('SELECT 1 FROM ip_monitors WHERE server_id=?',(d.get('server_id'),)).fetchone():raise IntegrationError('请先将此 VPS 加入监控')
                from failover import guarded
                if d.get('id') and guarded(db,d['id']):raise IntegrationError('此记录由 A 故障转移接管，切回前不能修改绑定')
                c=load_connection(db,cipher,d.get('connection_id'))
                if c['kind'] not in ('alidns','cloudflare') or c.get('owner_id') is not None:raise IntegrationError('请选择管理员的 DNS 连接')
                source=d.get('source_id') or None
                if source and load_connection(db,cipher,source)['kind']!='provider':raise IntegrationError('IP 来源类型错误')
                # Domain-scoped lookup proves the RecordId belongs to the requested domain.
                if c['kind']=='cloudflare':
                    found=next((r for r in cloudflare_records(c) if str(r.get('RecordId'))==rid),None)
                    if not found:raise IntegrationError('Cloudflare Zone 下未找到该 DNS Record ID')
                    if found['RR']!=rr or found['Line']!=line or found['Type']!='A' or found['Status']!='ENABLE' or found['Value']!=ip:raise IntegrationError('Cloudflare 记录身份或当前 IP 与表单不一致')
                else:
                    data=alidns(c,'DescribeDomainRecords',DomainName=domain,RRKeyWord=rr,PageSize=100)
                    found=next((r for r in data.get('DomainRecords',{}).get('Record',[]) if str(r.get('RecordId'))==rid),None)
                    if not found:raise IntegrationError('主域名下未找到该 RecordId（接口最多检查前 100 条匹配记录）')
                    validate_record(found,{'record_id':rid,'rr':rr,'line':line,'expected_ip':ip})
                values=(d['server_id'],c['id'],source,domain,rid,rr,line,ip,port,int(d.get('automatic',False)),int(verify_new_ip))
                if d.get('id'):
                    if not db.execute('UPDATE dns_bindings SET server_id=?,connection_id=?,source_id=?,domain=?,record_id=?,rr=?,line=?,expected_ip=?,port=?,automatic=?,verify_new_ip=?,candidate=NULL,candidate_since=NULL,status=\'等待检查\' WHERE id=?',values+(d['id'],)).rowcount:raise IntegrationError('绑定不存在')
                    bid=d['id']
                else:bid=db.execute('INSERT INTO dns_bindings(server_id,connection_id,source_id,domain,record_id,rr,line,expected_ip,port,automatic,verify_new_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?)',values).lastrowid
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
                if kind=='connections':deleted=db.execute('DELETE FROM ip_connections WHERE id=? AND owner_id IS NULL',(ident,)).rowcount
                else:deleted=db.execute('DELETE FROM dns_bindings WHERE id=? AND id IN (SELECT b.id FROM dns_bindings b JOIN ip_connections c ON c.id=b.connection_id WHERE c.owner_id IS NULL)',(ident,)).rowcount
                if not deleted:return error('连接或绑定不存在，或不属于管理员配置')
                audit(db,'删除 IP/DNS '+kind+' #'+str(ident))
            return jsonify(ok=True)
        except sqlite3.IntegrityError:return error('该连接仍被解析绑定使用，请先删除绑定')

    @app.post('/api/ip-dns/bindings/<int:bid>/check')
    @auth(admin=True)
    def check_binding(bid):
        try:
            with connect() as db:audit(db,'检查 DNS 绑定 #'+str(bid)+(' 并请求同步' if body().get('apply')is True else ''))
            return jsonify(run_binding(connect,cipher,bid,body().get('apply')is True))
        except IntegrationError as e:return error(str(e))
