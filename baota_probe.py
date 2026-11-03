"""Baota public TCP API. Incomplete/unknown evidence never triggers recovery."""
import ipaddress
import math
import re
import secrets
import urllib.parse
from ip_dns import IntegrationError, UpstreamHTTPError, request_json


def call(secret,path,params=None,method='GET',headers=None):
    query=urllib.parse.urlencode({'key':secret,**(params or {})})
    try:
        data=request_json('https://t.bt.cn/api/v1/open-api/'+path+'?'+query,
                          {'Accept':'application/json',**(headers or {})},method=method)
    except UpstreamHTTPError as e:
        raise IntegrationError(f'宝塔拨测 {path.split("/")[0]} HTTP {e.status}；请检查额度、密钥和接口权限') from None
    except IntegrationError:
        raise IntegrationError('宝塔拨测连接失败；请检查面板网络、TLS 和接口响应') from None
    if not isinstance(data,dict):raise IntegrationError('宝塔拨测响应不是 JSON 对象')
    field='status' if path=='nodes' else 'error_code'
    if type(data.get(field)) is not int or data[field]!=0:
        message=data.get('error') or data.get('msg')
        detail=message.replace(secret,'[隐藏]').replace(urllib.parse.quote(secret,safe=''),'[隐藏]')[:160] if isinstance(message,str) else '响应缺少成功状态'
        raise IntegrationError('宝塔拨测接口拒绝：'+detail)
    return data


def nodes(secret):
    data=call(secret,'nodes',{'area':'city'})
    if not isinstance(data.get('list'),list):raise IntegrationError('宝塔节点列表格式异常')
    result=[];seen=set()
    for row in data['list']:
        if not isinstance(row,dict) or str(row.get('isp_code')) not in ('2','3','4'):continue
        nid=str(row.get('id',''))
        if not re.fullmatch(r'[0-9]{1,20}',nid) or nid in seen:continue
        seen.add(nid)
        result.append({'id':nid,'name':str(row.get('node_name',''))[:80],'isp':str(row.get('isp_name',''))[:80]})
    if not result:raise IntegrationError('宝塔未返回可用的国内电信、移动或联通节点')
    return result


def create(secret,ip,port,selected,run_id,reference=False):
    if reference:
        if ip not in ('www.baidu.com','www.qq.com') or port!=80:raise IntegrationError('无效的固定参照站目标')
        target=ip
    else:
        try:target=ipaddress.ip_address(ip)
        except ValueError:raise IntegrationError('无效的公网 TCP 目标') from None
        if target.version!=4 or not target.is_global or type(port)is not int or not 1<=port<=65535:
            raise IntegrationError('无效的公网 TCP 目标')
    if not selected or len(selected)>20 or any(not re.fullmatch(r'[0-9]{1,20}',str(n)) for n in selected):
        raise IntegrationError('请选择 1–20 个宝塔节点 ID')
    available={n['id'] for n in nodes(secret)}
    if not set(map(str,selected))<=available:raise IntegrationError('所选宝塔节点已不可用，请重新获取节点')
    data=call(secret,'tasks/tcp',{'node_ids':','.join(map(str,selected)),'host':str(target),'port':port},
              method='POST',headers={'X-Idempotency-Key':'hksdan-'+str(run_id)+'-'+secrets.token_hex(12)})
    inner=data.get('data');remote=inner.get('id') if isinstance(inner,dict) else None
    if not isinstance(remote,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,200}',remote):
        raise IntegrationError('宝塔未返回有效任务 ID；不自动重试，避免重复扣费')
    return remote


def summarize(rows,selected):
    if not isinstance(rows,list):raise IntegrationError('宝塔 TCP 结果列表格式异常')
    grouped={}
    for row in rows:
        if not isinstance(row,dict):continue
        nid=str(row.get('node_id',''))
        if nid in grouped:raise IntegrationError('宝塔返回重复节点结果，不能用于故障判断')
        if nid:grouped[nid]=row
    result=[]
    for nid in map(str,selected):
        row=grouped.get(nid,{});state='unknown';latency=None
        # Public UI uses succeeded/tcp.open and TCP_CONNECT_FAILED. The open
        # API may return legacy packet counters. Require explicit evidence.
        tcp=row.get('tcp') if isinstance(row.get('tcp'),dict) else {}
        error=row.get('error')
        error_code=error.get('code') if isinstance(error,dict) else None
        if row.get('status')=='succeeded' and tcp.get('open') is True and not error:
            state='reachable'
        elif row.get('status')=='failed' and error_code=='TCP_CONNECT_FAILED' and tcp.get('open') is False:
            state='unreachable'
        elif not row.get('status'):
            sent=row.get('packets_transmitted');received=row.get('packets_received')
            valid=all(type(v) in (int,float) and math.isfinite(v) for v in (sent,received))
            if valid and sent>0 and 0<=received<=sent and type(row.get('error_code'))is int and row['error_code']==0:
                state='reachable' if received>0 else 'unreachable'
                avg=row.get('round_trip_avg')
                if type(avg) in (int,float) and math.isfinite(avg) and avg>=0:latency=avg
        result.append({'node_id':nid,'name':str(row.get('node_name',nid))[:100],
                       'state':state,'latency_ms':latency,
                       'note':'结果缺失或格式未识别，不能判定目标不通' if state=='unknown' else ''})
    return result


def poll(secret,remote,selected):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,200}',remote):raise IntegrationError('宝塔任务 ID 无效')
    data=call(secret,'tasks/tcp/'+remote)
    if data.get('id')!=remote:raise IntegrationError('宝塔返回的任务 ID 不匹配')
    if type(data.get('done'))is not bool:raise IntegrationError('宝塔任务完成状态格式异常')
    if not data['done']:return None
    return summarize(data.get('list'),selected)
