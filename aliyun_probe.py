"""Alibaba Cloud CMS one-time TCP probes; credentials stay encrypted in sources."""
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import urllib.parse
from datetime import datetime, timezone
from ip_dns import IntegrationError, UpstreamHTTPError, request_json


def credentials(secret):
    try:
        value = json.loads(secret)
        if not isinstance(value, dict): raise ValueError()
        for key in ('access_key_id', 'access_key_secret'):
            if not isinstance(value.get(key), str) or not 8 <= len(value[key]) <= 256: raise ValueError()
        return value
    except (ValueError, TypeError):
        raise IntegrationError('请填写有效的阿里云 AccessKey ID 和 Secret') from None


def diagnostic(action,status,data,redactions):
    def safe(value,limit):
        if not isinstance(value,str):return '未知'
        for token in sorted(set(redactions),key=len,reverse=True):
            if token:
                value=value.replace(token,'[隐藏]')
                value=value.replace(urllib.parse.quote(token,safe=''),'[隐藏]')
        return ' '.join(value.split())[:limit] or '未知'
    # Never include request headers, payloads, Recommend URLs or whole responses.
    fields=[f'阿里云 {action}',f'HTTP {status}',
            'Code='+safe(data.get('Code'),64),'RequestId='+safe(data.get('RequestId'),80),
            'Message='+safe(data.get('Message'),100)]
    return '；'.join(fields)


def call(secret, action, **kwargs):
    cred = credentials(secret)
    params = dict(AccessKeyId=cred['access_key_id'], Action=action, Format='JSON',
                  SignatureMethod='HMAC-SHA1', SignatureNonce=secrets.token_hex(16),
                  SignatureVersion='1.0', Timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                  Version='2019-01-01', RegionId='cn-hangzhou', **kwargs)
    quote = lambda s: urllib.parse.quote(str(s), safe='~')
    canonical = '&'.join(quote(k)+'='+quote(params[k]) for k in sorted(params))
    signature = hmac.new((cred['access_key_secret']+'&').encode(), ('POST&%2F&'+quote(canonical)).encode(), hashlib.sha1).digest()
    params['Signature'] = base64.b64encode(signature).decode()
    try:
        data = request_json('https://metrics.cn-hangzhou.aliyuncs.com/',
                            {'Content-Type': 'application/x-www-form-urlencoded'}, urllib.parse.urlencode(params))
    except UpstreamHTTPError as e:
        raise IntegrationError(diagnostic(action,e.status,e.details,
                               [cred['access_key_id'],cred['access_key_secret'],params['Signature']])) from None
    except IntegrationError as e:
        # Generic transport errors carry no provider body and must not echo secrets.
        reason=str(e)
        known=('API 地址必须解析到公网地址','接口响应过大',
               '接口连接、TLS 校验或 JSON 解析失败；请检查地址及凭证')
        if reason not in known:reason='连接失败，未取得可用响应'
        raise IntegrationError(f'阿里云 {action}；HTTP 未取得；'+reason) from None
    if not isinstance(data, dict):
        raise IntegrationError(f'阿里云 {action}；HTTP 200；响应不是 JSON 对象')
    if str(data.get('Success')).lower() != 'true' or str(data.get('Code')) != '200':
        raise IntegrationError(diagnostic(action,200,data,[cred['access_key_id'],cred['access_key_secret'],params['Signature']]))
    return data


def node_parts(node):
    if not isinstance(node, str) or not re.fullmatch(r'[0-9]{1,12}:[0-9]{1,12}', node):
        raise IntegrationError('阿里云节点格式应为 城市ID:运营商ID，请从节点列表选择')
    city, isp = node.split(':')
    return {'city': city, 'isp': isp, 'type': 'IDC'}


def nodes(secret):
    data = call(secret, 'DescribeSiteMonitorISPCityList', IPV4='true', IPV6='false', ViewAll='false')
    listing = data.get('IspCityList')
    rows = listing.get('IspCity') if isinstance(listing, dict) else None
    if not isinstance(rows, list): raise IntegrationError('阿里云节点列表格式异常')
    result = []
    for row in rows:
        if not isinstance(row, dict) or row.get('Country.en') != 'China': continue
        city, isp = str(row.get('City', '')), str(row.get('Isp', ''))
        if not city.isdigit() or not isp.isdigit(): continue
        result.append({'id': city+':'+isp, 'name': str(row.get('CityName.zh_CN') or row.get('CityName.en') or city)[:80],
                       'isp': str(row.get('IspName.zh_CN') or row.get('IspName.en') or isp)[:80]})
    if not result: raise IntegrationError('阿里云没有返回中国大陆可用节点')
    return result


def create(secret, ip, port, selected, run_id):
    target = ipaddress.ip_address(ip)
    if target.version != 4 or not target.is_global or type(port) is not int or not 1 <= port <= 65535:
        raise IntegrationError('无效的公网 TCP 目标')
    if not selected or len(selected) > 20: raise IntegrationError('请选择 1–20 个节点')
    # Revalidate the account's available mainland nodes before spending probe quota.
    available = {n['id'] for n in nodes(secret)}
    if not set(selected) <= available: raise IntegrationError('所选阿里云节点已不可用，请重新获取节点')
    data = call(secret, 'CreateInstantSiteMonitor', Address=str(target), TaskType='TCP',
                TaskName='hksdan_'+str(run_id)+'_'+secrets.token_hex(6), AgentGroup='PC',
                IspCities=json.dumps([node_parts(n) for n in selected]),
                OptionsJson=json.dumps({'port': port}))
    rows = data.get('CreateResultList')
    remote = rows[0].get('TaskId') if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else None
    if not isinstance(remote, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,200}', remote):
        raise IntegrationError('阿里云未返回有效任务 ID；不自动重试，避免重复扣费')
    return remote


def poll(secret, remote, selected, created):
    data = call(secret, 'DescribeSiteMonitorLog', TaskIds=remote, MetricName='ProbeLog',
                StartTime=str((created-1)*1000), Length='1000')
    # Incomplete pages must not imply that the selected nodes failed.
    if data.get('NextToken'): return None
    try:
        rows = data.get('Data')
        rows = json.loads(rows) if isinstance(rows, str) else rows
        if not isinstance(rows, list): raise ValueError()
    except (ValueError, TypeError): raise IntegrationError('阿里云结果日志格式异常') from None
    grouped = {node: [] for node in selected}
    for row in rows:
        if not isinstance(row, dict) or row.get('taskId') != remote: continue
        end = row.get('taskEndTimestamp')
        if type(end) not in (int, float) or not math.isfinite(end) or end < created*1000: continue
        node = str(row.get('city', ''))+':'+str(row.get('isp', ''))
        if node in grouped: grouped[node].append(row)
    if any(not batch for batch in grouped.values()): return None
    result = []
    for node, batch in grouped.items():
        states = []
        latencies = []
        for row in batch:
            code = row.get('errorCode')
            # Only explicit connect failure is unreachable. Socket-resource errors,
            # receive timeouts, unknown codes and missing values remain unknown.
            valid_code = type(code) in (int, float) and math.isfinite(code)
            state = 'reachable' if (valid_code and code == 0) or code == '0' else ('unreachable' if (valid_code and code == 611) or code == '611' else 'unknown')
            states.append(state)
            latency = row.get('tcpConnectTime')
            if state == 'reachable' and type(latency) in (int, float) and math.isfinite(latency) and 0 <= latency <= 60000:
                latencies.append(latency)
        state = 'reachable' if 'reachable' in states else ('unreachable' if all(s == 'unreachable' for s in states) else 'unknown')
        # Preserve raw latency for diagnosis without claiming an unverified unit.
        row = batch[-1]
        result.append({'node_id': node, 'name': str(row.get('cityCN') or row.get('cityEN') or node)+' '+str(row.get('ispCN') or row.get('ispEN') or ''),
                       'state': state, 'latency_ms': None,
                       'raw_tcp_connect_time': round(sum(latencies)/len(latencies), 2) if latencies else None})
    return result
