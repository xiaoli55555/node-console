#!/usr/bin/env python3
"""Read-only Debian host collector. No shell commands or remote execution."""
import json, os, time, socket, platform, shutil, subprocess, urllib.request, urllib.error, argparse, ipaddress, threading
from pathlib import Path

def tcp_count(root=Path('/proc')):
    count=0; found=False
    for name in ('tcp','tcp6'):
        p=root/'net'/name
        if not p.exists():continue
        found=True
        for line in p.read_text().splitlines()[1:]:
            cols=line.split()
            if len(cols)>3 and cols[3]=='01':count+=1
    return count if found else None

def tcp_port_counts(root=Path('/proc')):
    counts={};found=False
    for name in ('tcp','tcp6'):
        path=root/'net'/name
        if not path.exists():continue
        found=True
        for line in path.read_text().splitlines()[1:]:
            cols=line.split()
            if len(cols)>3 and cols[3]=='01':
                port=str(int(cols[1].rsplit(':',1)[1],16))
                counts[port]=counts.get(port,0)+1
    return counts if found else None

def udp_count():
    # Match ss -uanH: IPv4/IPv6 UDP sockets in all states, not conntrack flows.
    if not shutil.which('ss'):return None,'未安装 ss（iproute2），UDP socket 数不可用'
    try:
        r=subprocess.run(['ss','-u','-a','-n','-H'],capture_output=True,text=True,timeout=5,check=False)
        if r.returncode:return None,'ss UDP socket 采集失败'
        return sum(1 for line in r.stdout.splitlines() if line.strip()),''
    except (OSError,subprocess.TimeoutExpired):return None,'ss UDP socket 采集超时或失败'

def public_addresses():
    try:
        result=subprocess.run(['ip','-j','address','show','scope','global'],capture_output=True,text=True,timeout=5,check=True)
        addresses=set()
        for interface in json.loads(result.stdout):
            for info in interface.get('addr_info',[]):
                address=ipaddress.ip_address(info.get('local',''))
                if address.is_global:addresses.add(str(address))
        return sorted(addresses),''
    except (OSError,ValueError,subprocess.SubprocessError):return None,'网卡公网 IP 采集失败'

def logical_cpu_count():
    try:return len(os.sched_getaffinity(0))
    except (AttributeError,OSError):return os.cpu_count()

def cpu_snapshot():
    v=[int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
    return sum(v),v[3]+v[4]

class ConnectionSampler:
    def __init__(self):self.next_at=0;self.values=(None,None,'尚未采集连接数');self.sampled_at=None;self.by_port=None
    def sample(self,clock=time.monotonic):
        now=clock()
        if now>=self.next_at:
            udp,err=udp_count()
            try:tcp=tcp_count()
            except OSError:tcp=None;err+=' TCP 采集失败'
            try:self.by_port=tcp_port_counts()
            except (OSError,ValueError):self.by_port=None
            self.values=(tcp,udp,err.strip());self.sampled_at=int(time.time());self.next_at=now+15
        return self.values

class EgressSampler:
    # Slow or unavailable IP services never block the resource reporting loop.
    def __init__(self):self.lock=threading.Lock();self.state={}
    def snapshot(self):
        with self.lock:return dict(self.state)
    def run(self):
        while True:
            started=time.monotonic();addresses=[];failed=False
            for endpoint in ('https://api.ipify.org','https://api6.ipify.org'):
                try:
                    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)
                    with opener.open(endpoint,timeout=3) as response:
                        address=ipaddress.ip_address(response.read(128).decode().strip())
                    if not address.is_global:raise ValueError('non-public address')
                    addresses.append(str(address))
                except Exception:failed=True
            with self.lock:self.state={'egress_ips':sorted(set(addresses)) if addresses else None,'egress_checked':int(time.time()),'egress_error':'部分出口地址未检测到（无 IPv6 或检测服务不可用）' if failed else ''}
            time.sleep(max(0,60-(time.monotonic()-started)))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def collect(previous=None,connections=None):
    now=cpu_snapshot();cpu=None
    if previous and now[0]>previous[0]:cpu=round(100*(1-(now[1]-previous[1])/(now[0]-previous[0])),1)
    mem={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if len(line.split())>=2}
    disk=shutil.disk_usage('/');rx=tx=0
    for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
        iface,fields=line.split(':',1)
        if iface.strip()=='lo':continue
        values=fields.split();rx+=int(values[0]);tx+=int(values[8])
    tcp,udp,err=(connections or ConnectionSampler()).sample()
    addresses,ip_error=public_addresses()
    os_name=platform.system()
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if line.startswith('PRETTY_NAME='):os_name=line.split('=',1)[1].strip('"')
    except OSError:pass
    return {'cpu_percent':cpu,'memory_percent':round(100*(1-mem.get('MemAvailable',mem.get('MemFree',0))/mem['MemTotal']),1),
            'memory_total':mem['MemTotal'],'memory_used':max(0,mem['MemTotal']-mem.get('MemAvailable',mem.get('MemFree',0))),'cpu_count':logical_cpu_count(),'disk_percent':round(100*disk.used/disk.total,1),'disk_total':disk.total,
            'uptime':int(float(Path('/proc/uptime').read_text().split()[0])), 'rx_bytes':rx,'tx_bytes':tx,
            'tcp_by_port':connections.by_port if connections else None,'udp_method':'socket','connections_sampled':connections.sampled_at if connections else int(time.time()),'capabilities':['reboot'],'tcp':tcp,'udp':udp,'public_ips':addresses,'ip_error':ip_error,'network_error':err.strip(),'hostname':socket.gethostname(),'os':os_name,'kernel':platform.release()},now

def main():
    p=argparse.ArgumentParser();p.add_argument('--once',action='store_true');p.add_argument('--config',default='/etc/hk-sdan-agent/config.json');a=p.parse_args()
    config=json.loads(Path(a.config).read_text());url=config['url'].rstrip('/')
    if not url.startswith('https://'):raise SystemExit('只支持 HTTPS 面板地址')
    previous=None;connections=ConnectionSampler();egress=EgressSampler()
    threading.Thread(target=egress.run,daemon=True).start()
    while True:
        started=time.monotonic()
        try:
            metrics,previous=collect(previous,connections)
            metrics.update(egress.snapshot())
            req=urllib.request.Request(url+'/api/agent/report',data=json.dumps(metrics).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+config['token']},method='POST')
            # Never follow redirects with the agent credential.
            opener=urllib.request.build_opener(NoRedirect)
            with opener.open(req,timeout=15) as response:result=json.loads(response.read(32768))
            command=result.get('command')
            if isinstance(command,dict) and command.get('action')=='reboot' and type(command.get('id')) is int:
                command_url=url+'/api/agent/commands/'+str(command['id'])+'/ack'
                headers={'Content-Type':'application/json','Authorization':'Bearer '+config['token']}
                ack=urllib.request.Request(command_url,data=b'{}',headers=headers,method='POST')
                # Only act after the server accepts this one-time acknowledgement.
                with opener.open(ack,timeout=15) as response:response.read(1024)
                try:
                    subprocess.run(['/usr/bin/systemctl','reboot','--no-block'],check=True,timeout=15,capture_output=True)
                    print('重启请求已交给系统管理器',flush=True)
                except (OSError,subprocess.SubprocessError):
                    print('系统重启请求失败',flush=True)
                    failure=urllib.request.Request(command_url,data=b'{"status":"failed"}',headers=headers,method='POST')
                    with opener.open(failure,timeout=15) as response:response.read(1024)
            # Routine five-second reports stay out of journald to reduce disk writes.
        except Exception as e:
            # Avoid including URL, request headers or token in logs.
            print('采集或上报失败：'+type(e).__name__,flush=True)
        if a.once:break
        time.sleep(max(0,5-(time.monotonic()-started)))
if __name__=='__main__':main()
