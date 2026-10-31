#!/usr/bin/env python3
"""Host collector with explicitly enabled, fixed reboot/DHCP actions."""
import json, os, time, socket, platform, shutil, subprocess, urllib.request, urllib.error, argparse, ipaddress, threading, fcntl, re, signal
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

DHCP_CONFIG=Path('/etc/hk-sdan-agent/hkt-dhcp.json')
DHCP_STATE=Path('/var/lib/hk-sdan-agent')

def dhcp_config():
    cfg=json.loads(DHCP_CONFIG.read_text())
    iface=cfg.get('interface','')
    if cfg.get('enabled') is not True or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',iface):raise ValueError('DHCP 未在本机启用')
    if not (Path('/sys/class/net')/iface).exists() or not shutil.which('dhclient'):raise ValueError('缺少网卡或 dhclient')
    return cfg

def dhcp_address(iface):
    data=json.loads(subprocess.run(['ip','-j','-4','address','show','dev',iface],check=True,capture_output=True,text=True,timeout=5).stdout)
    ips=[a['local'] for row in data for a in row.get('addr_info',[]) if ipaddress.ip_address(a['local']).is_global]
    return ips[0] if len(ips)==1 else None

def dhcp_write(result):
    DHCP_STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=DHCP_STATE/'dhcp-result.json';tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(result));tmp.chmod(0o600);tmp.replace(path)

def dhcp_clients(iface,cleanup_unscoped=False,root=Path('/proc')):
    result=[]
    for path in root.iterdir():
        if not path.name.isdecimal():continue
        try:args=[x.decode() for x in (path/'cmdline').read_bytes().split(b'\0') if x]
        except (OSError,UnicodeError):continue
        if not args or Path(args[0]).name!='dhclient' or '-6' in args:continue
        if iface in args[1:] or (cleanup_unscoped and args[1:]==['-v']):result.append((int(path.name),args))
    return result

def dhcp_run(args,timeout=45):
    # Kill a timed-out invocation's process group, not unrelated DHCP clients.
    child=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    try:return child.wait(timeout=timeout)==0
    except subprocess.TimeoutExpired:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        child.wait();return False

def dhcp_acquire(iface,background=False):
    return [shutil.which('dhclient'),'-4']+(['-nw'] if background else ['-1','-v'])+['-pf',f'/run/dhclient.{iface}.pid','-lf',f'/var/lib/dhcp/dhclient.{iface}.leases',iface]

def dhcp_lease_path(iface):return Path(f'/var/lib/dhcp/dhclient.{iface}.leases')

def dhcp_background(iface,cfg):
    if not dhcp_clients(iface,cfg.get('cleanup_unscoped') is True):
        dhcp_run(dhcp_acquire(iface,background=True),timeout=15)

def dhcp_recover():
    cfg=dhcp_config();iface=cfg['interface']
    route=subprocess.run(['ip','-4','route','show','default','dev',iface],capture_output=True,text=True,timeout=5,check=True).stdout.strip()
    if dhcp_address(iface) and route:return
    dhcp_background(iface,cfg)

def dhcp_task(cid):
    cfg=dhcp_config();iface=cfg['interface'];DHCP_STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (DHCP_STATE/'dhcp.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        path=DHCP_STATE/'dhcp-result.json'
        previous=json.loads(path.read_text()) if path.exists() else {}
        if previous.get('id',0)>=cid:return  # persistent at-most-once across agent restarts
        old=dhcp_address(iface)
        result={'id':cid,'state':'running','old_ip':old,'attempts':0};dhcp_write(result)
        try:
            # Verify a public IPv4 before touching DHCP; no guessed interface/lease.
            if not old:raise ValueError('无法唯一确认原 IPv4')
            for attempt in range(1,4):
                result['attempts']=attempt
                clients=dhcp_clients(iface,cfg.get('cleanup_unscoped') is True)
                dhcp_run([shutil.which('dhclient'),'-4','-r','-pf',f'/run/dhclient.{iface}.pid','-lf',f'/var/lib/dhcp/dhclient.{iface}.leases',iface],timeout=10)
                for pid,args in clients:
                    try:
                        current=[x.decode() for x in (Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0') if x]
                        if current==args:os.kill(pid,signal.SIGTERM)
                    except (OSError,UnicodeError):pass
                time.sleep(3)
                if dhcp_clients(iface,cfg.get('cleanup_unscoped') is True):raise ValueError('仍有 DHCP 客户端未退出')
                # Remove only this interface's IPv4 lease; preserve IPv6 and other NICs.
                lease=dhcp_lease_path(iface)
                if lease.exists():
                    backup=DHCP_STATE/'dhcp-lease.backup';backup.write_bytes(lease.read_bytes());backup.chmod(0o600)
                    lease.unlink()
                dhcp_run(dhcp_acquire(iface),timeout=45)
                time.sleep(5)
                new=dhcp_address(iface);result['new_ip']=new
                if new and new!=old:
                    result['state']='changed';break
                if not new:dhcp_background(iface,cfg)
                time.sleep(5)
            else:result['state']='unchanged' if dhcp_address(iface)==old else 'failed'
        except Exception as e:
            result['state']='failed';result['error']=type(e).__name__+': '+str(e)[:180]
        finally:
            try:
                if not dhcp_address(iface):dhcp_background(iface,cfg)
            except Exception:pass
            result['finished_at']=int(time.time());dhcp_write(result)


def dispatch_dhcp(cid):
    dhcp_config()  # local opt-in is required even for a valid panel command
    # Independent systemd jobs survive agent restart or loss of its HTTPS link.
    subprocess.run(['systemd-run','--unit=hksdan-dhcp-recover-'+str(cid),'--on-active=300s','--collect','/usr/bin/python3',str(Path(__file__).resolve()),'--dhcp-recover'],check=True,timeout=10,capture_output=True)
    subprocess.run(['systemd-run','--unit=hksdan-dhcp-'+str(cid),'--collect','--property=RuntimeMaxSec=240','/usr/bin/python3',str(Path(__file__).resolve()),'--dhcp-task',str(cid)],check=True,timeout=10,capture_output=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--once',action='store_true');p.add_argument('--config',default='/etc/hk-sdan-agent/config.json');p.add_argument('--dhcp-task',type=int);p.add_argument('--dhcp-recover',action='store_true');a=p.parse_args()
    if a.dhcp_recover:dhcp_recover();return
    if a.dhcp_task is not None:
        if a.dhcp_task<1:raise SystemExit('无效任务')
        dhcp_task(a.dhcp_task);return
    config=json.loads(Path(a.config).read_text());url=config['url'].rstrip('/')
    if not url.startswith('https://'):raise SystemExit('只支持 HTTPS 面板地址')
    previous=None;connections=ConnectionSampler();egress=EgressSampler()
    threading.Thread(target=egress.run,daemon=True).start()
    while True:
        started=time.monotonic()
        try:
            metrics,previous=collect(previous,connections)
            metrics.update(egress.snapshot())
            try:
                dhcp_config();metrics['capabilities'].append('hkt_dhcp')
                state=DHCP_STATE/'dhcp-result.json'
                if state.exists():
                    result_state=json.loads(state.read_text())
                    if result_state.get('state') in ('changed','unchanged','failed'):
                        metrics['dhcp_result']=result_state
                        if metrics.get('egress_checked',0)<result_state.get('finished_at',0):
                            metrics['egress_ips']=None;metrics['egress_checked']=0
            except (OSError,ValueError):pass
            req=urllib.request.Request(url+'/api/agent/report',data=json.dumps(metrics).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+config['token']},method='POST')
            # Never follow redirects with the agent credential.
            opener=urllib.request.build_opener(NoRedirect)
            with opener.open(req,timeout=15) as response:result=json.loads(response.read(32768))
            command=result.get('command')
            if isinstance(command,dict) and command.get('action') in ('reboot','hkt_dhcp') and type(command.get('id')) is int:
                command_url=url+'/api/agent/commands/'+str(command['id'])+'/ack'
                headers={'Content-Type':'application/json','Authorization':'Bearer '+config['token']}
                ack=urllib.request.Request(command_url,data=b'{}',headers=headers,method='POST')
                # Only act after the server accepts this one-time acknowledgement.
                with opener.open(ack,timeout=15) as response:response.read(1024)
                try:
                    if command['action']=='hkt_dhcp':dispatch_dhcp(command['id'])
                    else:subprocess.run(['/usr/bin/systemctl','reboot','--no-block'],check=True,timeout=15,capture_output=True)
                    print('动作请求已交给系统管理器',flush=True)
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
