#!/usr/bin/env python3
"""Outbound-only TCP probe. Configuration file contains panel_url and token; chmod 600."""
import ipaddress,json,socket,ssl,sys,time,urllib.request

def main():
    config=json.load(open(sys.argv[1],encoding='utf-8'))
    url=config['panel_url'].rstrip('/')
    if not url.startswith('https://'):raise ValueError('panel_url must use HTTPS')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def post(path,data):
        req=urllib.request.Request(url+path,data=json.dumps(data).encode(),headers={'Authorization':'Bearer '+config['token'],'Content-Type':'application/json'})
        with opener.open(req,timeout=15) as r:return json.load(r)
    while True:
        try:
            job=post('/api/probe/jobs',{}).get('job')
            if job:
                ip=ipaddress.ip_address(job['ip']);port=job['port']
                if ip.version!=4 or not ip.is_global or type(port)is not int or not 1<=port<=65535:raise ValueError('invalid public target')
                start=time.monotonic();reachable=False
                try:
                    with socket.create_connection((str(ip),port),timeout=5):reachable=True
                except OSError:pass
                post('/api/probe/results/'+str(int(job['id'])),{'ip':str(ip),'port':port,'reachable':reachable,'latency_ms':round((time.monotonic()-start)*1000,2) if reachable else None})
        except Exception:print('Probe request failed; retrying next cycle',flush=True)
        time.sleep(10)

if __name__=='__main__':main()
