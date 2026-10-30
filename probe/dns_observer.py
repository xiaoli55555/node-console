#!/usr/bin/env python3
"""Observe A-record propagation from this machine's actual recursive resolver.
No VPS control, SSH, DNS-provider credentials or BOCE requests are used.
"""
import argparse
import ipaddress
import json
import os
import secrets
import socket
import struct
import time
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def skip_name(packet,offset):
    for _ in range(128):
        if offset>=len(packet):raise ValueError('short DNS name')
        n=packet[offset];offset+=1
        if n==0:return offset
        if n&192==192:
            if offset>=len(packet):raise ValueError('short DNS pointer')
            return offset+1
        if n&192 or n>63 or offset+n>len(packet):raise ValueError('invalid DNS name')
        offset+=n
    raise ValueError('long DNS name')

def parse_answer(packet,ident):
    if len(packet)<12:raise ValueError('short DNS response')
    rid,flags,questions,answers,_,_=struct.unpack('!6H',packet[:12])
    if rid!=ident or not flags&32768 or flags&15 or flags&512 or questions!=1 or answers>128:raise ValueError('invalid DNS response')
    offset=skip_name(packet,12)+4;found=[]
    if offset>len(packet):raise ValueError('short DNS question')
    for _ in range(answers):
        offset=skip_name(packet,offset)
        if offset+10>len(packet):raise ValueError('short DNS record')
        kind,cls,ttl,size=struct.unpack('!HHIH',packet[offset:offset+10]);offset+=10
        if offset+size>len(packet):raise ValueError('short DNS data')
        if kind==1 and cls==1 and size==4:found.append(socket.inet_ntoa(packet[offset:offset+4]))
        offset+=size
    return sorted(set(found))

def lookup(host,resolver):
    labels=host.rstrip('.').encode('idna').split(b'.')
    if not labels or any(not x or len(x)>63 for x in labels) or sum(map(len,labels))>253:raise ValueError('invalid hostname')
    ident=secrets.randbelow(65536)
    question=struct.pack('!6H',ident,256,1,0,0,0)+b''.join(bytes([len(x)])+x for x in labels)+b'\0\0\1\0\1'
    address=ipaddress.ip_address(resolver);family=socket.AF_INET6 if address.version==6 else socket.AF_INET
    with socket.socket(family,socket.SOCK_DGRAM) as sock:
        sock.settimeout(2);sock.connect((resolver,53));sock.send(question);packet=sock.recv(65535)
    if len(packet)>=4 and struct.unpack('!H',packet[2:4])[0]&512:
        with socket.socket(family,socket.SOCK_STREAM) as sock:
            sock.settimeout(2);sock.connect((resolver,53));sock.sendall(struct.pack('!H',len(question))+question)
            def read(size):
                data=b''
                while len(data)<size:
                    chunk=sock.recv(size-len(data))
                    if not chunk:raise ValueError('short DNS TCP response')
                    data+=chunk
                return data
            packet=read(struct.unpack('!H',read(2))[0])
    return parse_answer(packet,ident)

def system_resolver():
    with open('/etc/resolv.conf') as stream:
        for line in stream:
            parts=line.split()
            if len(parts)>=2 and parts[0]=='nameserver':return str(ipaddress.ip_address(parts[1]))
    raise ValueError('configure resolver in observer JSON')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    with open(args.config) as stream:config=json.load(stream)
    url=config['url'].rstrip('/');parts=urllib.parse.urlsplit(url)
    if parts.scheme!='https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:raise SystemExit('use an HTTPS panel origin')
    token=config['token'];resolver=str(ipaddress.ip_address(config.get('resolver') or system_resolver()))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)
    def api(path,data=None):
        req=urllib.request.Request(url+path,data=json.dumps(data).encode() if data is not None else None,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with opener.open(req,timeout=5) as response:return json.loads(response.read(65536))
    while True:
        started=time.monotonic()
        try:
            for job in api('/api/rotation-observer/jobs')['jobs']:
                failed=False
                try:answers=lookup(job['hostname'],resolver)
                except (OSError,ValueError):answers=[];failed=True
                if job['id']:api('/api/rotation-observer/results',{'trial_id':job['id'],'answers':answers,'resolver':resolver,'error':failed})
        except Exception:
            # Do not print tokens, URLs or response payloads.
            print('DNS observer: request failed; retrying',flush=True)
        time.sleep(max(0,5-(time.monotonic()-started)))

if __name__=='__main__':main()
