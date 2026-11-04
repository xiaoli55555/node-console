#!/usr/bin/env python3
"""Outbound-only panel worker and standalone TCP diagnostic."""
import argparse
import ipaddress
import json
import socket
import time
import urllib.parse
import urllib.error
import urllib.request


def measure(ip, port, timeout=5):
    ip = ipaddress.ip_address(ip)
    if ip.version != 4 or not ip.is_global or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('target must be a public IPv4 and a valid TCP port')
    attempts = []
    for _ in range(2):
        start = time.monotonic()
        try:
            with socket.create_connection((str(ip), port), timeout=timeout):
                pass
            attempts.append({'state': 'reachable', 'latency_ms': round((time.monotonic()-start)*1000, 2)})
        except ConnectionRefusedError:
            attempts.append({'state': 'refused', 'latency_ms': None})
        except (TimeoutError, socket.timeout):
            attempts.append({'state': 'timeout', 'latency_ms': None})
        except OSError:
            attempts.append({'state': 'network_error', 'latency_ms': None})
        if attempts[-1]['state'] == 'reachable':
            break
    good = next((a for a in attempts if a['state'] == 'reachable'), None)
    return {'ip': str(ip), 'port': port, 'reachable': good is not None,
            'latency_ms': good['latency_ms'] if good else None, 'attempts': attempts}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', nargs='?')
    parser.add_argument('--test', nargs=2, metavar=('IP', 'PORT'))
    args = parser.parse_args()
    if args.test:
        result = measure(args.test[0], int(args.test[1]))
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result['reachable'] else 1
    if not args.config:
        parser.error('provide config path or --test IP PORT')
    with open(args.config, encoding='utf-8') as f:
        config = json.load(f)
    url = config['panel_url'].rstrip('/')
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('panel_url must be a credential-free HTTPS URL')
    poll = max(1, min(10, float(config.get('poll_interval_s', 2))))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def post(path, data):
        req = urllib.request.Request(url+path, data=json.dumps(data).encode(), headers={
            'Authorization': 'Bearer '+config['token'], 'Content-Type': 'application/json'})
        with opener.open(req, timeout=15) as response:
            return json.load(response)

    pending = None
    while True:
        try:
            if pending is None:
                job = post('/api/probe/jobs', {}).get('job')
                if job:
                    result = measure(job['ip'], job['port'])
                    pending = (int(job['id']), result, time.monotonic())
            if pending:
                rid, result, created = pending
                if time.monotonic()-created > 60:
                    print('Result expired; discarded (not a target failure)', flush=True)
                    pending = None
                else:
                    post('/api/probe/results/'+str(rid), result)
                    print(json.dumps({'job_id': rid, **result}), flush=True)
                    pending = None
        except urllib.error.HTTPError as exc:
            print('Panel HTTP error '+str(exc.code)+'; check source/token/connectivity', flush=True)
            if exc.code in (400, 404, 409):
                pending = None
        except Exception as exc:
            # Never log URLs, headers, tokens or server response bodies.
            print('Probe cycle failed: '+type(exc).__name__+'; retrying', flush=True)
        time.sleep(poll)


if __name__ == '__main__':
    raise SystemExit(main())
