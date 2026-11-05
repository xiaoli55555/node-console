#!/usr/bin/env python3
"""Outbound-only panel worker and standalone TCP diagnostic."""
import argparse
import os
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
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


def load_pending(path):
    try:
        data = json.loads(path.read_text())
        return {k: v for k, v in data.items() if time.time()-v['created'] <= 120}
    except FileNotFoundError:
        return {}


def save_pending(path, pending):
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(pending, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


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

    state_dir = Path(os.environ.get('STATE_DIRECTORY') or config.get('state_dir', '/var/lib/hksdan-probe'))
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    scope = hashlib.sha256((url+'|'+config['token']).encode()).hexdigest()
    state_file = state_dir / ('pending-'+scope+'.json')
    pending = load_pending(state_file)
    active = {}
    uploads = {}
    workers = max(1, min(8, int(config.get('max_workers', 4))))
    with ThreadPoolExecutor(max_workers=workers*2) as pool:
        while True:
            for rid, (job, future) in list(active.items()):
                if not future.done():continue
                try:
                    pending[str(rid)] = {'result': future.result(), 'created': time.time()}
                    save_pending(state_file, pending)
                except Exception as exc:
                    print('Measurement failed: '+type(exc).__name__, flush=True)
                del active[rid]
            # Uploads run independently so a slow panel request cannot block other results.
            for rid, future in list(uploads.items()):
                if not future.done():continue
                discard = False
                try:
                    future.result()
                    print(json.dumps({'job_id': int(rid), **pending[rid]['result']}), flush=True)
                    discard = True
                except urllib.error.HTTPError as exc:
                    discard = exc.code in (400, 404, 409)
                    print('Upload HTTP error '+str(exc.code), flush=True)
                except Exception as exc:
                    print('Upload failed: '+type(exc).__name__+'; saved for retry', flush=True)
                del uploads[rid]
                if discard:
                    del pending[rid]
                    save_pending(state_file, pending)
            for rid, item in list(pending.items()):
                if rid in uploads:continue
                if time.time()-item['created'] > 120:
                    del pending[rid]
                    save_pending(state_file, pending)
                else:
                    uploads[rid] = pool.submit(post, '/api/probe/results/'+rid, item['result'])
            if len(active)+len(pending) < workers:
                try:
                    job = post('/api/probe/jobs', {}).get('job')
                    if job and int(job['id']) not in active and str(job['id']) not in pending:
                        active[int(job['id'])] = (job, pool.submit(measure, job['ip'], job['port']))
                except urllib.error.HTTPError as exc:
                    print('Poll HTTP error '+str(exc.code)+'; check source/token', flush=True)
                except Exception as exc:
                    print('Poll failed: '+type(exc).__name__+'; retrying', flush=True)
            time.sleep(poll)


if __name__ == '__main__':
    raise SystemExit(main())
