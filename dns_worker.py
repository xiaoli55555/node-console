"""Run one dedicated worker: python dns_worker.py (Compose starts it automatically)."""
import time
import server
from ip_dns import run_binding, check_monitor, IntegrationError

def tick():
    with server.connect() as db:
        monitors=[r[0] for r in db.execute('SELECT server_id FROM ip_monitors WHERE enabled=1')]
    for sid in monitors:
        try:check_monitor(server.connect,sid,server.CIPHER)
        except Exception:print('IP monitor: check failed for server #'+str(sid),flush=True)
    with server.connect() as db:
        ids=[r[0] for r in db.execute('SELECT dns_bindings.id FROM dns_bindings JOIN ip_monitors ON ip_monitors.server_id=dns_bindings.server_id WHERE automatic=1 AND ip_monitors.enabled=1')]
    for bid in ids:
        try:run_binding(server.connect,server.CIPHER,bid,apply=True)
        except IntegrationError:pass # Safe status is available to admins, no credentials in logs.
        except Exception:print('DNS worker: internal error for binding #'+str(bid),flush=True)

if __name__=='__main__':
    while True:
        try:tick()
        except Exception:print('DNS worker: cycle failed',flush=True)
        time.sleep(30)
