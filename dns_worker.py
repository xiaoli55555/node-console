"""Run one dedicated worker: python dns_worker.py (Compose starts it automatically)."""
import time
import server
from detectors import tick as detection_tick, execute_change_ip_actions
from ip_dns import run_binding, check_monitor, IntegrationError
from rotation import tick as rotation_tick, expedite_recovery_probes
from rotation_insights import collect_reports

def tick():
    with server.connect() as db:
        monitors=[r[0] for r in db.execute('SELECT server_id FROM ip_monitors WHERE enabled=1')]
    for sid in monitors:
        try:check_monitor(server.connect,sid,server.CIPHER)
        except Exception:print('IP monitor: check failed for server #'+str(sid),flush=True)
    from server_failover import tick as failover_tick
    try:failover_tick(server.connect,server.CIPHER)
    except BlockingIOError:pass
    with server.connect() as db:
        ids=[r[0] for r in db.execute('SELECT dns_bindings.id FROM dns_bindings JOIN ip_monitors ON ip_monitors.server_id=dns_bindings.server_id WHERE automatic=1 AND ip_monitors.enabled=1')]
    for bid in ids:
        try:run_binding(server.connect,server.CIPHER,bid,apply=True)
        except IntegrationError:pass # Safe status is available to admins, no credentials in logs.
        except Exception:print('DNS worker: internal error for binding #'+str(bid),flush=True)

def rotation_detection_cycle():
    try:detection_tick(server.connect,server.CIPHER)
    except Exception:print('Detection worker: cycle failed',flush=True)
    try:
        rotation_tick(server.connect,server.CIPHER)
        # Bounded submit/poll/confirm passes only for a failed carrier whose
        # partner is mid-repair. Normal schedules and unrelated actions retain
        # their cadence; no sleeps, unbounded loops or duplicate probe POSTs.
        for _ in range(3):
            rotations,servers=expedite_recovery_probes(server.connect,server.CIPHER)
            if not rotations:break
            if servers:detection_tick(server.connect,server.CIPHER,server_ids=servers)
            rotation_tick(server.connect,server.CIPHER,rotation_ids=rotations)
    except BlockingIOError:pass
    except Exception:print('VPS rotation: cycle failed',flush=True)


if __name__=='__main__':
    while True:
        try:tick()
        except Exception:print('DNS worker: cycle failed',flush=True)
        rotation_detection_cycle()
        try:collect_reports(server.connect)
        except Exception:print("Rotation report: collection failed",flush=True)
        # Keep normal monitoring cadence, while failed-target guards advance at 1 s.
        import detection_recheck
        for _ in range(5):
            try:
                if detection_recheck.tick(server.connect,server.CIPHER):
                    rotation_tick(server.connect,server.CIPHER)
                    execute_change_ip_actions(server.connect,server.CIPHER)
            except Exception:print('Reference check: cycle failed',flush=True)
            time.sleep(1)
