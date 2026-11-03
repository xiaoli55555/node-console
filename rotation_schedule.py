"""Validated, complete four-period drain thresholds in fixed UTC+8."""
import json
from ip_dns import IntegrationError

DEFAULT = {'enabled': False, 'boundaries': [180, 600, 1200], 'thresholds': [80, 20, 40, 80]}


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT):
        raise IntegrationError('分时排空配置必须包含开关、三个分界时间和四个阈值')
    bounds, limits = value['boundaries'], value['thresholds']
    if type(value['enabled']) is not bool or not isinstance(bounds, list) or len(bounds) != 3 or not isinstance(limits, list) or len(limits) != 4:
        raise IntegrationError('分时排空必须完整配置四个时段')
    if any(type(x) is not int for x in bounds) or not 0 < bounds[0] < bounds[1] < bounds[2] < 1440:
        raise IntegrationError('三个分界时间必须按顺序位于 00:00 与 24:00 之间，不允许空段或重叠')
    if any(type(x) is not int or not 1 <= x <= 10000 for x in limits):
        raise IntegrationError('每段 TCP 阈值必须是 1～10000 的整数')
    return {'enabled': value['enabled'], 'boundaries': list(bounds), 'thresholds': list(limits)}


def config(r):
    raw = r['drain_schedule']
    return validate(json.loads(raw)) if raw else validate(DEFAULT)


def effective(r, now):
    warning = None
    try:
        cfg = config(r)
    except (ValueError, TypeError, IntegrationError):
        cfg = validate(DEFAULT)
        warning = '分时排空配置异常，已使用默认 TCP 阈值；请检查配置'
    threshold = r['connection_threshold']
    if not cfg['enabled']:
        return {'threshold': threshold, 'label': '默认阈值', 'key': f'default:{threshold}', 'start': None, 'warning': warning}
    day = (now + 28800) // 86400
    minute = ((now + 28800) % 86400) // 60
    bounds = [0] + cfg['boundaries'] + [1440]
    index = next(i for i in range(4) if bounds[i] <= minute < bounds[i + 1])
    def fmt(m): return f'{m // 60:02}:{m % 60:02}'
    return {'threshold': cfg['thresholds'][index], 'label': f'{fmt(bounds[index])}–{fmt(bounds[index + 1])}（北京时间）',
            'key': json.dumps([day, index, cfg], sort_keys=True),
            'start': day * 86400 - 28800 + bounds[index] * 60, 'warning': warning}


def save(db, rid, cfg, now):
    raw = json.dumps(cfg, sort_keys=True)
    old = db.execute('SELECT * FROM vps_rotations WHERE id=?', (rid,)).fetchone()
    if old['drain_schedule'] == raw:
        return
    db.execute('UPDATE vps_rotations SET drain_schedule=?,drain_schedule_key=NULL,drain_schedule_after=?,low_samples=CASE WHEN emergency THEN low_samples ELSE 0 END,last_sample_at=NULL WHERE id=?', (raw, now, rid))


def sync(db, r, now):
    state = effective(r, now)
    # Legacy/default-only plans retain their existing sampling semantics.
    if r['drain_schedule_key'] != state['key']:
        if r['drain_schedule_key'] is not None or state['start'] is not None or r['drain_schedule_after'] is not None:
            db.execute('UPDATE vps_rotations SET low_samples=CASE WHEN emergency THEN low_samples ELSE 0 END,last_sample_at=NULL,drain_schedule_after=? WHERE id=?', (now, r['id']))
        db.execute('UPDATE vps_rotations SET drain_schedule_key=? WHERE id=?', (state['key'], r['id']))
        r = db.execute('SELECT * FROM vps_rotations WHERE id=?', (r['id'],)).fetchone()
    return r, state


def samples_current(r, now):
    state = effective(r, now)
    if state['start'] is None and r['drain_schedule_key'] is None and r['drain_schedule_after'] is None:
        return True
    return r['drain_schedule_key'] == state['key'] and r['last_sample_at'] is not None and (r['drain_schedule_after'] is None or r['last_sample_at'] > r['drain_schedule_after'])
