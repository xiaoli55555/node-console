"""Node Console: authenticated multi-tenant monitoring, SQLite, outbound-only agents."""
import os, sqlite3, secrets, hashlib, time, json, re, math, sys, ipaddress, calendar
from pathlib import Path
from datetime import date, datetime, time as datetime_time, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
from network import record_network, traffic_summary
from credential_store import load_cipher, InvalidToken
from flask import Flask, request, jsonify, g, send_from_directory, make_response
from werkzeug.security import generate_password_hash, check_password_hash

ROOT = Path(__file__).parent
DATA = Path(os.environ.get('DATA_DIR', ROOT / 'data'))
DATA.mkdir(parents=True, exist_ok=True)
SHANGHAI = ZoneInfo('Asia/Shanghai')
DB = DATA / 'panel.db'
SECURE = os.environ.get('COOKIE_SECURE', '1') == '1'
app = Flask(__name__, static_folder=None)
app.config['MAX_CONTENT_LENGTH'] = 32768

def connect():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def init():
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','client')));
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          csrf TEXT NOT NULL, expires INTEGER NOT NULL, entry TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS servers(id INTEGER PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER REFERENCES users(id),
          agent_hash TEXT UNIQUE NOT NULL, metrics TEXT, seen INTEGER, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS traffic_daily(server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          day TEXT NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL, PRIMARY KEY(server_id,day));
        CREATE TABLE IF NOT EXISTS network_points(server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          stamp INTEGER NOT NULL, rx_bps REAL, tx_bps REAL, PRIMARY KEY(server_id,stamp));
        CREATE TABLE IF NOT EXISTS ip_events(id INTEGER PRIMARY KEY,server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          addresses TEXT NOT NULL,observed INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS ip_events_server_time ON ip_events(server_id,observed);
        CREATE INDEX IF NOT EXISTS ip_events_server_id ON ip_events(server_id,id);
        CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY,server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id),action TEXT NOT NULL,status TEXT NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS commands_pending ON commands(server_id,status,created);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT OR IGNORE INTO settings(key,value) VALUES('admin_path','/admin');
        CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL, updated INTEGER NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL);
        CREATE TABLE IF NOT EXISTS client_subscriptions(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, starts_on TEXT NOT NULL, expires_on TEXT NOT NULL, cycle_months INTEGER NOT NULL CHECK(cycle_months BETWEEN 1 AND 60), updated_at INTEGER NOT NULL, updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, thread_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, content TEXT NOT NULL, created INTEGER NOT NULL, read_at INTEGER);
        CREATE TABLE IF NOT EXISTS forwarding_requests(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS messages_thread_order ON messages(thread_user_id,id);
        CREATE INDEX IF NOT EXISTS messages_recipient_unread ON messages(recipient_id,read_at);
        CREATE INDEX IF NOT EXISTS announcements_published ON announcements(published,created DESC);
        CREATE TABLE IF NOT EXISTS metric_points(server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          stamp INTEGER NOT NULL,cpu REAL,memory REAL,tcp REAL,udp REAL,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));
        CREATE TABLE IF NOT EXISTS install_tickets(hash TEXT PRIMARY KEY,server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
        PRAGMA user_version=11;
        ''')

        if 'password_encrypted' not in [r[1] for r in db.execute('PRAGMA table_info(users)')]:
            db.execute('ALTER TABLE users ADD COLUMN password_encrypted TEXT')
        if 'entry' not in [r[1] for r in db.execute('PRAGMA table_info(sessions)')]:
            db.execute("ALTER TABLE sessions ADD COLUMN entry TEXT NOT NULL DEFAULT ''")

def admin_path():
    with connect() as db:return db.execute("SELECT value FROM settings WHERE key='admin_path'").fetchone()[0]

def entry_context():
    path=request.headers.get('X-Panel-Entry','')
    if not path:return '', 'client', 'node_console'
    if path==admin_path():return path, 'admin', 'node_console_admin'
    return None,None,None

def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def error(msg, status=400): return jsonify(error=msg), status

def issue_install_ticket(db,sid):
    ticket=secrets.token_urlsafe(40);now=int(time.time())
    db.execute('DELETE FROM install_tickets WHERE server_id=? OR expires<?',(sid,now))
    db.execute('INSERT INTO install_tickets(hash,server_id,expires) VALUES(?,?,?)',(digest(ticket),sid,now+600))
    return ticket

def audit(db, action):
    db.execute('INSERT INTO audit(user_id,action,created) VALUES(?,?,?)', (g.user['id'], action, int(time.time())))

def auth(admin=False):
    def decorator(fn):
        @wraps(fn)
        def inner(*a, **kw):
            entry,required_role,cookie=entry_context()
            if entry is None:return error('入口不存在',404)
            with connect() as db:
                row = db.execute('SELECT users.*,sessions.csrf FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>? AND entry=?',
                                 (digest(request.cookies.get(cookie, '')), int(time.time()),entry)).fetchone()
            if not row or row['role']!=required_role: return error('请先登录', 401)
            g.user = dict(row)
            g.cookie=cookie
            g.entry=entry
            if admin and row['role'] != 'admin': return error('没有管理员权限', 403)
            if request.method not in ('GET','HEAD') and not secrets.compare_digest(request.headers.get('X-CSRF-Token',''), row['csrf']):
                return error('请求校验失败，请刷新页面', 403)
            return fn(*a, **kw)
        return inner
    return decorator

def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return {}
    return data

def throttled(key, limit=10, window=900):
    now = int(time.time())
    with connect() as db:
        db.execute('DELETE FROM attempts WHERE expires<?', (now,))
        db.execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1', (key,now+window))
        return db.execute('SELECT count FROM attempts WHERE key=?', (key,)).fetchone()[0] > limit

@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options']='nosniff'
    r.headers['X-Frame-Options']='DENY'
    r.headers['Referrer-Policy']='no-referrer'
    r.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.path.startswith('/api/'): r.headers['Cache-Control']='no-store'
    return r

@app.get('/health')
def health():
    with connect() as db: db.execute('SELECT 1').fetchone()
    return jsonify(ok=True, version='0.3.2')

@app.post('/api/login')
def login():
    entry,required_role,cookie=entry_context()
    if entry is None:return error('入口不存在',404)
    data=body(); name=str(data.get('username',''))[:64]; password=str(data.get('password',''))[:1024]
    # Do not trust X-Forwarded-For; proxy traffic also has a global safety ceiling.
    if throttled('login:'+digest(name)) or throttled('login-global', 200): return error('尝试次数过多，请 15 分钟后再试',429)
    with connect() as db:
        u=db.execute('SELECT * FROM users WHERE username=?',(name,)).fetchone()
        candidate=u['password'] if u else generate_password_hash('dummy-value')
        if not check_password_hash(candidate,password) or not u or u['role']!=required_role: return error('账号或密码不正确',401)
        token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); now=int(time.time())
        db.execute('DELETE FROM sessions WHERE expires<?',(now,))
        db.execute('DELETE FROM attempts WHERE key=?',('login:'+digest(name),))
        db.execute('INSERT INTO sessions(token,user_id,csrf,expires,entry) VALUES(?,?,?,?,?)',(digest(token),u['id'],csrf,now+43200,entry))
    r=jsonify(ok=True); r.set_cookie(cookie,token,max_age=43200,secure=SECURE,httponly=True,samesite='Strict')
    return r

@app.get('/api/entry')
def get_entry():
    entry,role,cookie=entry_context()
    if entry is None:return error('入口不存在',404)
    return jsonify(kind=role)

@app.get('/api/announcements')
@auth()
def get_announcements():
    with connect() as db:
        rows=db.execute('SELECT id,title,content,created,updated FROM announcements WHERE published=1 ORDER BY created DESC,id DESC LIMIT 20').fetchall()
    return jsonify([dict(r) for r in rows])

@app.get('/api/admin/announcements')
@auth(True)
def manage_announcements():
    with connect() as db:
        rows=db.execute('SELECT id,title,content,published,created,updated,user_id FROM announcements ORDER BY created DESC,id DESC LIMIT 100').fetchall()
    return jsonify([dict(r) for r in rows])

def validate_announcement(data, current=None):
    title=data.get('title',current['title'] if current else '')
    content=data.get('content',current['content'] if current else '')
    published=data.get('published',bool(current['published']) if current else True)
    if not isinstance(title,str) or not title.strip() or len(title.strip())>80:return None,error('公告标题不能为空，且不能超过 80 个字符')
    if not isinstance(content,str) or not content.strip() or len(content.strip())>2000:return None,error('公告内容不能为空，且不能超过 2000 个字符')
    if type(published) is not bool:return None,error('发布状态无效')
    return (title.strip(),content.strip(),int(published)),None

@app.post('/api/announcements')
@auth(True)
def create_announcement():
    fields,problem=validate_announcement(body())
    if problem:return problem
    title,content,published=fields;now=int(time.time())
    with connect() as db:
        cur=db.execute('INSERT INTO announcements(title,content,published,created,updated,user_id) VALUES(?,?,?,?,?,?)',(title,content,published,now,now,g.user['id']))
        aid=cur.lastrowid;audit(db,('发布' if published else '保存')+'公告 #'+str(aid)+' '+title[:80])
    return jsonify(ok=True,id=aid),201

@app.patch('/api/announcements/<int:aid>')
@auth(True)
def edit_announcement(aid):
    with connect() as db:
        current=db.execute('SELECT * FROM announcements WHERE id=?',(aid,)).fetchone()
        if not current:return error('公告不存在',404)
        fields,problem=validate_announcement(body(),current)
        if problem:return problem
        title,content,published=fields
        db.execute('UPDATE announcements SET title=?,content=?,published=?,updated=? WHERE id=?',(title,content,published,int(time.time()),aid))
        audit(db,('发布' if published else '撤回')+'公告 #'+str(aid)+' '+title[:80])
    return jsonify(ok=True,id=aid)

@app.delete('/api/announcements/<int:aid>')
@auth(True)
def delete_announcement(aid):
    with connect() as db:
        row=db.execute('SELECT title FROM announcements WHERE id=?',(aid,)).fetchone()
        if not row:return error('公告不存在',404)
        db.execute('DELETE FROM announcements WHERE id=?',(aid,));audit(db,'删除公告 #'+str(aid)+' '+row['title'][:80])
    return jsonify(ok=True)

def validate_message_client(db, uid):
    client=db.execute("SELECT id,username FROM users WHERE id=? AND role='client'",(uid,)).fetchone()
    if not client:return None
    if g.user['role']=='client' and g.user['id']!=uid:return None
    return client

@app.get('/api/messages/unread')
@auth()
def unread_messages():
    with connect() as db:
        if g.user['role']=='admin':count=db.execute("SELECT COUNT(*) FROM messages WHERE recipient_id IN (SELECT id FROM users WHERE role='admin') AND read_at IS NULL").fetchone()[0]
        else:count=db.execute('SELECT COUNT(*) FROM messages WHERE recipient_id=? AND read_at IS NULL',(g.user['id'],)).fetchone()[0]
    return jsonify(unread=count)

@app.get('/api/messages/threads')
@auth(True)
def message_threads():
    with connect() as db:
        rows=db.execute('''SELECT u.id user_id,u.username,
          (SELECT content FROM messages m WHERE m.thread_user_id=u.id ORDER BY m.id DESC LIMIT 1) last_content,
          (SELECT created FROM messages m WHERE m.thread_user_id=u.id ORDER BY m.id DESC LIMIT 1) last_created,
          (SELECT sender_id FROM messages m WHERE m.thread_user_id=u.id ORDER BY m.id DESC LIMIT 1) last_sender_id,
          (SELECT COUNT(*) FROM messages m WHERE m.thread_user_id=u.id AND m.recipient_id IN (SELECT id FROM users WHERE role='admin') AND m.read_at IS NULL) unread
          FROM users u WHERE u.role='client' ORDER BY COALESCE(last_created,0) DESC,u.username COLLATE NOCASE''').fetchall()
    return jsonify([dict(r) for r in rows])

@app.get('/api/messages/threads/<int:uid>')
@auth()
def get_message_thread(uid):
    with connect() as db:
        client=validate_message_client(db,uid)
        if not client:return error('会话不存在或无权查看',404)
        if g.user['role']=='admin':db.execute("UPDATE messages SET read_at=? WHERE thread_user_id=? AND recipient_id IN (SELECT id FROM users WHERE role='admin') AND read_at IS NULL",(int(time.time()),uid))
        else:db.execute('UPDATE messages SET read_at=? WHERE thread_user_id=? AND recipient_id=? AND read_at IS NULL',(int(time.time()),uid,g.user['id']))
        rows=db.execute('''SELECT m.id,m.sender_id,m.recipient_id,m.content,m.created,m.read_at,u.username sender_name
          FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.thread_user_id=? ORDER BY m.id ASC LIMIT 500''',(uid,)).fetchall()
    return jsonify(user_id=uid,username=client['username'],messages=[dict(r) for r in rows])

@app.post('/api/messages/threads/<int:uid>')
@auth()
def send_thread_message(uid):
    data=body();content=data.get('content')
    if not isinstance(content,str) or not content.strip() or len(content.strip())>2000:return error('消息不能为空，且不能超过 2000 个字符')
    if throttled('message:'+str(g.user['id']),20,60):return error('发送过于频繁，请稍后再试',429)
    with connect() as db:
        client=validate_message_client(db,uid)
        if not client:return error('会话不存在或无权发送',404)
        if g.user['role']=='client':
            admin=db.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
            if not admin:return error('暂时无法联系管理员',503)
            recipient=admin['id']
        else:recipient=uid
        now=int(time.time())
        cur=db.execute('INSERT INTO messages(thread_user_id,sender_id,recipient_id,content,created) VALUES(?,?,?,?,?)',(uid,g.user['id'],recipient,content.strip(),now))
        row=db.execute('SELECT m.id,m.sender_id,m.recipient_id,m.content,m.created,m.read_at,u.username sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?',(cur.lastrowid,)).fetchone()
    return jsonify(ok=True,message=dict(row)),201

@app.get('/api/forwarding-request')
@auth()
def get_forwarding_request():
    if g.user['role']!='client':return error('仅客户账号可查看申请状态',403)
    with connect() as db:
        row=db.execute('SELECT id,created FROM forwarding_requests WHERE user_id=?',(g.user['id'],)).fetchone()
    return jsonify(dict(row) if row else {'id':None,'created':None})

@app.post('/api/forwarding-request')
@auth()
def submit_forwarding_request():
    if g.user['role']!='client':return error('仅客户账号可提交申请',403)
    now=int(time.time())
    with connect() as db:
        inserted=db.execute('INSERT OR IGNORE INTO forwarding_requests(user_id,created) VALUES(?,?)',(g.user['id'],now)).rowcount
        row=db.execute('SELECT id,created FROM forwarding_requests WHERE user_id=?',(g.user['id'],)).fetchone()
    return jsonify(ok=True,already_submitted=inserted==0,**dict(row)),(201 if inserted else 200)

@app.get('/api/admin/forwarding-requests')
@auth(True)
def list_forwarding_requests():
    with connect() as db:
        rows=db.execute('SELECT r.id,r.created,u.id user_id,u.username FROM forwarding_requests r JOIN users u ON u.id=r.user_id ORDER BY r.created DESC,r.id DESC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.get('/api/settings')
@auth(True)
def get_settings():return jsonify(admin_path=admin_path())

@app.patch('/api/settings')
@auth(True)
def update_settings():
    value=body().get('admin_path','')
    reserved={'api','health','agent.py','agent-install.sh','agent-update.sh','app.js','style.css','password.js'}
    if not isinstance(value,str) or not re.fullmatch(r'/[A-Za-z0-9][A-Za-z0-9/_-]{2,79}',value) or value.endswith('/') or '//' in value or value.split('/')[1] in reserved:
        return error('路径需以 / 开头，3～80 位英文、数字、下划线或短横线，可分层；不能使用系统保留路径')
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute("SELECT value FROM settings WHERE key='admin_path'").fetchone()[0]!=g.entry:return error('入口已被其他管理员修改，请重新登录',409)
        if value==g.entry:return jsonify(ok=True,changed=False,admin_path=value)
        db.execute("UPDATE settings SET value=? WHERE key='admin_path'",(value,))
        db.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE role='admin')")
        audit(db,'修改管理员登录入口')
    r=jsonify(ok=True,changed=True,admin_path=value);r.delete_cookie(g.cookie,secure=SECURE,httponly=True,samesite='Strict');return r

@app.get('/api/me')
@auth()
def me(): return jsonify(id=g.user['id'], username=g.user['username'],role=g.user['role'],csrf=g.user['csrf'])

@app.post('/api/logout')
@auth()
def logout():
    with connect() as db: db.execute('DELETE FROM sessions WHERE token=?',(digest(request.cookies.get(g.cookie,'')),))
    r=jsonify(ok=True);r.delete_cookie(g.cookie,secure=SECURE,httponly=True,samesite='Strict');return r

@app.post('/api/password')
@auth()
def password():
    d=body(); new=d.get('new',''); old=d.get('old','')
    if not isinstance(new,str) or not 12<=len(new)<=128: return error('新密码需为 12～128 位')
    if not isinstance(old,str) or not check_password_hash(g.user['password'],old): return error('原密码不正确',403)
    with connect() as db:
        db.execute('UPDATE users SET password=?,password_encrypted=? WHERE id=?',(generate_password_hash(new),CIPHER.encrypt(new.encode()).decode() if g.user['role']=='client' else None,g.user['id']))
        db.execute('DELETE FROM sessions WHERE user_id=?',(g.user['id'],));audit(db,'修改登录密码')
    r=jsonify(ok=True);r.delete_cookie(g.cookie,secure=SECURE);return r

def shanghai_today():
    return datetime.now(SHANGHAI).date()

def add_calendar_months(day, months):
    total=day.year*12+(day.month-1)+months
    year,month=divmod(total,12);month+=1
    return date(year,month,min(day.day,calendar.monthrange(year,month)[1]))

def date_midnight_epoch(day):
    return int(datetime.combine(day,datetime_time.min,tzinfo=SHANGHAI).timestamp())

def subscription_payload(row):
    if not row:return {'starts_on':None,'expires_on':None,'cycle_months':None,'starts_at':None,'expires_at':None,'remaining_seconds':None,'server_now':int(time.time())}
    start=date.fromisoformat(row['starts_on']);expiry=date.fromisoformat(row['expires_on'])
    expires_at=int(datetime.combine(expiry+timedelta(days=1),datetime_time.min,tzinfo=SHANGHAI).timestamp())
    starts_at=date_midnight_epoch(start);now=int(time.time())
    return {'starts_on':row['starts_on'],'expires_on':row['expires_on'],'cycle_months':row['cycle_months'],'starts_at':starts_at,'expires_at':expires_at,'remaining_seconds':max(0,expires_at-now),'server_now':now}

def client_subscription_row(db,uid):
    return db.execute('SELECT starts_on,expires_on,cycle_months,updated_at FROM client_subscriptions WHERE user_id=?',(uid,)).fetchone()

@app.get('/api/subscription')
@auth()
def own_subscription():
    if g.user['role']!='client':return error('仅客户账号有个人服务期限',403)
    with connect() as db:return jsonify(subscription_payload(client_subscription_row(db,g.user['id'])))

@app.get('/api/users/<int:uid>/subscription')
@auth(True)
def get_client_subscription(uid):
    with connect() as db:
        if not db.execute("SELECT 1 FROM users WHERE id=? AND role='client'",(uid,)).fetchone():return error('客户不存在',404)
        row=client_subscription_row(db,uid)
    return jsonify(subscription_payload(row))

@app.patch('/api/users/<int:uid>/subscription')
@auth(True)
def set_client_subscription(uid):
    data=body();expires_on=data.get('expires_on');months=data.get('cycle_months')
    if not isinstance(expires_on,str):return error('请选择有效的到期日期')
    try:expiry=date.fromisoformat(expires_on)
    except ValueError:return error('到期日期格式无效')
    if expiry.isoformat()!=expires_on:return error('到期日期格式无效')
    if type(months) is not int or not 1<=months<=60:return error('续费周期需为 1～60 个自然月')
    now=int(time.time());today=shanghai_today();starts=(today if expiry>=today else expiry).isoformat()
    with connect() as db:
        if not db.execute("SELECT 1 FROM users WHERE id=? AND role='client'",(uid,)).fetchone():return error('客户不存在',404)
        db.execute('INSERT INTO client_subscriptions(user_id,starts_on,expires_on,cycle_months,updated_at,updated_by) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET starts_on=excluded.starts_on,expires_on=excluded.expires_on,cycle_months=excluded.cycle_months,updated_at=excluded.updated_at,updated_by=excluded.updated_by',(uid,starts,expiry.isoformat(),months,now,g.user['id']))
        audit(db,f'设置客户 #{uid} 服务到期日 {expiry.isoformat()}，周期 {months} 个自然月')
        row=client_subscription_row(db,uid)
    return jsonify(ok=True,**subscription_payload(row))

@app.post('/api/users/<int:uid>/subscription/renew')
@auth(True)
def renew_client_subscription(uid):
    now=int(time.time());today=shanghai_today()
    with connect() as db:
        row=client_subscription_row(db,uid)
        if not db.execute("SELECT 1 FROM users WHERE id=? AND role='client'",(uid,)).fetchone():return error('客户不存在',404)
        if not row:return error('请先为客户设置到期日期和续费周期')
        current_expiry=date.fromisoformat(row['expires_on']);base=current_expiry if current_expiry>=today else today
        expiry=add_calendar_months(base,row['cycle_months'])
        db.execute('UPDATE client_subscriptions SET starts_on=?,expires_on=?,updated_at=?,updated_by=? WHERE user_id=?',(base.isoformat(),expiry.isoformat(),now,g.user['id'],uid))
        audit(db,f'为客户 #{uid} 按 {row["cycle_months"]} 个自然月续期至 {expiry.isoformat()}')
        updated=client_subscription_row(db,uid)
    return jsonify(ok=True,**subscription_payload(updated))

@app.delete('/api/users/<int:uid>/subscription')
@auth(True)
def clear_client_subscription(uid):
    with connect() as db:
        if not db.execute("SELECT 1 FROM users WHERE id=? AND role='client'",(uid,)).fetchone():return error('客户不存在',404)
        db.execute('DELETE FROM client_subscriptions WHERE user_id=?',(uid,));audit(db,f'清除客户 #{uid} 服务期限')
    return jsonify(ok=True)

@app.get('/api/users')
@auth(True)
def users():
    with connect() as db: return jsonify([dict(x) for x in db.execute('SELECT u.id,u.username,u.role,s.expires_on,s.cycle_months FROM users u LEFT JOIN client_subscriptions s ON s.user_id=u.id ORDER BY u.id')])

@app.post('/api/users')
@auth(True)
def add_user():
    d=body(); name=d.get('username',''); pw=d.get('password','')
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{3,64}',name): return error('账号需为 3～64 位英文、数字或 _.@-')
    if not isinstance(pw,str) or not 12<=len(pw)<=128: return error('密码需为 12～128 位')
    try:
        with connect() as db:
            db.execute('INSERT INTO users(username,password,role,password_encrypted) VALUES(?,?,?,?)',(name,generate_password_hash(pw),'client',CIPHER.encrypt(pw.encode()).decode()));audit(db,'创建客户 '+name)
    except sqlite3.IntegrityError: return error('账号已存在',409)
    return jsonify(ok=True),201

@app.post('/api/users/<int:uid>/credentials')
@auth(True)
def client_credentials(uid):
    with connect() as db:
        user=db.execute("SELECT username,password_encrypted FROM users WHERE id=? AND role='client'",(uid,)).fetchone()
        if not user:return error('客户不存在',404)
        password=None
        if user['password_encrypted']:
            try:password=CIPHER.decrypt(user['password_encrypted'].encode()).decode()
            except InvalidToken:return error('密码解密失败，请检查数据库匹配的 credential.key',500)
        audit(db,f'查看客户 #{uid} 凭据')
    return jsonify(username=user['username'],password=password,recoverable=password is not None)

@app.patch('/api/users/<int:uid>')
@auth(True)
def edit_client(uid):
    data=body();pw=data.get('password')
    if pw is not None and (not isinstance(pw,str) or not 12<=len(pw)<=128):return error('密码需为 12～128 位')
    try:
        with connect() as db:
            user=db.execute("SELECT username FROM users WHERE id=? AND role='client'",(uid,)).fetchone()
            if not user:return error('客户不存在',404)
            name=data.get('username',user['username'])
            if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{3,64}',name):return error('账号需为 3～64 位英文、数字或 _.@-')
            if pw is None:db.execute('UPDATE users SET username=? WHERE id=?',(name,uid))
            else:db.execute('UPDATE users SET username=?,password=?,password_encrypted=? WHERE id=?',(name,generate_password_hash(pw),CIPHER.encrypt(pw.encode()).decode(),uid))
            db.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
            audit(db,f'修改客户 #{uid} 账号或密码')
    except sqlite3.IntegrityError:return error('账号已存在',409)
    return jsonify(ok=True,username=name)

@app.get('/api/servers')
@auth()
def servers():
    with connect() as db:
        sql='SELECT servers.*,users.username AS owner FROM servers LEFT JOIN users ON users.id=servers.owner_id'
        rows=db.execute(sql+('' if g.user['role']=='admin' else ' WHERE owner_id=?')+' ORDER BY servers.id',() if g.user['role']=='admin' else (g.user['id'],)).fetchall()
    result=[];now=int(time.time())
    for row in rows:
        x=dict(row);x.pop('agent_hash');x['metrics']=json.loads(x['metrics']) if x['metrics'] else None
        x['online']=bool(x['seen'] and now-x['seen']<=60)
        with connect() as summary_db:
            x['traffic']=traffic_summary(summary_db,x['id'],now)
            command=summary_db.execute('SELECT id,status,created,updated FROM commands WHERE server_id=? ORDER BY id DESC LIMIT 1',(x['id'],)).fetchone()
            x['last_command']=dict(command) if command else None
        result.append(x)
    return jsonify(result)

@app.post('/api/servers')
@auth(True)
def add_server():
    d=body();name=d.get('name','')
    if not isinstance(name,str) or not 1<=len(name.strip())<=64: return error('服务器名称需为 1～64 字符')
    token=secrets.token_urlsafe(40)
    with connect() as db:
        c=db.execute('INSERT INTO servers(name,agent_hash,created) VALUES(?,?,?)',(name.strip(),digest(token),int(time.time())))
        audit(db,'添加服务器 '+name)
        ticket=issue_install_ticket(db,c.lastrowid)
    return jsonify(id=c.lastrowid,token=token,ticket=ticket),201

@app.patch('/api/servers/<int:sid>')
@auth(True)
def assign(sid):
    owner=body().get('owner_id')
    if owner is not None and type(owner) is not int:return error('客户编号无效')
    with connect() as db:
        current=db.execute('SELECT id,owner_id FROM servers WHERE id=?',(sid,)).fetchone()
        if not current:return error('服务器不存在',404)
        if owner is not None and not db.execute("SELECT id FROM users WHERE id=? AND role='client'",(owner,)).fetchone():return error('客户不存在')
        if current['owner_id']!=owner and current['owner_id'] is not None:
            private=db.execute('SELECT id FROM detection_sources WHERE owner_id=? AND server_id=?',(current['owner_id'],sid)).fetchall()
            private_ids=[r['id'] for r in private]
            if private_ids:
                marks=','.join('?' for _ in private_ids)
                empty_secret=CIPHER.encrypt(b'').decode()
                db.execute('UPDATE detection_sources SET enabled=0,secret=?,verified_at=NULL WHERE id IN ('+marks+')',(empty_secret,*private_ids))
                db.execute("UPDATE detection_plans SET automatic=0,action_enabled=0,response_mode='none',action_connection_id=NULL,failure_streak=0,failure_ip=NULL,failure_port=NULL,status='客户变更，等待新探测配置' WHERE server_id=? AND source_id IN ("+marks+")",(sid,*private_ids))
                db.execute("UPDATE detection_runs SET action_status='cancelled',action_result='服务器归属已变更，旧客户的探测 Key 已停用' WHERE server_id=? AND source_id IN ("+marks+") AND action_status IN ('queued','issued','submitted','uncertain','verifying')",(sid,*private_ids))
        db.execute('UPDATE servers SET owner_id=? WHERE id=?',(owner,sid));audit(db,f'服务器 #{sid} 分配给客户 #{owner}')
    return jsonify(ok=True)

@app.post('/api/servers/<int:sid>/rotate')
@auth(True)
def rotate(sid):
    token=secrets.token_urlsafe(40)
    with connect() as db:
        if not db.execute('UPDATE servers SET agent_hash=? WHERE id=?',(digest(token),sid)).rowcount:return error('服务器不存在',404)
        audit(db,f'重置服务器 #{sid} 采集密钥')
        ticket=issue_install_ticket(db,sid)
    return jsonify(token=token,ticket=ticket)

@app.post('/api/servers/<int:sid>/install-ticket')
@auth(True)
def create_install_ticket(sid):
    with connect() as db:
        if not db.execute('SELECT id FROM servers WHERE id=?',(sid,)).fetchone():return error('服务器不存在',404)
        ticket=issue_install_ticket(db,sid);audit(db,f'生成服务器 #{sid} 一次性接入命令')
    return jsonify(ticket=ticket)

@app.delete('/api/servers/<int:sid>')
@auth(True)
def delete(sid):
    with connect() as db:
        db.execute('DELETE FROM servers WHERE id=?',(sid,));audit(db,f'移除服务器 #{sid}')
    return jsonify(ok=True)

@app.get('/api/audit')
@auth(True)
def logs():
    with connect() as db:return jsonify([dict(r) for r in db.execute('SELECT audit.*,users.username FROM audit LEFT JOIN users ON users.id=audit.user_id ORDER BY audit.id DESC LIMIT 200')])

@app.post('/api/agent/enroll')
def agent_enroll():
    ticket=body().get('ticket','')
    if not isinstance(ticket,str) or not re.fullmatch(r'[A-Za-z0-9_-]{40,128}',ticket):return error('接入凭证无效',401)
    now=int(time.time())
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT * FROM install_tickets WHERE hash=?',(digest(ticket),)).fetchone()
        if not row or row['used'] or row['expires']<now:return error('接入凭证已失效或已使用，请重新生成',401)
        token=secrets.token_urlsafe(40)
        db.execute('UPDATE install_tickets SET used=1 WHERE hash=?',(digest(ticket),))
        db.execute('UPDATE servers SET agent_hash=? WHERE id=?',(digest(token),row['server_id']))
    return jsonify(token=token)

@app.post('/api/agent/report')
def report():
    bearer=request.headers.get('Authorization','')
    if not bearer.startswith('Bearer ') or len(bearer)>256:return error('采集认证失败',401)
    token_hash=digest(bearer[7:])
    with connect() as db:
        row=db.execute('SELECT id FROM servers WHERE agent_hash=?',(token_hash,)).fetchone()
        if not row:return error('采集认证失败',401)
        # Per-server write throttle; accept up to 30 reports a minute.
        if throttled('agent:'+str(row['id']),30,60):return error('上报过于频繁',429)
        d=body(); clean={}
        numeric={'cpu_percent':100,'memory_percent':100,'disk_percent':100,'memory_total':2**60,'disk_total':2**60,
                 'uptime':2**53,'cpu_count':4096,'memory_used':2**60,'rx_bytes':2**63,'tx_bytes':2**63,'tcp':2**53,'udp':2**53}
        for k,maximum in numeric.items():
            v=d.get(k)
            if v is None:clean[k]=None;continue
            if type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=maximum:return error('指标格式无效：'+k)
            if k in ('tcp','udp','cpu_count') and type(v) is not int:return error('连接数必须是整数')
            clean[k]=v
        for k in ('hostname','os','kernel','network_error','ip_error','egress_error'):
            v=d.get(k,'')
            if not isinstance(v,str) or len(v)>256:return error('指标格式无效：'+k)
            clean[k]=v
        if d.get('public_ips') is not None:
            ips=d['public_ips']
            if not isinstance(ips,list) or len(ips)>64:return error('公网 IP 列表格式无效')
            try:
                normalized=[ipaddress.ip_address(ip) for ip in ips if isinstance(ip,str)]
                if len(normalized)!=len(ips) or any(not ip.is_global for ip in normalized):return error('只能上报公网 IP 地址')
                clean['public_ips']=sorted(set(str(ip) for ip in normalized))
            except ValueError:return error('IP 地址格式无效')
        if 'egress_ips' in d:
            ips=d['egress_ips']
            if ips is not None:
                if not isinstance(ips,list) or len(ips)>2:return error('出口 IP 格式无效')
                try:
                    addresses=[ipaddress.ip_address(ip) for ip in ips if isinstance(ip,str)]
                    if len(addresses)!=len(ips) or any(not ip.is_global for ip in addresses):return error('出口 IP 格式无效')
                    clean['egress_ips']=sorted(set(str(ip) for ip in addresses))
                except ValueError:return error('出口 IP 格式无效')
            else:clean['egress_ips']=None
        for stamp_key in ('egress_checked','connections_sampled'):
            stamp=d.get(stamp_key)
            if stamp is not None:
                if type(stamp) is not int or not 0<=stamp<=int(time.time())+60:return error('采集时间格式无效')
                clean[stamp_key]=stamp
        clean['capabilities']=['reboot'] if isinstance(d.get('capabilities'),list) and 'reboot' in d['capabilities'] else []
        clean['udp_method']='socket' if d.get('udp_method')=='socket' else 'conntrack'
        clean['network_method']='TCP ESTABLISHED sockets; UDP '+clean['udp_method']
        db.execute('BEGIN IMMEDIATE')
        current=db.execute('SELECT * FROM servers WHERE id=? AND agent_hash=?',(row['id'],token_hash)).fetchone()
        if not current:return error('采集密钥已失效',401)
        previous_method=(json.loads(current['metrics']) if current['metrics'] else {}).get('udp_method','conntrack')
        if current['metrics'] and previous_method!=clean['udp_method']:
            # Different units must not share one historical curve.
            db.execute('UPDATE metric_points SET udp=NULL WHERE server_id=?',(row['id'],))
        clean=record_network(db,current,clean,int(time.time()))
        previous=json.loads(current['metrics']) if current['metrics'] else {}
        reboot_detected=clean.get('uptime') is not None and previous.get('uptime') is not None and clean['uptime']<previous['uptime']
        if reboot_detected:
            db.execute("UPDATE commands SET status='completed',updated=? WHERE server_id=? AND status='accepted' AND created>=?",(int(time.time()),row['id'],int(time.time())-600))
            # A post-reboot IP (common on CMHK) should be re-probed immediately;
            # do not wait out the plan's normal 2+ minute interval.
            db.execute("UPDATE detection_plans SET next_at=MIN(next_at,?) WHERE server_id=? AND automatic=1 AND response_mode='reboot'",(int(time.time()),row['id']))
        db.execute("UPDATE commands SET status='unconfirmed',updated=? WHERE server_id=? AND status='accepted' AND created<?",(int(time.time()),row['id'],int(time.time())-600))
        # Match the public-IP display: fresh external observations first, then
        # interface addresses. Missing/failed samples never erase IP history.
        history_ips=clean.get('public_ips') or None
        if clean.get('egress_ips') and 0<=int(time.time())-clean.get('egress_checked',0)<=90:
            history_ips=clean['egress_ips']
        if history_ips:
            last=db.execute('SELECT addresses FROM ip_events WHERE server_id=? ORDER BY id DESC LIMIT 1',(row['id'],)).fetchone()
            addresses=json.dumps(history_ips)
            if not last or last['addresses']!=addresses:
                db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(?,?,?)',(row['id'],addresses,int(time.time())))
        db.execute('UPDATE servers SET metrics=?,seen=? WHERE id=?',(json.dumps(clean),int(time.time()),row['id']))
        # Fetch at most one command, and mark it issued before replying (no redelivery).
        command=None;now=int(time.time())
        db.execute("UPDATE commands SET status='expired',updated=? WHERE server_id=? AND status IN ('queued','issued') AND created<?",(now,row['id'],now-120))
        if 'reboot' in clean['capabilities']:
            job=db.execute("SELECT commands.*,users.role FROM commands JOIN users ON users.id=commands.user_id WHERE server_id=? AND status='queued' ORDER BY commands.id LIMIT 1",(row['id'],)).fetchone()
            if job:
                if job['role']=='admin' or current['owner_id']==job['user_id']:
                    db.execute("UPDATE commands SET status='issued',updated=? WHERE id=?",(now,job['id']))
                    command={'id':job['id'],'action':'reboot'}
                else:db.execute("UPDATE commands SET status='cancelled',updated=? WHERE id=?",(now,job['id']))
    return jsonify(ok=True,command=command)

@app.post('/api/servers/<int:sid>/reboot')
@auth()
def request_reboot(sid):
    if body().get('confirm') is not True:return error('请确认重启操作')
    now=int(time.time())
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT * FROM servers WHERE id=?',(sid,)).fetchone()
        if not row or (g.user['role']!='admin' and row['owner_id']!=g.user['id']):return error('服务器不存在',404)
        if not row['seen'] or now-row['seen']>60:return error('服务器离线，无法下发重启',409)
        metrics=json.loads(row['metrics']) if row['metrics'] else {}
        if 'reboot' not in metrics.get('capabilities',[]):return error('请先升级此服务器的采集客户端以启用重启',409)
        db.execute("UPDATE commands SET status='expired',updated=? WHERE server_id=? AND status IN ('queued','issued') AND created<?",(now,sid,now-120))
        # Accepted commands are also held for two minutes to prevent double-clicks.
        if db.execute("SELECT id FROM commands WHERE server_id=? AND status IN ('queued','issued','accepted') AND created>=?",(sid,now-120)).fetchone():return error('已有重启任务，请等待状态更新',409)
        result=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot','queued',?,?)",(sid,g.user['id'],now,now))
        audit(db,f'请求重启服务器 #{sid}')
    return jsonify(ok=True,id=result.lastrowid),202

@app.post('/api/agent/commands/<int:cid>/ack')
def ack_command(cid):
    bearer=request.headers.get('Authorization','')
    if not bearer.startswith('Bearer ') or len(bearer)>256:return error('采集认证失败',401)
    now=int(time.time())
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        node=db.execute('SELECT id,owner_id FROM servers WHERE agent_hash=?',(digest(bearer[7:]),)).fetchone()
        if not node:return error('采集认证失败',401)
        job=db.execute('SELECT commands.*,users.role FROM commands JOIN users ON users.id=commands.user_id WHERE commands.id=? AND server_id=?',(cid,node['id'])).fetchone()
        if not job:return error('任务不存在',404)
        if job['role']!='admin' and job['user_id']!=node['owner_id']:return error('任务权限已失效',403)
        if body().get('status')=='failed':
            if job['status']!='accepted':return error('任务状态不匹配',409)
            db.execute("UPDATE commands SET status='failed',updated=? WHERE id=?",(now,cid));return jsonify(ok=True)
        if job['status']!='issued' or now-job['created']>120:return error('任务已过期或已确认',409)
        db.execute("UPDATE commands SET status='accepted',updated=? WHERE id=?",(now,cid))
    return jsonify(ok=True)

@app.get('/api/servers/<int:sid>/network')
@auth()
def network_history(sid):
    now=int(time.time());period=request.args.get('range','1h')
    if period not in ('1h','24h'):return error('时间范围无效')
    seconds,bucket=(3600,15) if period=='1h' else (86400,360)
    with connect() as db:
        row=db.execute('SELECT * FROM servers WHERE id=?',(sid,)).fetchone()
        if not row or (g.user['role']!='admin' and row['owner_id']!=g.user['id']):return error('服务器不存在',404)
        points=db.execute('SELECT CAST(stamp/? AS INTEGER)*? AS stamp,AVG(rx_bps) AS rx_bps,AVG(tx_bps) AS tx_bps FROM network_points WHERE server_id=? AND stamp>=? GROUP BY CAST(stamp/? AS INTEGER) ORDER BY stamp',(bucket,bucket,sid,now-seconds,bucket)).fetchall()
        metrics=json.loads(row['metrics']) if row['metrics'] else {};online=bool(row['seen'] and now-row['seen']<=60)
        return jsonify(points=[dict(p) for p in points],traffic=traffic_summary(db,sid,now),
                       rx_bps=metrics.get('rx_bps') if online else None,tx_bps=metrics.get('tx_bps') if online else None,
                       online=online,seen=row['seen'],uptime=metrics.get('uptime') if online else None,now=now,bucket=bucket,seconds=seconds)

@app.get('/api/servers/<int:sid>/metrics')
@auth()
def metric_history(sid):
    now=int(time.time());period=request.args.get('range','1h')
    if period not in ('1h','24h'):return error('时间范围无效')
    seconds,bucket=(3600,15) if period=='1h' else (86400,360)
    with connect() as db:
        row=db.execute('SELECT owner_id,metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
        if not row or (g.user['role']!='admin' and row['owner_id']!=g.user['id']):return error('服务器不存在',404)
        points=db.execute('SELECT CAST(stamp/? AS INTEGER)*? AS stamp,AVG(cpu) AS cpu,AVG(memory) AS memory,AVG(tcp) AS tcp,AVG(udp) AS udp,AVG(rx_bps) AS rx_bps,AVG(tx_bps) AS tx_bps FROM metric_points WHERE server_id=? AND stamp>=? GROUP BY CAST(stamp/? AS INTEGER) ORDER BY stamp',(bucket,bucket,sid,now-seconds,bucket)).fetchall()
        metrics=json.loads(row['metrics']) if row['metrics'] else {};online=bool(row['seen'] and now-row['seen']<=60)
        return jsonify(points=[dict(p) for p in points],current=metrics if online else {},online=online,seen=row['seen'],now=now,
                       bucket=bucket,seconds=seconds,traffic=traffic_summary(db,sid,now),
                       rx_bps=metrics.get('rx_bps') if online else None,tx_bps=metrics.get('tx_bps') if online else None)

@app.get('/api/servers/<int:sid>/ip-history')
@auth()
def ip_history(sid):
    raw_before=request.args.get('before')
    try:
        before=int(raw_before) if raw_before is not None else None
        if before is not None and before<1:raise ValueError()
    except ValueError:return error('历史分页参数无效')
    with connect() as db:
        row=db.execute('SELECT owner_id,metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
        if not row or (g.user['role']!='admin' and row['owner_id']!=g.user['id']):return error('服务器不存在',404)
        query="""SELECT e.id,e.addresses,e.observed,
                 (SELECT previous.addresses FROM ip_events previous WHERE previous.server_id=e.server_id AND previous.id<e.id ORDER BY previous.id DESC LIMIT 1) AS previous_addresses
                 FROM ip_events e WHERE e.server_id=?"""
        params=[sid]
        if before is not None:query+=' AND e.id<?';params.append(before)
        events=db.execute(query+' ORDER BY e.id DESC LIMIT 51',params).fetchall()
        more=len(events)>50;events=events[:50]
        metrics=json.loads(row['metrics']) if row['metrics'] else {}
        latest=db.execute('SELECT addresses,observed FROM ip_events WHERE server_id=? ORDER BY id DESC LIMIT 1',(sid,)).fetchone()
        count=db.execute('SELECT COUNT(*) FROM ip_events WHERE server_id=?',(sid,)).fetchone()[0]
        return jsonify(events=[{'id':e['id'],'addresses':json.loads(e['addresses']),'observed':e['observed'],
                                'previous_addresses':json.loads(e['previous_addresses']) if e['previous_addresses'] is not None else None} for e in events],
                       available=bool(metrics.get('public_ips') or metrics.get('egress_ips')),error=metrics.get('egress_error','') if metrics.get('egress_ips') else metrics.get('ip_error',''),seen=row['seen'],
                       current_addresses=json.loads(latest['addresses']) if latest else None,
                       latest_observed=latest['observed'] if latest else None,total=count,has_more=more,
                       next_cursor=events[-1]['id'] if more else None)

@app.get('/agent-update.sh')
def agent_updater_download(): return send_from_directory(ROOT/'agent','update.sh',mimetype='text/plain')

@app.get('/agent.py')
def agent_download(): return send_from_directory(ROOT/'agent','agent.py',mimetype='text/x-python')
@app.get('/agent-install.sh')
def installer_download(): return send_from_directory(ROOT/'agent','install.sh',mimetype='text/plain')
@app.get('/')
def index():
    r=send_from_directory(ROOT/'web','index.html');r.headers['Cache-Control']='no-store';return r
@app.get('/<path:path>')
def static(path):
    if '/'+path==admin_path():return index()
    return send_from_directory(ROOT/'web',path)

@app.errorhandler(413)
def too_large(e): return error('请求内容过大',413)

init()
from ip_dns import init_schema, register as register_ip_dns
init_schema(connect)
from detectors import initialize as initialize_detectors, register as register_detectors
initialize_detectors(connect)
with connect() as cipher_db:
    CIPHER=load_cipher(DATA,bool(cipher_db.execute('SELECT 1 FROM users WHERE password_encrypted IS NOT NULL LIMIT 1').fetchone() or cipher_db.execute('SELECT 1 FROM ip_connections LIMIT 1').fetchone() or cipher_db.execute('SELECT 1 FROM detection_sources LIMIT 1').fetchone()))
register_ip_dns(app,connect,CIPHER,auth,body,error,audit)
register_detectors(app,connect,CIPHER,auth,body,error,audit)
if __name__=='__main__':
    import argparse, getpass
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['admin','backup','entry']);parser.add_argument('target',nargs='?');args=parser.parse_args()
    if args.command=='entry':
        print('管理员入口：'+admin_path())
    elif args.command=='backup':
        if not args.target:parser.error('需要备份路径')
        with connect() as src, sqlite3.connect(args.target) as dst:src.backup(dst)
        os.chmod(args.target,0o600);print('数据库备份完成')
    else:
        username=input('管理员账号 [admin]: ').strip() or 'admin';pw=getpass.getpass('管理员密码（至少 12 位）: ')
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{3,64}',username) or not 12<=len(pw)<=128:sys.exit('账号或密码格式不正确')
        if pw!=getpass.getpass('再输入一次密码: '):sys.exit('两次密码不一致')
        with connect() as db:
            db.execute("INSERT INTO users(username,password,role) VALUES(?,?,'admin') ON CONFLICT(username) DO UPDATE SET password=excluded.password,role='admin',password_encrypted=NULL",(username,generate_password_hash(pw)))
            uid=db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()[0]
            db.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
        print('管理员已配置')



