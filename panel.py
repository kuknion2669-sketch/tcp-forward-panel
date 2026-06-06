#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCP Forward Panel v9.0 — pure static SSR"""
from flask import Flask, request, redirect, render_template_string, Response, session
import subprocess, os, json, time, socket, logging, re, urllib.parse, sqlite3, secrets, hashlib
from datetime import datetime, timedelta
from functools import wraps

logging.basicConfig(filename='/root/panel.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.permanent_session_lifetime = timedelta(hours=24)


DB_FILE = "/root/traffic.db"
VERSION = "13.0"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login?next=" + request.path)
        return f(*args, **kwargs)
    return decorated

def kill_port(p): pass  # HAProxy manages ports

def get_free_port():
    for p in range(10000, 65535):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            if s.connect_ex(("127.0.0.1", p)) != 0: s.close(); return str(p)
            s.close()
        except: continue
    return "10000"

def load_data():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM rules ORDER BY id")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def save_data(data):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM rules")
        for i, item in enumerate(data):
            c.execute("INSERT INTO rules (name, local, ip, port, expire, quota, used, used_in, used_out, enable, note) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (item.get("name",""), item.get("local",""), item.get("ip",""),
                 item.get("port",""), item.get("expire",""), item.get("quota",0),
                 item.get("used",0), item.get("used_in",0), item.get("used_out",0),
                 1 if item.get("enable",True) else 0, item.get("note","")))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def is_running(p):
    try:
        return "LISTEN" in subprocess.getoutput("netstat -tlnp 2>/dev/null | grep :" + p)
    except: return False

def is_expired(e):
    if not e: return False
    try: return time.time() > float(e)
    except: return False

def start_forward(local, ip, rport, expire=None): pass  # HAProxy handles forwarding

def reload_haproxy():
    data = load_data()
    lines = [
        "global",
        "    daemon",
        "    maxconn 4096",
        "    stats socket /run/haproxy.sock mode 600 level admin",
        "    tune.bufsize 65536",
        "",
        "defaults",
        "    mode tcp",
        "    timeout connect 5000ms",
        "    timeout client 50000ms",
        "    timeout server 50000ms",
        "    option tcp-smart-connect",
        "    option tcp-smart-accept",
        "",
    ]
    for item in data:
        if not item.get("enable", True): continue
        if is_expired(item.get('expire', '')): continue
        _q = item.get('quota', 0)
        if _q > 0 and item.get('used', 0) >= _q * 1024: continue
        loc = item.get("local", "")
        ip = item.get("ip", "")
        prt = item.get("port", "")
        if not loc or not ip or not prt: continue
        ensure_iptables_rules(loc)
        lines.append(f"frontend fe_{loc}")
        lines.append(f"    bind 0.0.0.0:{loc}")
        lines.append("    mode tcp")
        lines.append(f"    default_backend be_{loc}")
        lines.append("")
        lines.append(f"backend be_{loc}")
        lines.append("    mode tcp")
        lines.append(f"    server s{loc} {ip}:{prt} check inter 10s fall 3 rise 2")
        lines.append("")
    update_used()
    # Don't clear HAPROXY_LAST - keep incremental tracking across config reloads
    import socket as _sk
    _sh = _sk.socket(_sk.AF_UNIX, _sk.SOCK_STREAM)
    try:
        _sh.connect("/run/haproxy.sock")
        for _it in data:
            if not _it.get("enable", True): continue
            _lo = _it.get("local", "")
            if not _lo: continue
            if is_expired(_it.get("expire", "")) or (_it.get("quota", 0) > 0 and _it.get("used", 0) >= _it.get("quota", 0) * 1024):
                _sh.sendall(f"shutdown sessions server be_{_lo}/s{_lo}\n".encode())
        _sh.close()
    except:
        pass
    cfg = "\n".join(lines) + "\n"
    with open("/etc/haproxy/haproxy.cfg", "w") as f: f.write(cfg)
    import os as _hap_os, subprocess as _hap_sp
    try:
        if _hap_os.path.exists("/run/haproxy.pid"):
            pid = open("/run/haproxy.pid").read().strip()
            _hap_sp.run(f"haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -sf {pid}", shell=True, capture_output=True)
        else:
            _hap_sp.run("haproxy -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -D", shell=True, capture_output=True)
    except: pass

def ensure_iptables_rules(p):
    out_chain = "OUT_" + p
    in_chain = "IN_" + p
    subprocess.run("iptables -N " + out_chain + " 2>/dev/null || true", shell=True)
    subprocess.run("iptables -N " + in_chain + " 2>/dev/null || true", shell=True)
    subprocess.run("iptables -C INPUT -p tcp --dport " + p + " -j " + in_chain + " 2>/dev/null || iptables -I INPUT -p tcp --dport " + p + " -j " + in_chain, shell=True)
    subprocess.run("iptables -C OUTPUT -p tcp --sport " + p + " -j " + out_chain + " 2>/dev/null || iptables -I OUTPUT -p tcp --sport " + p + " -j " + out_chain, shell=True)
    for ch in [in_chain, out_chain]:
        lc = subprocess.getoutput("iptables -L " + ch + " -v -n 2>/dev/null | wc -l").strip()
        if lc == "3":
            subprocess.run("iptables -A " + ch + " -j RETURN 2>/dev/null", shell=True)

def get_chain_bytes(chain):
    try:
        b = subprocess.getoutput("iptables -L " + chain + " -v -n -x 2>/dev/null | awk 'NR==3{print $2}'")
        return int(b or "0") / (1024*1024)
    except:
        return 0.0

def get_traffic(p):
    return get_chain_bytes("TRAFFIC_" + p)

def get_in_traffic(p):
    return get_chain_bytes("IN_" + p)

def get_out_traffic(p):
    return get_chain_bytes("OUT_" + p)

LAST_UPDATE = [0.0]
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, local TEXT NOT NULL, ip TEXT NOT NULL, port TEXT NOT NULL, expire TEXT DEFAULT "", quota REAL DEFAULT 0, used REAL DEFAULT 0, used_in REAL DEFAULT 0, used_out REAL DEFAULT 0, enable INTEGER DEFAULT 1, note TEXT DEFAULT "")\n')
    c.execute('CREATE TABLE IF NOT EXISTS traffic (date TEXT, port TEXT, name TEXT, used REAL, online INT DEFAULT 0, quota REAL DEFAULT 0, PRIMARY KEY (date, port))')
    c.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, port TEXT, name TEXT, event_type TEXT, message TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS daily (date TEXT PRIMARY KEY, total_traffic REAL DEFAULT 0, total_in REAL DEFAULT 0, total_out REAL DEFAULT 0, online_count INT DEFAULT 0, total_nodes INT DEFAULT 0)')
    c.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)')
    for k, v in [('panel_port', '8080'), ('username', 'admin'), ('password_hash', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9')]:
        c.execute('INSERT OR IGNORE INTO config VALUES (?,?)', (k, v))
    conn.commit()
    conn.close()

def log_event(port, name, event_type, message=''):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute('INSERT INTO events (time, port, name, event_type, message) VALUES (?,?,?,?,?)',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), port, name, event_type, message))
        conn.commit()
        conn.close()
    except: pass

def record_traffic():
    today = datetime.now().strftime('%Y-%m-%d')
    data = load_data()
    total = 0
    total_in = 0
    total_out = 0
    online = 0
    for item in data:
        p = item.get('local', '')
        if not p: continue
        used = item.get('used', 0)
        used_in = item.get('used_in', 0)
        used_out = item.get('used_out', 0)
        try:
            total += float(used)
            total_in += float(used_in)
            total_out += float(used_out)
        except:
            pass
        running = item.get('enable', True) and is_running(p)
        if running: online += 1
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        # Read previous day's cumulative value
        cur.execute('SELECT total_traffic, total_in, total_out FROM daily ORDER BY date DESC LIMIT 1')
        prev = cur.fetchone()
        if prev:
            # Current raw totals might be lower after HAProxy restart
            # Only use raw if they're >= previous cumulative (counting from infra reset)
            # Otherwise, keep old cumulative and add delta since last check
            raw_total, raw_in, raw_out = round(total,1), round(total_in,1), round(total_out,1)
            # Check if raw values are >= previous cumulative (normal case)
            if raw_total >= prev[0] and raw_in >= prev[1] and raw_out >= prev[2]:
                new_total, new_in, new_out = raw_total, raw_in, raw_out
            else:
                # HAProxy counters reset: add raw values as delta on top of previous
                delta_total = max(0, raw_total)
                delta_in = max(0, raw_in)
                delta_out = max(0, raw_out)
                new_total = round(prev[0] + delta_total, 1)
                new_in = round(prev[1] + delta_in, 1)
                new_out = round(prev[2] + delta_out, 1)
        else:
            new_total, new_in, new_out = round(total,1), round(total_in,1), round(total_out,1)
        cur.execute('INSERT OR REPLACE INTO daily (date, total_traffic, total_in, total_out, online_count, total_nodes) VALUES (?,?,?,?,?,?)',
                    (today, new_total, new_in, new_out, online, len(data)))
        conn.commit()
        conn.close()
    except:
        pass

HAPROXY_LAST = {}

def read_haproxy_stats():
    try:
        raw = subprocess.getoutput("echo 'show stat' | socat /run/haproxy.sock stdio 2>/dev/null")
        stats = {}
        for line in raw.strip().split('\n')[1:]:
            parts = line.split(',')
            if len(parts) < 10: continue
            pxname = parts[0]
            svname = parts[1]
            if svname not in ('FRONTEND', 'BACKEND'): continue
            if svname == 'FRONTEND': continue
            port = pxname[3:] if pxname.startswith('be_') else ''
            if not port or not port.isdigit(): continue
            try:
                stats[port] = {"bin": int(parts[8] or 0), "bout": int(parts[9] or 0)}
            except:
                pass
        return stats
    except:
        return {}


def update_used():
    now = time.time()
    if now - LAST_UPDATE[0] < 60: return
    LAST_UPDATE[0] = now
    cur = read_haproxy_stats()
    if not cur: return
    data = load_data()
    changed = False
    for i in data:
        p = i.get("local")
        if not p or p not in cur: continue
        prev = HAPROXY_LAST.get(p)
        c = cur[p]
        if not prev:
            i["used_in"] = round(c["bin"] / (1024*1024), 1)
            i["used_out"] = round(c["bout"] / (1024*1024), 1)
            i["used"] = round(i["used_in"] + i["used_out"], 1)
            changed = True
        else:
            d_in = c["bin"] - prev["bin"]
            d_out = c["bout"] - prev["bout"]
            if d_in >= 0 and d_out >= 0 and d_in < 10*1024*1024*1024 and d_out < 10*1024*1024*1024:
                i["used_in"] = round(i.get("used_in",0) + d_in / (1024*1024), 1)
                i["used_out"] = round(i.get("used_out",0) + d_out / (1024*1024), 1)
                i["used"] = round(i.get("used_in",0) + i.get("used_out",0), 1)
                changed = True
        HAPROXY_LAST[p] = c
    if changed: save_data(data)
    record_traffic()
    # Auto-disable quota-exhausted nodes via HAProxy socket
    try:
        import socket as _sq
        _sq_s = _sq.socket(_sq.AF_UNIX, _sq.SOCK_STREAM)
        _sq_s.connect("/run/haproxy.sock")
        for _sq_i in data:
            _sq_q = _sq_i.get("quota", 0)
            if _sq_q > 0 and _sq_i.get("used", 0) >= _sq_q * 1024 and _sq_i.get("enable", True):
                _sq_l = _sq_i.get("local", "")
                if _sq_l:
                    _sq_cmd = f"disable server be_{_sq_l}/s{_sq_l}\n"
                    _sq_s.sendall(_sq_cmd.encode())
                    _sq_s.sendall(f"shutdown sessions server be_{_sq_l}/s{_sq_l}\n".encode())
        _sq_s.close()
    except:
        pass

def recover_all():
    try:
        import sqlite3 as _s
        _d = _s.connect('/root/traffic.db')
        # Traffic preserved across restarts - use reset_quota to zero
        _d.close()
    except:
        pass
init_db()
recover_all()

def get_config():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT key, value FROM config')
    rows = c.fetchall()
    conn.close()
    return dict(rows)

def check_auth(user, pwd):
    cfg = get_config()
    h = hashlib.sha256(pwd.encode()).hexdigest()
    return user == cfg.get('username') and h == cfg.get('password_hash')

GROUP_LABELS = {
    "美区": "🇺🇸 美区", "香港": "🇭🇰 香港", "泰国": "🇹🇭 泰国",
    "马来": "🇲🇾 马来西亚", "日区": "🇯🇵 日区", "土耳": "🇹🇷 土耳其",
    "MY": "🇲🇾 马来西亚",
}

def detect_group(name):
    # Try matching against GROUP_LABELS keys directly
    for label_key in GROUP_LABELS:
        if name.startswith(label_key):
            return GROUP_LABELS[label_key]
    # Fallback: first 2 Chinese chars
    m = re.match(r'^([\u4e00-\u9fff]{2})', name)
    if m:
        return m.group(1)
    m = re.match(r'^([A-Za-z]+)', name)
    if m:
        return GROUP_LABELS.get(m.group(1).upper(), m.group(1).upper())
    return "📦 其他"

def enrich_data(data):
    enriched = []
    for i in data:
        i2 = i.copy()
        running = is_running(i['local'])
        expire = i.get('expire','')
        expired = is_expired(expire)
        quota, used = i.get('quota',0), i.get('used',0)
        if expired or (quota>0 and used>=quota*1024):
            if running: pass  # HAProxy handles port management
            running = False
        i2['online'] = running
        i2['expired'] = expired
        i2['expire_time_display'] = datetime.fromtimestamp(float(expire)).strftime("%Y-%m-%d %H:%M:%S") if expire else ""
        ui = i2.get('used_in',0); uo = i2.get('used_out',0)
        i2['used_in_display'] = str(round(ui/1024,1))+'GB' if ui>=1024 else str(round(ui,1))+'MB'
        i2['used_out_display'] = str(round(uo/1024,1))+'GB' if uo>=1024 else str(round(uo,1))+'MB'
        i2.setdefault('quota',0)
        i2.setdefault('used',0)
        i2['group'] = detect_group(i2['name'])
        enriched.append(i2)
    return enriched

# ─── Routes ───

@app.route('/')
@login_required
def index():
    record_traffic()
    q = request.args.get('q', '')
    sf = request.args.get('status', 'all')
    group_filter = request.args.get('group', '')
    view = request.args.get('view', 'groups') if not group_filter else 'detail'
    update_used()
    data = load_data()
    enriched = enrich_data(data)
    total_q = sum(i.get('quota',0) for i in enriched)
    total_u = sum(i.get('used',0) for i in enriched)

    # Build groups
    groups = {}
    for idx, item in enumerate(enriched):
        item['_idx'] = idx

    for item in enriched:
        g = item['group']
        if g not in groups:
            groups[g] = {'count': 0, 'used': 0, 'used_in': 0, 'used_out': 0, 'online': 0, 'offline': 0, 'expired': 0, 'quotaExhausted': 0, 'items': []}
        groups[g]['count'] += 1
        groups[g]['used'] += item.get('used', 0)
        groups[g]['used_in'] += item.get('used_in', 0)
        groups[g]['used_out'] += item.get('used_out', 0)
        if item.get('expired'):
            groups[g]['expired'] += 1
        elif item.get('quota', 0) > 0 and item.get('used', 0) >= item.get('quota', 0) * 1024:
            groups[g]['quotaExhausted'] += 1
        elif item.get('online'):
            groups[g]['online'] += 1
        else:
            groups[g]['offline'] += 1
        groups[g]['items'].append(item)


    # Build sorted groups with display info
    sorted_groups = []
    for g_name in sorted(groups.keys()):
        nfo = groups[g_name]
        total_quota_mb = sum(it.get('quota', 0) * 1024 for it in nfo['items'])
        bar = int(nfo['used'] / total_quota_mb * 100) if total_quota_mb > 0 else 0
        used_str = str(round(nfo['used']/1024, 1)) + ' GB' if nfo['used'] >= 1024 else str(round(nfo['used'], 1)) + ' MB'
        dots = ''
        if nfo['online'] > 0: dots += '<span class="dot dot-on"></span>' + str(nfo['online']) + ' 在线 '
        if nfo['offline'] > 0: dots += '<span class="dot dot-off"></span>' + str(nfo['offline']) + ' 离线 '
        if nfo['expired'] > 0: dots += '<span class="dot dot-exp"></span>' + str(nfo['expired']) + ' 过期 '
        if nfo['quotaExhausted'] > 0: dots += '<span style="color:var(--purple)">&#9889;' + str(nfo['quotaExhausted']) + ' 耗尽</span>'
        in_str = str(round(nfo['used_in']/1024,1)) + ' GB' if nfo['used_in'] >= 1024 else str(round(nfo['used_in'],1)) + ' MB'
        out_str = str(round(nfo['used_out']/1024,1)) + ' GB' if nfo['used_out'] >= 1024 else str(round(nfo['used_out'],1)) + ' MB'
        sorted_groups.append({'name': g_name, 'count': nfo['count'], 'bar_pct': bar, 'used_str': used_str, 'used_in': round(nfo['used_in'],1), 'used_out': round(nfo['used_out'],1), 'in_str': in_str, 'out_str': out_str, 'status_dots': dots})

    # Filter items based on view
    filtered = []
    if view == 'all':
        for v in groups.values():
            filtered.extend(v['items'])
    elif group_filter and group_filter in groups:
        filtered = groups[group_filter]['items']
    else:
        filtered = []

    # Apply search/filter
    if q:
        ql = q.lower()
        filtered = [i for i in filtered if ql in i['name'].lower() or ql in i['ip'].lower() or ql in i['local'] or ql in i['port']]
    if sf != 'all':
        if sf == 'online':
            filtered = [i for i in filtered if i['online'] and not i['expired'] and not (i['quota']>0 and i['used']>=i['quota']*1024)]
        elif sf == 'offline':
            filtered = [i for i in filtered if not i['online'] and not i['expired'] and not (i['quota']>0 and i['used']>=i['quota']*1024)]
        elif sf == 'expired':
            filtered = [i for i in filtered if i['expired']]
        elif sf == 'quota':
            filtered = [i for i in filtered if i['quota']>0 and i['used']>=i['quota']*1024]

    # Load traffic history - compute daily delta from cumulative
    history_days = []
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute('SELECT date, total_traffic, total_in, total_out FROM daily ORDER BY date ASC LIMIT 30')
        rows = cur.fetchall()
        conn.close()
        prev_total = None
        prev_in = None
        prev_out = None
        max_daily = 1
        daily_data = []
        for row in rows:
            d = row[0]
            total = row[1]
            total_in = row[2] if len(row) > 2 else 0
            total_out = row[3] if len(row) > 3 else 0
            if prev_total is not None:
                daily = max(0, total - prev_total)
                daily_in = max(0, total_in - prev_in) if prev_in is not None else total_in
                daily_out = max(0, total_out - prev_out) if prev_out is not None else total_out
            else:
                daily = total
                daily_in = total_in
                daily_out = total_out
            prev_total = total
            prev_in = total_in
            prev_out = total_out
            daily_data.append({'date': d, 'daily': daily, 'daily_in': daily_in, 'daily_out': daily_out})
            if daily > max_daily:
                max_daily = daily
        for entry in daily_data:
            d = entry['date']
            daily = entry['daily']
            daily_in = entry['daily_in']
            daily_out = entry['daily_out']
            bar_pct = int(daily / max_daily * 100) if max_daily > 0 else 0
            td = str(round(daily/1024,1)) + ' GB' if daily >= 1024 else str(round(daily,1)) + ' MB'
            tid = str(round(daily_in/1024,1)) + ' GB' if daily_in >= 1024 else str(round(daily_in,1)) + ' MB'
            tod = str(round(daily_out/1024,1)) + ' GB' if daily_out >= 1024 else str(round(daily_out,1)) + ' MB'
            history_days.append({'date': d, 'short_date': d[5:], 'total_display': td, 'bar_pct': bar_pct, 'total_in': round(daily_in,1), 'total_out': round(daily_out,1), 'total_in_display': tid, 'total_out_display': tod})
    except:
        pass
    return render_template_string(HTML, version=VERSION, rule_count=len(enriched),
        total_quota=round(total_q,1), total_used=str(round(total_u/1024,1))+' GB' if total_u>=1024 else str(round(total_u,1))+' MB',
        sorted_groups=sorted_groups, filtered=filtered,
        view=view, group_filter=group_filter, q=q, sf=sf,
        history_days=history_days)

@app.route('/add', methods=['POST'])
@login_required
def add():
    name = request.form.get('name','').strip()
    local = request.form.get('local','').strip()
    ip = request.form.get('ip','').strip()
    port = request.form.get('port','').strip()
    expire_raw = request.form.get('expire','').strip()
    quota_raw = request.form.get('quota','').strip()
    quota = 1.0 if quota_raw in ('','0') else float(quota_raw) if quota_raw else 1.0
    if not name or not ip or not port: return redirect(request.referrer or '/')
    if not local: local = get_free_port()
    elif not local.isdigit() or not port.isdigit(): return redirect(request.referrer or '/')
    # Check port duplicate - auto reassign if taken
    existing_ports = [i['local'] for i in load_data() if i.get('local')]
    if local in existing_ports:
        local = get_free_port()
    if expire_raw == "":
        expire = str((datetime.now()+timedelta(days=30)).timestamp())
    else:
        try:
            er = expire_raw.replace("T"," ")
            if er.isdigit(): expire = str(int(er))
            else: expire = str(datetime.strptime(er,"%Y-%m-%d %H:%M:%S").timestamp())
        except: expire = str((datetime.now()+timedelta(days=30)).timestamp())
    ensure_iptables_rules(local)
    data = load_data()
    data.append({"name":name,"local":local,"ip":ip,"port":port,"expire":expire,"quota":quota,"used":0,"enable":True})
    save_data(data)
    reload_haproxy()
    return redirect(request.referrer or '/')

@app.route('/batch_add', methods=['POST'])
@login_required
def batch_add():
    text = request.form.get('batch_data','')
    rules = []
    for line in text.strip().split('\n'):
        if not line or line.startswith('#'): continue
        parts = line.strip().split(':')
        if len(parts)<4: continue
        name,local,ip,rport = parts[0], parts[1].strip(), parts[2], parts[3]
        ep = parts[4].strip() if len(parts)>4 else ""
        qp = parts[5].strip() if len(parts)>5 else ""
        if not name or not ip or not rport or not rport.isdigit(): continue
        if local and not local.isdigit(): continue
        if not local: local = get_free_port()
        quota = 10.0 if qp in ('','0') else float(qp) if qp else 10.0
        if ep == "":
            expire = str((datetime.now()+timedelta(days=30)).timestamp())
        else:
            try:
                er = ep.replace("T"," ")
                expire = str(int(er)) if er.isdigit() else str(datetime.strptime(er,"%Y-%m-%d %H:%M:%S").timestamp())
            except: expire = str((datetime.now()+timedelta(days=30)).timestamp())
        rules.append({"name":name,"local":local,"ip":ip,"port":rport,"expire":expire,"quota":quota,"used":0})
    data = load_data()
    for r in rules:
        if any(i['local']==r['local'] for i in data): continue
        ensure_iptables_rules(r['local'])
        data.append(r)
    save_data(data)
    reload_haproxy()
    return redirect(request.referrer or '/')

@app.route('/del/<int:idx>')
@login_required
def delete(idx):
    data = load_data()
    ok = 0<=idx<len(data)
    if ok: del data[idx]; save_data(data); reload_haproxy()
    return Response(json.dumps({'ok': ok}), mimetype='application/json')

@app.route('/killport/<port>')
@login_required
def kill(port):
    return redirect(request.referrer or '/')

@app.route('/edit/<int:idx>', methods=['POST'])
@login_required
def edit(idx):
    data = load_data()
    if 0<=idx<len(data):
        old = data[idx]
        new_name = request.form.get('name','').strip()
        new_local = request.form.get('local','').strip()
        new_ip = request.form.get('ip','').strip()
        new_port = request.form.get('port','').strip()
        new_er = request.form.get('expire','').strip()
        new_q = float(request.form.get('quota',0)) if request.form.get('quota','').strip() else old.get('quota',0)
        if not new_name or not new_ip or not new_port: return redirect(request.referrer or '/')
        if not new_local.isdigit() or not new_port.isdigit(): return redirect(request.referrer or '/')
        for oi,o in enumerate(data):
            if oi!=idx and o.get('local')==new_local: return redirect(request.referrer or '/')
        ne = ""
        if new_er:
            try:
                ne_r = new_er.replace("T"," ")
                if ne_r.isdigit(): ne = str(int(ne_r))
                else:
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
                        try:
                            ne = str(datetime.strptime(ne_r, fmt).timestamp())
                            break
                        except: pass
            except: pass
        kill_port(old['local'])
        old.update({"name":new_name,"local":new_local,"ip":new_ip,"port":new_port,"expire":ne,"quota":new_q})
        save_data(data)
        ensure_iptables_rules(new_local)
        reload_haproxy()
    return redirect(request.referrer or '/')

@app.route('/reset_quota/<int:idx>')
@login_required
def reset_quota(idx):
    data = load_data()
    if 0<=idx<len(data):
        data[idx]['used'] = 0
        data[idx]['used_in'] = 0
        data[idx]['used_out'] = 0
        save_data(data)
        i = data[idx]
        global HAPROXY_LAST
        if i['local'] in HAPROXY_LAST:
            del HAPROXY_LAST[i['local']]
        if not is_running(i['local']) and not is_expired(i.get('expire','')):
            start_forward(i['local'], i['ip'], i['port'], i['expire'])
    return redirect(request.referrer or '/')

@app.route('/backup')
@login_required
def backup():
    data = load_data()
    from flask import Response as Rsp
    import datetime
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    lines = []
    for d in data:
        lines.append(':'.join([d.get('name',''), d.get('local',''), d.get('ip',''), d.get('port','')]))
    txt = chr(10).join(lines)
    return Rsp(txt, mimetype='text/plain; charset=utf-8',
        headers={'Content-Disposition': 'attachment; filename=forward_backup_' + ts + '.txt'})

@app.route('/restart/<local>')
@login_required
def restart_node(local):
    data = load_data()
    for item in data:
        if item.get('local') == local:
            kill_port(local)
            if is_expired(item.get('expire','')) or (item.get('quota',0) > 0 and item.get('used',0) >= item.get('quota',0)*1024): return redirect(request.referrer or '/')
            start_forward(local, item['ip'], item['port'], item.get('expire',''))
            break
    return redirect(request.referrer or '/')

@app.route('/api/toggle/<local>', methods=['POST'])
@login_required
def api_toggle(local):
    data = load_data()
    for item in data:
        if item.get("local") == local:
            item["enable"] = not item.get("enable", True)
            if not item["enable"]: kill_port(local)
            save_data(data); return redirect(request.referrer or '/')
    return redirect(request.referrer or '/')

@app.route('/check/<int:idx>')
@login_required
def check_node(idx):
    import socket
    data = load_data()
    if idx < 0 or idx >= len(data):
        return json.dumps({'ok': False, 'error': 'invalid index'})
    item = data[idx]
    ip = item.get('ip', '')
    port = item.get('port', '')
    try:
        port_int = int(port)
    except:
        return json.dumps({'ok': False, 'error': 'invalid port'})
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    start = time.time()
    try:
        s.connect((ip, port_int))
        ms = round((time.time() - start) * 1000, 1)
        s.close()
        return json.dumps({'ok': True, 'ms': ms, 'ip': ip, 'port': port})
    except Exception as e:
        ms = round((time.time() - start) * 1000, 1)
        return json.dumps({'ok': False, 'ms': ms, 'error': str(e), 'ip': ip, 'port': port})


@app.route('/check_all')
@login_required
def check_all():
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import socket as _sk
    data = load_data()
    results = {}
    
    def _check_one(idx, ip, port):
        try:
            port_int = int(port)
        except:
            return idx, {'ok': False, 'ms': 0, 'error': 'invalid port'}
        s = _sk.socket(_sk.AF_INET, _sk.SOCK_STREAM)
        s.settimeout(3)
        start = time.time()
        try:
            s.connect((ip, port_int))
            ms = round((time.time() - start) * 1000, 1)
            s.close()
            return idx, {'ok': True, 'ms': ms}
        except Exception as e:
            ms = round((time.time() - start) * 1000, 1)
            return idx, {'ok': False, 'ms': ms, 'error': str(e)}
    
    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(_check_one, i, item.get('ip',''), item.get('port','')): i for i, item in enumerate(data)}
        for fut in as_completed(futures):
            idx, result = fut.result()
            results[str(idx)] = result
    
    return json.dumps({'ok': True, 'results': results})
@app.route('/api/haproxy')
@login_required
def haproxy_stats():
    import subprocess as sp, json as j
    try:
        d = sp.getoutput('echo "show stat" | socat /run/haproxy.sock - 2>/dev/null')
        if not d:
            return j.dumps({'ok': False, 'error': 'socket not available'})
        lines = d.strip().split('\n')
        if len(lines) < 2:
            return j.dumps({'ok': False, 'error': 'no data'})
        hdrs = lines[0].split(',')
        result = []
        for line in lines[1:]:
            vals = line.split(',')
            if len(vals) >= 30 and vals[1] != 'FRONTEND' and vals[1] != 'BACKEND':
                row = {}
                for i, h in enumerate(hdrs):
                    if i < len(vals):
                        row[h] = vals[i]
                result.append(row)
        return j.dumps({'ok': True, 'backends': result, 'total': len(result)})
    except Exception as e:
        return j.dumps({'ok': False, 'error': str(e)})




@app.route('/api/connections')
@login_required
def api_connections():
    import subprocess as sp, json as j
    try:
        raw = sp.getoutput('netstat -tn 2>/dev/null')
        result = {}
        for ln in raw.strip().split(chr(10)):
            p = ln.split()
            if len(p) >= 5 and p[0] != 'Active' and p[0] != 'Proto':
                loc = p[3]; rem = p[4]; st = p[5] if len(p) > 5 else ''
                i = loc.rfind(':')
                if i >= 0:
                    po = loc[i+1:]
                    if po not in result: result[po] = []
                    result[po].append({'remote': rem, 'state': st})
        return j.dumps({'ok': True, 'ports': result})
    except Exception as e:
        return j.dumps({'ok': False, 'error': str(e)})

@app.route('/haproxy')
@login_required
def haproxy_page():
    import subprocess as sp, json as _j
    try:
        # Load node names
        # Load node names from SQLite
        import sqlite3 as _sq2
        _conn = _sq2.connect('/root/traffic.db')
        _conn.row_factory = _sq2.Row
        _cur = _conn.cursor()
        _cur.execute('SELECT local, name, ip FROM rules')
        _nodes = {str(r['local']): {'name': r['name'], 'ip': r['ip']} for r in _cur.fetchall()}
        _conn.close()
        d = sp.getoutput('echo "show stat" | socat /run/haproxy.sock - 2>/dev/null')
        if not d:
            return '<html><body><h2>HAProxy not available</h2></body></html>'
        lines = d.strip().split('\n')
        if len(lines) < 2:
            return '<html><body><h2>No data</h2></body></html>'
        rows = ''
        for line in lines[1:]:
            vals = line.split(',')
            if len(vals) >= 18 and vals[1] != 'FRONTEND' and vals[1] != 'BACKEND':
                sname = vals[1]
                port = sname.lstrip('s') if sname.startswith('s') else sname
                info = _nodes.get(port, {'name': sname, 'ip': ''})
                name = info['name']
                ip = info['ip']
                s = vals[17] if len(vals) > 17 else 'DOWN'
                c = '#0f0' if s == 'UP' else ('#f22' if s == 'DOWN' else '#fb0')
                scur = vals[4] if len(vals) > 4 else '0'
                bin_v = vals[8] if len(vals) > 8 else '0'
                bout_v = vals[9] if len(vals) > 9 else '0'
                rows += '<tr><td style="color:' + c + '">' + s + '</td><td>' + name + '</td><td style="color:#8899bb">' + ip + '</td><td data-port="' + port + '">' + scur + '</td><td>' + bin_v + '</td><td>' + bout_v + '</td></tr>'
        return '''<!DOCTYPE html><html><head><meta charset=utf-8><title>连接状态</title><style>
body{background:#0f172a;color:#f1f5f9;font-family:system-ui;padding:20px}
h2{color:#d0daf0;font-weight:400;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{background:rgba(255,255,255,0.05);color:#94a3b8;padding:8px 10px;text-align:left;font-weight:600}
td{padding:6px 10px;border-bottom:1px solid rgba(255,255,255,0.04)}
td[data-port]{cursor:pointer;text-decoration:underline}
td[data-port]:hover{opacity:.8}
</style></head><body><h2>连接状态</h2>
<table><tr><th>Status</th><th>节点</th><th>目标IP</th><th>连接数</th><th>入站</th><th>出站</th></tr>''' + rows + '''</table>
<script>
document.addEventListener('click',function(e){
  var td=e.target.closest('td[data-port]');
  if(!td)return;
  var p=td.getAttribute('data-port');
  var el=document.getElementById('ip_'+p);
  if(el&&el.style.display!=='none'){el.style.display='none';return;}
  if(el&&el.style.display==='none'){el.style.display='block';return;}
  if(!el){
    el=document.createElement('div');
    el.id='ip_'+p;
    el.style.cssText='margin:0 0 8px 24px;padding:8px 12px;background:rgba(255,255,255,0.03);border-radius:6px;font-size:12px;color:#8899bb';
    el.innerHTML='<span style=color:#94a3b8>Loading...</span>';
    var tr=td.closest('tr');
    if(tr)tr.parentNode.insertBefore(el,tr.nextSibling);
  }
  fetch('/api/connections').then(function(r){return r.json();}).then(function(d){
    if(!d.ok||!d.ports[p]){el.innerHTML='<span style=color:#94a3b8>No connections</span>';return;}
    var ips={};
    d.ports[p].forEach(function(x){
      var ip=x.remote.split(':')[0];
      if(x.state==='ESTABLISHED')ips[ip]=(ips[ip]||0)+1;
    });
    var ks=Object.keys(ips);
    if(ks.length===0){el.innerHTML='<span style=color:#94a3b8>No established connections</span>';return;}
    var h='<div style=color:#a0aec0;font-weight:600;margin-bottom:4px>客户端真实IP:</div>';
    ks.sort().forEach(function(ip){h+='<div style=margin-top:3px>'+ip+' <span style=color:#94a3b8>('+ips[ip]+'连接)</span></div>';});
    el.innerHTML=h;
  });
});
</script>
<div class=footer>''' + str(len(rows.split('</tr>')) - 1) + ' 节点</div></body></html>'
    except Exception as e:
        return '<html><body><h2>Error: ' + str(e) + '</h2></body></html>'


@app.route('/edit_page/<int:idx>', methods=['GET', 'POST'])
@login_required
def edit_page(idx):
    data = load_data()
    if idx < 0 or idx >= len(data):
        return redirect(request.referrer or '/')
    item = dict(data[idx])
    if request.method == 'POST':
        old = data[idx]
        kill_port(old['local'])
        old.update({
            'name': request.form.get('name', '').strip(),
            'local': request.form.get('local', '').strip(),
            'ip': request.form.get('ip', '').strip(),
            'port': request.form.get('port', '').strip(),
            'quota': float(request.form.get('quota', 0)) if request.form.get('quota', '').strip() else old.get('quota', 0),
            'note': request.form.get('note', '').strip(),
        })
        expire_raw = request.form.get('expire', '').strip()
        if expire_raw:
            try:
                t = expire_raw.replace('T', ' ')
                if t.isdigit(): old['expire'] = str(int(t))
                else:
                    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
                        try:
                            old['expire'] = str(datetime.strptime(t, fmt).timestamp())
                            break
                        except: pass
            except: pass
        save_data(data)
        ensure_iptables_rules(old['local'])
        reload_haproxy()
        return redirect(request.referrer or '/')
    nm = item.get('name', '')
    lo = item.get('local', '')
    ip = item.get('ip', '')
    po = item.get('port', '')
    qu = item.get('quota', 0)
    no = item.get('note', '')
    exp = item.get('expire', '')
    exp_dt = ''
    if exp:
        try: exp_dt = datetime.fromtimestamp(float(exp)).strftime('%Y-%m-%dT%H:%M')
        except: pass
    return render_template_string(EDIT_HTML, name=nm, local=lo, ip=ip, port=po, quota=qu, note=no, expire=exp_dt)

HTML = '''
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TCP管理面板 v''' + VERSION + '''</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/themes/dark.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/l10n/zh.js"></script>
<style>
.flatpickr-calendar{background:var(--card)!important;border-color:var(--border)!important;box-shadow:0 4px 24px rgba(0,0,0,.4)!important}
.flatpickr-months .flatpickr-month,.flatpickr-weekdays,.flatpickr-weekday{background:var(--card)!important;color:var(--text2)!important}
.flatpickr-day{color:var(--text)!important}
.flatpickr-day.today{border-color:var(--cyan)!important}
.flatpickr-day.selected,.flatpickr-day.startRange,.flatpickr-day.endRange,.flatpickr-day.inRange{background:var(--cyan)!important;border-color:var(--cyan)!important;color:#000!important}
.flatpickr-day:hover{background:rgba(0,229,255,.15)!important;border-color:transparent!important}
.flatpickr-day.flatpickr-disabled,.flatpickr-day.flatpickr-disabled:hover{color:var(--text2)!important;opacity:.4!important}
.flatpickr-time input{color:var(--text)!important;background:rgba(0,0,0,.3)!important}
.flatpickr-time .flatpickr-am-pm{color:var(--text2)!important}
.flatpickr-time .flatpickr-am-pm:hover{background:rgba(0,229,255,.15)!important}
:root{
  --bg:#080c18;--card:#0d1326;--border:#1a2340;--text:#d0daf0;--text2:#8899bb;
  --cyan:#00e5ff;--pink:#ff0088;--purple:#7c3aed;--green:#00ff88;--gold:#ffbb00;--red:#ff2255;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;padding:20px;min-height:100vh;font-size:15px;line-height:1.5;background-image:radial-gradient(circle,rgba(0,229,255,.2) 1.5px,transparent 1.5px),radial-gradient(circle,rgba(124,58,237,.15) 1.5px,transparent 1.5px);background-size:40px 40px,40px 40px;background-position:0px 0px;animation:waveBg 15s ease-in-out infinite}
@keyframes waveBg{0%{background-position:0px 0px,20px 20px}25%{background-position:10px -5px,30px 15px}50%{background-position:-5px 10px,15px 30px}75%{background-position:8px 8px,25px 10px}100%{background-position:0px 0px,20px 20px}}
body::before{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background-image:radial-gradient(circle,rgba(0,229,255,.12) 1px,transparent 1px);background-size:24px 24px;pointer-events:none;z-index:0;opacity:.5}

.wave-fixed{position:fixed;inset:0;pointer-events:none;z-index:0;background:#080c18;animation:waveAnim 15s ease-in-out infinite}.container{position:relative;z-index:1}.content-box{position:relative;z-index:1;background:rgba(8,12,24,.7);-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.05);border-radius:16px;padding:20px;min-height:calc(100vh - 40px)}.container{max-width:1200px;margin:0 auto;position:relative;z-index:2}a{color:inherit;text-decoration:none}

.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px}
.hdr h1{font-size:1.3rem;font-weight:800;color:var(--text);letter-spacing:0}
.hdr h1 span{color:var(--cyan)}
.hdr .sub{font-size:.82rem;color:var(--text2)}

.st{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.st-box{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px;text-align:center;position:relative}
.st-box .n{font-size:1.5rem;font-weight:800;color:var(--cyan)}
.st-box .l{font-size:.72rem;color:var(--text2);margin-top:4px}

.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:16px}
.card h2{font-size:1rem;font-weight:700;margin-bottom:14px;color:var(--text)}

.gc{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;margin-bottom:20px}
.gc-item{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px;display:block;transition:all .2s}
.gc-item:hover{border-color:var(--cyan);transform:translateY(-2px)}
.chart-section{margin-bottom:24px}
.chart-section h3{font-size:.85rem;color:var(--text2);margin-bottom:12px;font-weight:600;display:flex;align-items:center;gap:8px}














.gc-name{font-size:1rem;font-weight:700;margin-bottom:6px;color:var(--cyan)}
.gc-cnt{font-size:.78rem;color:var(--text2);margin-bottom:4px}
.gc-bar{background:rgba(0,229,255,.08);border-radius:20px;height:4px;width:100%;overflow:hidden;margin:6px 0}
.gc-fill{height:100%;border-radius:20px;background:var(--cyan)}
.gc-traf{font-size:.75rem;color:var(--text2)}
.gc-status{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;font-size:.78rem;color:var(--text2)}

.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:3px;vertical-align:middle}
.dot-on{background:var(--green)}
.dot-off{background:var(--red)}
.dot-exp{background:var(--gold)}

.tb{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.tb input,.tb select{padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.85rem;outline:none}
.tb input:focus,.tb select:focus{border-color:var(--cyan)}

.tabs{display:flex;gap:0;margin-bottom:18px;border-bottom:1px solid var(--border)}
.tab{background:none;color:var(--text2);padding:8px 18px;font-size:.85rem;font-weight:500;border-bottom:1px solid transparent;margin-bottom:-1px;display:inline-block;transition:all .15s}
.tab:hover{color:var(--text)}
.tab.act{color:var(--cyan);border-bottom-color:var(--cyan)}

.nl{display:flex;flex-direction:column;gap:8px}
.nd{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:8px;padding:14px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:center;transition:all .15s}
.nd:hover{background:rgba(0,229,255,.03);border-color:rgba(0,229,255,.2)}
.nd-info{flex:1;min-width:180px}
.nd-name{font-weight:600;font-size:.9rem;margin-bottom:2px;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.nd-route{font-family:monospace;font-size:.92rem;color:var(--cyan);background:rgba(0,229,255,.06);border:1px solid rgba(0,229,255,.12);border-radius:5px;padding:3px 10px;display:inline-block}
.nd-meta{font-size:.78rem;color:var(--text2);margin-top:4px;display:flex;gap:12px;flex-wrap:wrap}
.nd-acts{display:flex;gap:4px;flex-wrap:wrap}

.bdg{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.65rem;font-weight:600;border:1px solid}
.bdg-on{background:rgba(0,255,136,.08);color:var(--green);border-color:rgba(0,255,136,.2)}
.bdg-off{background:rgba(255,34,85,.08);color:var(--red);border-color:rgba(255,34,85,.2)}
.bdg-exp{background:rgba(255,187,0,.08);color:var(--gold);border-color:rgba(255,187,0,.2)}
.bdg-quota{background:rgba(124,58,237,.08);color:var(--purple);border-color:rgba(124,58,237,.2)}

.grp-tag{font-size:.6rem;color:var(--text2);border:1px solid var(--border);border-radius:3px;padding:1px 5px}

.btn{display:inline-block;padding:6px 14px;border-radius:5px;font-size:.85rem;font-weight:500;cursor:pointer;border:1px solid transparent;transition:all .15s}
.btn-pri{background:var(--cyan);color:var(--bg);font-weight:600}
.btn-pri:hover{opacity:.9}
.btn-gho{background:transparent;color:var(--text2);border-color:var(--border)}
.btn-gho:hover{border-color:var(--text2);color:var(--text)}
.btn-dgr{background:rgba(255,34,85,.1);color:var(--red);border-color:rgba(255,34,85,.2)}
.btn-dgr:hover{background:var(--red);color:#fff}
.btn-sm{padding:4px 10px;font-size:.8rem}

.fg{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}
.fg label{font-size:.75rem;color:var(--text2);display:block;margin-bottom:3px}
.fg input{padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.85rem;outline:none;width:100%}
.fg input:focus{border-color:var(--cyan)}
.fg .full{grid-column:1/-1}
.fg .hint{font-size:.65rem;color:var(--text2);margin-top:2px;float:right}

.brc{font-size:.82rem;color:var(--text2);margin-bottom:14px}
.brc a{color:var(--cyan)}
.ft{text-align:center;font-size:.72rem;color:var(--text2);margin-top:30px;opacity:.4}

.pb{background:rgba(0,229,255,.08);border-radius:4px;height:8px;width:120px;overflow:hidden;display:inline-block;vertical-align:middle}
.pf{display:block;height:100%;border-radius:4px;background:var(--cyan)}

.modal{display:none;position:fixed;inset:0;z-index:1000;align-items:center;justify-content:center;background:rgba(0,0,0,.7);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px)}.modal:target{display:flex}.modal-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;width:90%;max-width:520px;max-height:90vh;overflow-y:auto}


@media(max-width:720px){
  body{padding:10px;font-size:14px}
  .content-box{padding:12px;border-radius:10px;min-height:calc(100vh - 20px)}
  .hdr{flex-direction:column;align-items:stretch;gap:8px}
  .hdr h1{font-size:1rem}
  .hdr .sub{font-size:.7rem}
  .st{grid-template-columns:1fr;gap:8px}
  .st-box{padding:12px}
  .st-box .n{font-size:1.2rem}
  .gc{grid-template-columns:1fr;gap:8px}
  .gc-item{padding:12px}
  .gc-name{font-size:.9rem}
  .gc-cnt,.gc-traf,.gc-status{font-size:.7rem}
  .tabs{overflow-x:auto;white-space:nowrap;gap:0}
  .tab{padding:8px 14px;font-size:.8rem}
  .tb{flex-direction:column;gap:8px}
  .tb input,.tb select{width:100%!important}
  .card{padding:14px;border-radius:12px;margin-bottom:12px}
  .card h2{font-size:.9rem}
  .nd{padding:10px;flex-direction:column;gap:6px}
  .nd-info{min-width:auto}
  .nd-name{font-size:.82rem}
  .nd-route{font-size:.8rem;padding:2px 8px}
  .nd-meta{font-size:.7rem;gap:6px}
  .nd-acts{width:100%;justify-content:flex-start}
  .nd-acts .btn,.nd-acts a{padding:5px 10px;font-size:.75rem}
  .nl{gap:6px}
  .btn,.btn-sm{padding:6px 12px;font-size:.8rem}
  .fg{grid-template-columns:1fr}
  .chart-section h3{font-size:.8rem}
  .brc{font-size:.75rem}
  .ft{font-size:.65rem}
  #dailyChart{height:200px!important}
}
</style>



<style>
</style>


<script defer src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.waves.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
<style>
.vanta-bg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none}
</style>
</head>
<body><div class="container"><div class="content-box">
<div class="hdr">
  <div><h1>TCP 转发管理</h1><div class="sub">v''' + VERSION + ''' · {{ rule_count }} 条规则</div></div>
  <div style="display:flex;gap:6px;flex-wrap:wrap"><a href="#addModal" class="btn btn-pri btn-sm">+ 新建</a><a href="/settings" class="btn btn-gho btn-sm" style="margin-right:4px">设置</a><a href="/logout" class="btn btn-gho btn-sm" style="margin-right:4px">退出</a><a href="/backup" class="btn btn-gho btn-sm">导出备份</a><button class="btn btn-pri btn-sm" onclick="location.reload()">刷新</button><button class="btn btn-gho btn-sm" onclick="window.location.href='/haproxy'">查看连接状态</button></div>
</div>

<div class="st">
  <div class="st-box"><div class="n">{{ total_quota }}</div><div class="l">总配额</div></div>
  <div class="st-box"><div class="n">{{ total_used }}</div><div class="l">已用流量</div></div>
  <div class="st-box"><div class="n">{{ rule_count }}</div><div class="l">转发规则</div></div>
</div>

{% if history_days %}
<div class="chart-section">
  <h3>📈 近30天流量趋势</h3>
  <div id="dailyChart" style="width:100%;height:280px;"></div>
</div>
<script>
(function(){
  var rawHistory = {{ history_days | tojson }};
  if (!rawHistory || rawHistory.length === 0) return;
  function initChart(){
    try {
      if (typeof echarts === 'undefined') { setTimeout(initChart, 500); return; }
      var chart = echarts.init(document.getElementById('dailyChart'));
      var dates = rawHistory.map(function(d) { return d.short_date; });
      var inVals = rawHistory.map(function(d) {
        return d.total_in === undefined ? 0 : d.total_in;
      });
      var outVals = rawHistory.map(function(d) {
        return d.total_out === undefined ? 0 : d.total_out;
      });
      chart.setOption({
        tooltip: {
          trigger: 'axis',
          axisPointer: { type: 'shadow' },
          formatter: function(params) {
            var raw = rawHistory[params[0].dataIndex];
            return raw.date + '<br/>' +
              '<span style="color:#00e5ff">▼ 入站:</span> ' + (raw.total_in_display || '0 MB') + '<br/>' +
              '<span style="color:#ffbb00">▲ 出站:</span> ' + (raw.total_out_display || '0 MB') + '<br/>' +
              '<span style="color:#a78bfa;font-weight:bold">合计:</span> ' + (raw.total_display || '0 MB');
          }
        },
        legend: { data: ['合计','出站','入站'], textStyle: { color: '#8899bb', fontSize: 11 }, top: 0, right: 10 },
        grid: { left: '3%', right: '4%', bottom: '15%', top: '22%', containLabel: true },
        xAxis: { type: 'category', data: dates, axisLabel: { color: '#8899bb', fontSize: 10, interval: 'auto' }, axisLine: { lineStyle: { color: '#1a2340' } } },
        yAxis: { type: 'value', name: 'MB', nameTextStyle: { color: '#8899bb', fontSize: 10 }, axisLabel: { color: '#8899bb', fontSize: 10 }, splitLine: { lineStyle: { color: 'rgba(255,255,255,0.05)' } } },
        dataZoom: dates.length > 7 ? [{
          type: 'slider',
          show: true,
          start: 0,
          end: Math.min(100, 7/dates.length*100),
          height: 20,
          bottom: 8,
          borderColor: 'rgba(0,229,255,0.2)',
          backgroundColor: 'rgba(0,229,255,0.05)',
          fillerColor: 'rgba(0,229,255,0.15)',
          handleStyle: { color: '#00e5ff' },
          textStyle: { color: '#8899bb', fontSize: 10 }
        }] : [],
        series: [
          {
            name: '合计',
            type: 'line',
            data: rawHistory.map(function(d) {
              return +((d.total_in || 0) + (d.total_out || 0)).toFixed(1);
            }),
            smooth: true,
            symbol: 'none',
            lineStyle: { width: 2, color: '#a78bfa' },
            areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [
              { offset: 0, color: 'rgba(167,139,250,0.35)' },
              { offset: 1, color: 'rgba(167,139,250,0.02)' }
            ] } },
            z: 5
          },
          {
            name: '出站',
            type: 'bar',
            stack: 'traffic',
            data: outVals,
            barWidth: '60%',
            itemStyle: {
              color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [
                { offset: 0, color: '#ffbb00' },
                { offset: 1, color: 'rgba(255,187,0,0.5)' }
              ] },
              borderRadius: [0,0,0,0]
            }
          },
          {
            name: '入站',
            type: 'bar',
            stack: 'traffic',
            data: inVals,
            barWidth: '60%',
            itemStyle: {
              color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [
                { offset: 0, color: '#00e5ff' },
                { offset: 1, color: 'rgba(0,229,255,0.5)' }
              ] },
              borderRadius: [4,4,0,0]
            }
          }
        ]
      });
      window.addEventListener('resize', function(){ chart.resize(); });
    } catch(e) { console.error('Chart error:', e); }
  }
  if (typeof echarts !== 'undefined') initChart();
  else setTimeout(initChart, 200);
})();
</script>
{% endif %}

<div class="tabs">
  <a href="/" class="tab{% if view == 'groups' or not view %} act{% endif %}">分组视图</a>
  <a href="/?view=all" class="tab{% if view == 'all' %} act{% endif %}">全部节点</a>
</div>

{% if view == 'all' %}
  <div class="card">
    <div class="tb">
      <form method="get" action="/" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <input type="hidden" name="view" value="all">
        <input name="q" placeholder="搜索名称/IP/端口..." value="{{ q }}" style="width:200px">
        <select name="status">
          <option value="all"{% if sf=='all' %} selected{% endif %}>全部状态</option>
          <option value="online"{% if sf=='online' %} selected{% endif %}>在线</option>
          <option value="offline"{% if sf=='offline' %} selected{% endif %}>离线</option>
          <option value="expired"{% if sf=='expired' %} selected{% endif %}>过期</option>
          <option value="quota"{% if sf=='quota' %} selected{% endif %}>耗尽</option>
        </select>
        <button class="btn btn-pri btn-sm" type="submit">搜索</button>
              <button class="btn btn-pri btn-sm" type="button" id="checkAllBtn" onclick="checkAllNodes()">一键检测</button>
        <a href="/?view=all" class="btn btn-gho btn-sm">清除</a>
      </form>
      <div style="font-size:.75rem;color:var(--text2)">{{ filtered|length }} 条</div>
    </div>
    <div class="nl">
    {% for item in filtered %}
      <div class="nd">
        <div class="nd-info">
          <div class="nd-name">
            <span class="bdg{% if item.expired %} bdg-exp{% elif item.quota>0 and item.used>=item.quota*1024 %} bdg-quota{% elif item.online %} bdg-on{% else %} bdg-off{% endif %}">
              {% if item.expired %}已过期{% elif item.quota>0 and item.used>=item.quota*1024 %}流量耗尽{% elif item.online %}在线{% else %}离线{% endif %}
            </span>
            {{ item.name }}
            <span class="grp-tag">{{ item.group }}</span><span class="cr" data-idx="{{ item._idx }}"></span>
          </div>
          <div class="nd-route">{{ item.local }} → {{ item.ip }}:{{ item.port }}</div>
          <div class="nd-meta">
            {% if item.expire_time_display %}<span>{{ item.expire_time_display }}</span>{% endif %}
            <span style="color:var(--cyan)">▼入 {{ item.used_in_display }}</span>
            <span style="color:var(--gold)">▲出 {{ item.used_out_display }}</span>
            <span>{% if item.quota > 0 %}<span class="pb"><span class="pf" style="width:{% if item.quota>0 %}{{ (item.used/(item.quota*1024)*100)|int }}{% else %}0{% endif %}%"></span></span> {{ "%.1f"|format(item.used) }} MB / {{ item.quota }} GB{% else %}不限量{% endif %}</span>
          </div>
        </div>
        <div class="nd-acts" style="display:flex;gap:4px;flex-wrap:wrap;align-items:center"><div style="display:flex;gap:4px">
          <button class="btn btn-gho btn-sm check-btn" data-idx="{{ item._idx }}" onclick="checkNode(this)">检测</button>
          <a href="/edit_page/{{ item._idx }}" class="btn btn-gho btn-sm">编辑</a>
          <a href="/reset_quota/{{ item._idx }}" class="btn btn-gho btn-sm" onclick="return confirm('确定？')">重置</a>
          <a href="/killport/{{ item.local }}" class="btn btn-gho btn-sm" onclick="return confirm('确定？')">清端口</a><a href="/restart/{{ item.local }}" class="btn btn-gho btn-sm">重启</a>
          </div>
          <a href="javascript:void(0)" class="btn btn-dgr btn-sm" style="margin-left:24px" onclick="deleteNode({{ item._idx }}, this)">删除</a>
        </div>
      </div>
    {% endfor %}
    {% if filtered|length == 0 %}<div style="text-align:center;padding:30px;color:var(--text2)">暂无规则</div>{% endif %}
    </div>
  </div>
{% elif view == 'detail' and group_filter %}
  <div class="brc"><a href="/">所有分组</a> / {{ group_filter }}</div>
  <div class="card">
    <div class="tb">
      <form method="get" action="/" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <input type="hidden" name="group" value="{{ group_filter }}">
        <input name="q" placeholder="搜索..." value="{{ q }}" style="width:200px">
        <select name="status">
          <option value="all"{% if sf=='all' %} selected{% endif %}>全部</option>
          <option value="online"{% if sf=='online' %} selected{% endif %}>在线</option>
          <option value="offline"{% if sf=='offline' %} selected{% endif %}>离线</option>
          <option value="expired"{% if sf=='expired' %} selected{% endif %}>过期</option>
          <option value="quota"{% if sf=='quota' %} selected{% endif %}>耗尽</option>
        </select>
        <button class="btn btn-pri btn-sm" type="submit">搜索</button>
              <button class="btn btn-pri btn-sm" type="button" id="checkAllBtn2" onclick="checkAllNodes()">一键检测</button>
      </form>
      <div style="font-size:.75rem;color:var(--text2)">{{ filtered|length }} 条</div>
    </div>
    <div class="nl">
    {% for item in filtered %}
      <div class="nd">
        <div class="nd-info">
          <div class="nd-name">
            <span class="bdg{% if item.expired %} bdg-exp{% elif item.quota>0 and item.used>=item.quota*1024 %} bdg-quota{% elif item.online %} bdg-on{% else %} bdg-off{% endif %}">
              {% if item.expired %}已过期{% elif item.quota>0 and item.used>=item.quota*1024 %}流量耗尽{% elif item.online %}在线{% else %}离线{% endif %}
            </span>
            {{ item.name }}<span class="cr" data-idx="{{ item._idx }}"></span>
          </div>
          <div class="nd-route">{{ item.local }} → {{ item.ip }}:{{ item.port }}</div>
          <div class="nd-meta">
            {% if item.expire_time_display %}<span>{{ item.expire_time_display }}</span>{% endif %}
            <span style="color:var(--cyan)">▼入 {{ item.used_in_display }}</span>
            <span style="color:var(--gold)">▲出 {{ item.used_out_display }}</span>
            <span>{% if item.quota > 0 %}<span class="pb"><span class="pf" style="width:{% if item.quota>0 %}{{ (item.used/(item.quota*1024)*100)|int }}{% else %}0{% endif %}%"></span></span> {{ "%.1f"|format(item.used) }} MB / {{ item.quota }} GB{% else %}不限量{% endif %}</span>
          </div>
        </div>
        <div class="nd-acts" style="display:flex;gap:4px;flex-wrap:wrap;align-items:center"><div style="display:flex;gap:4px">
          <button class="btn btn-gho btn-sm check-btn" data-idx="{{ item._idx }}" onclick="checkNode(this)">检测</button>
          <a href="/edit_page/{{ item._idx }}" class="btn btn-gho btn-sm">编辑</a>
          <a href="/reset_quota/{{ item._idx }}" class="btn btn-gho btn-sm" onclick="return confirm('确定？')">重置</a>
          <a href="/killport/{{ item.local }}" class="btn btn-gho btn-sm" onclick="return confirm('确定？')">清端口</a><a href="/restart/{{ item.local }}" class="btn btn-gho btn-sm">重启</a>
          </div>
          <a href="javascript:void(0)" class="btn btn-dgr btn-sm" style="margin-left:24px" onclick="deleteNode({{ item._idx }}, this)">删除</a>
        </div>
      </div>
    {% endfor %}
    </div>
  </div>
{% else %}
  <div class="gc">
  {% for g in sorted_groups %}
    <a href="/?group={{ g.name | urlencode }}" class="gc-item">
      <div class="gc-name">{{ g.name }}</div>
      <div class="gc-cnt">{{ g.count }} 条规则</div>
      <div class="gc-bar"><div class="gc-fill" style="width:{{ g.bar_pct }}%"></div></div>
      <div class="gc-traf">已用 {{ g.used_str }}</div>
      <div class="gc-inout" style="font-size:.68rem;color:var(--text2);margin-top:2px">
        <span style="color:var(--cyan)">▼入 {{ g.in_str }}</span>
        <span style="color:var(--gold);margin-left:8px">▲出 {{ g.out_str }}</span>
      </div>
      <div class="gc-status">{{ g.status_dots | safe }}</div>
    </a>
  {% endfor %}
  </div>
{% endif %}

<div id="addModal" class="modal">
  <div class="modal-card">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h3 style="margin:0;font-size:1rem;font-weight:700">新建转发规则</h3>
      <a href="#" class="btn btn-gho btn-sm">X</a>
    </div>
    <div class="text-secondary small mb-3" style="line-height:1.5">
      名称前缀自动归组：美区-美区 香港-香港 泰国-泰国 马来-马来西亚 日区-日区
    </div>
    <form method="post" action="/add">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <div><label style="font-size:.75rem;color:var(--text2);display:block;margin-bottom:3px">备注名称</label>
          <input name="name" placeholder="香港-01" required style="width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.85rem;outline:none"></div>
        <div><label style="font-size:.75rem;color:var(--text2);display:block;margin-bottom:3px">本地端口</label>
          <input name="local" placeholder="留空自动分配" style="width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.85rem;outline:none"></div>
        <div><label style="font-size:.75rem;color:var(--text2);display:block;margin-bottom:3px">目标 IP</label>
          <input name="ip" placeholder="1.2.3.4" required style="width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.85rem;outline:none"></div>
        <div><label style="font-size:.75rem;color:var(--text2);display:block;margin-bottom:3px">目标端口</label>
          <input name="port" placeholder="443" required style="width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.85rem;outline:none"></div>
        <div><label style="font-size:.75rem;color:var(--text2);display:block;margin-bottom:3px">流量配额 GB <span style="font-size:.65rem;color:var(--text2);float:right;font-weight:normal">0=不限量</span></label>
          <input name="quota" value="10" step="0.5" min="0" style="width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.85rem;outline:none"></div>
        <div><label style="font-size:.75rem;color:var(--text2);display:block;margin-bottom:3px">过期时间 <span style="font-size:.65rem;color:var(--text2);float:right;font-weight:normal">留空=30天</span></label>
          <input type="text" name="expire" id="fp_main" style="width:100%;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.85rem;outline:none"><script>flatpickr("#fp_main",{enableTime:true,dateFormat:"Y-m-d H:i",locale:"zh"})</script></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:14px">
        <button class="btn btn-pri" type="submit" style="flex:1">添加</button>
        <a href="#" class="btn btn-gho" style="flex:1;text-align:center">取消</a>
      </div>
    </form>
    <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
      <span onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display=='none'?'':'none'" class="btn btn-gho btn-sm" style="cursor:pointer;width:100%;text-align:center;display:block">批量导入</span>
      <div style="display:none;margin-top:8px">
        <form method="post" action="/batch_add">
        <div class="text-secondary small mb-2" style="font-size:.7rem">每行一条，格式: 名称:本地端口:目标IP:目标端口</div>
        <textarea name="batch_data" rows="3" style="width:100%;padding:8px;border-radius:6px;border:1px solid var(--border);background:rgba(0,0,0,0.4);color:var(--text);font-size:.75rem;font-family:monospace;outline:none;resize:vertical" placeholder="香港1:35957:1.2.3.4:443"></textarea>
        <button class="btn btn-pri btn-sm mt-2" type="submit" style="margin-top:6px">导入</button>
        </form>
      </div>
    </div>
  </div>
</div>
</div>
<div class="ft">流量超额/到期自动断连</div>
</div>
<div class="vanta-bg" id="vantaBg"></div>
<script>
function checkNode(btn){
  var idx = btn.getAttribute('data-idx');
  var orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '检测中...';
  fetch('/check/' + idx).then(function(r){ return r.json(); }).then(function(d){
    if(d.ok){
      btn.innerHTML = '✅ ' + d.ms + 'ms';
      btn.style.color = '#00ff88';
    } else {
      btn.innerHTML = '❌ 超时';
      btn.style.color = '#ff2255';
      btn.title = d.error || '不可达';
    }
    setTimeout(function(){
      btn.innerHTML = orig;
      btn.style.color = '';
      btn.disabled = false;
    }, 5000);
  }).catch(function(){
    btn.innerHTML = '❌ 失败';
    setTimeout(function(){ btn.innerHTML = orig; btn.style.color = ''; btn.disabled = false; }, 3000);
  });
}
function checkAllNodes(){
  var btn = document.getElementById('checkAllBtn') || document.getElementById('checkAllBtn2');
  if(!btn) return;
  btn.disabled = true;
  btn.textContent = '检测中...';
  document.querySelectorAll('.cr').forEach(function(el){ el.textContent = '...'; el.style.color = '#8899bb'; });
  fetch('/check_all').then(function(r){ return r.json(); }).then(function(data){
    if(!data.ok){ btn.textContent = '失败'; btn.disabled = false; return; }
    var results = data.results;
    var ok = 0, fail = 0;
    document.querySelectorAll('.cr').forEach(function(el){
      var idx = el.getAttribute('data-idx');
      var r = results && results[idx];
      if(!r) return;
      if(r.ok){
        el.textContent = 'OK ' + r.ms + 'ms';
        el.style.color = '#00ff88'; ok++;
      } else {
        el.textContent = 'FAIL'; el.style.color = '#ff2255'; el.title = r.error || ''; fail++;
      }
    });
    btn.textContent = '重测(' + ok + '/' + fail + ')';
    btn.disabled = false;
  }).catch(function(){ btn.textContent = 'Err'; btn.disabled = false; });

}
function deleteNode(idx, el){
  if(!confirm('确定删除该节点？')) return;
  var nd = el.closest ? el.closest('.nd') : null;
  if(!nd && el.parentNode){ nd = el.parentNode; while(nd && !nd.classList.contains('nd')) nd = nd.parentNode; }
  fetch('/del/' + idx).then(function(r){ return r.json(); }).then(function(d){
    if(d.ok && nd) nd.remove();
  }).catch(function(){});
  return false;
}
(function(){
  function initVanta(){
    try{
      if(typeof THREE==='undefined'||typeof VANTA==='undefined'){setTimeout(initVanta,500);return;}
      VANTA.WAVES({el:"#vantaBg",color:0x2a6f8f,color2:0x3a8faf,waveHeight:25,shininess:40,zoom:0.8});
    }catch(e){console.warn('Vanta:',e.message);}
  }
  if(document.readyState==='complete') initVanta();
  else window.addEventListener('load',initVanta);
})();
</script>




<script>
function upgradePanel(){
  if(!confirm('确定升级面板？')) return;
  var btn=event.target;
  btn.disabled=true;btn.textContent='升级中...';
  fetch('/upgrade',{method:'POST'}).then(function(r){return r.json();}).then(function(j){
    alert(j.msg);
    if(j.ok)setTimeout(function(){location.reload();},2000);
    else{btn.disabled=false;btn.textContent='升级';}
  });
}
function showHAProxy(){
  var el=document.getElementById('hapStatus');
  if(el&&el.style.display!=='none'){el.style.display='none';return;}
  if(el&&el.style.display==='none'){el.style.display='block';return;}
  var d=document.createElement('div');
  d.id='hapStatus';
  d.style.cssText='background:rgba(13,19,38,0.95);border:1px solid rgba(26,35,64,0.8);border-radius:10px;padding:16px;margin-top:16px';
  d.innerHTML='<div style=font-size:14px;font-weight:600;margin-bottom:12px;color:#d0daf0>HAProxy Status</div><div id=hapLoad style=color:#8899bb;font-size:13px>Loading...</div>';
  document.querySelector('.container').appendChild(d);
  fetch('/api/haproxy').then(function(r){return r.json();}).then(function(r){
    if(!r.ok){document.getElementById('hapLoad').innerHTML='Error: '+r.error;return;}
    var h='<div style=color:#8899bb;font-size:12px;margin-bottom:8px>'+r.total+' backends</div><div style=font-size:12px;color:#d0daf0>';
    r.backends.forEach(function(b){
      var s=b.status||'DOWN';var c=s==='UP'?'#00ff88':(s==='DOWN'?'#ff2255':'#ffbb00');
      h+='<div style=display:flex;gap:10px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:12px>'+
        '<span style=min-width:50px>'+(b.svname||'')+'</span>'+
        '<span style=min-width:140px;color:#8899bb>'+(b.saddr||'')+'</span>'+
        '<span style=color:'+c+'>'+s+'</span>'+
        '<span style=color:#8899bb;margin-left:auto>Cur:'+(b.scur||'0')+'</span></div>';
    });
    document.getElementById('hapLoad').innerHTML=h+'</div>';
  });
}
</script>
</body>
</html>
'''

EDIT_HTML = '''
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>编辑规则</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/themes/dark.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/l10n/zh.js"></script>
<style>
.flatpickr-calendar{background:var(--card)!important;border-color:var(--border)!important;box-shadow:0 4px 24px rgba(0,0,0,.4)!important}
.flatpickr-months .flatpickr-month,.flatpickr-weekdays,.flatpickr-weekday{background:var(--card)!important;color:var(--text2)!important}
.flatpickr-day{color:var(--text)!important}
.flatpickr-day.today{border-color:var(--cyan)!important}
.flatpickr-day.selected,.flatpickr-day.startRange,.flatpickr-day.endRange,.flatpickr-day.inRange{background:var(--cyan)!important;border-color:var(--cyan)!important;color:#000!important}
.flatpickr-day:hover{background:rgba(0,229,255,.15)!important;border-color:transparent!important}
.flatpickr-day.flatpickr-disabled,.flatpickr-day.flatpickr-disabled:hover{color:var(--text2)!important;opacity:.4!important}
.flatpickr-time input{color:var(--text)!important;background:rgba(0,0,0,.3)!important}
.flatpickr-time .flatpickr-am-pm{color:var(--text2)!important}
.flatpickr-time .flatpickr-am-pm:hover{background:rgba(0,229,255,.15)!important}
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(145deg,#0f172a,#1e293b);color:#f1f5f9;font-family:system-ui;padding:20px;min-height:100vh}
.container{max-width:520px;margin:0 auto}
.card{background:rgba(255,255,255,0.05);backdrop-filter:blur(12px);border-radius:24px;border:1px solid rgba(255,255,255,0.1);padding:24px;margin-bottom:16px}
h2{font-size:1.3rem;margin-bottom:20px}
h2 span{color:#667eea;font-weight:700}
label{display:block;color:#94a3b8;font-size:.8rem;margin:14px 0 6px}
input,textarea{width:100%;padding:10px 14px;border-radius:40px;border:1px solid rgba(255,255,255,0.1);background:rgba(0,0,0,0.3);color:#f1f5f9;font-size:.9rem;box-sizing:border-box}
input:focus,textarea:focus{outline:none;border-color:#667eea}
textarea{border-radius:16px;resize:vertical;min-height:60px}
.help{background:rgba(255,255,255,0.03);border-radius:12px;padding:10px 12px;margin:8px 0;font-size:.8rem;color:#94a3b8;border-left:3px solid #667eea;line-height:1.5}
.actions{display:flex;gap:12px;margin-top:24px}
.btn{background:#667eea;color:#fff;border:none;border-radius:40px;padding:12px;font-size:1rem;cursor:pointer;font-weight:600;flex:1;text-align:center}
.btn:hover{filter:brightness(1.05)}
.btn2{background:rgba(255,255,255,0.08);color:#f1f5f9;border:none;border-radius:40px;padding:12px;font-size:1rem;text-decoration:none;text-align:center;display:block;flex:1}
</style>


<style>
</style>


<script defer src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.waves.min.js"></script>
<script defer src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
<style>
.vanta-bg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none}
</style>
</head><body><div class="container"><div class="content-box">
<div class="card">
<h2>编辑: <span>{{ name }}</span></h2>
<form method="post"><label>备注名称</label><input name="name" value="{{ name }}" required>
<label>本地端口</label><input name="local" value="{{ local }}" required>
<label>目标IP</label><input name="ip" value="{{ ip }}" required>
<label>目标端口</label><input name="port" value="{{ port }}" required>
<label>过期时间（可选）</label><input type="text" name="expire" value="{{ expire }}" id="fp_edit"><script>flatpickr("#fp_edit",{enableTime:true,dateFormat:"Y-m-d H:i",locale:"zh"})</script>
<div class="help">选择日期和时间，到期后自动断开连接。不选=永不过期。</div>
<label>流量配额（可选）</label><input name="quota" value="{{ quota }}" step="0.5" min="0" placeholder="0 = 不限量">
<div class="help">设置流量上限，单位为GB。例如：输入10表示最多使用10GB流量。输入0或不填=不限流量。超过配额自动断连。</div>
<div class="actions"><button class="btn" type="submit">保存修改</button><a class="btn2" href="/">取消</a></div></form>
</div></div>



<script>
function upgradePanel(){
  if(!confirm('确定升级面板？')) return;
  var btn=event.target;
  btn.disabled=true;btn.textContent='升级中...';
  fetch('/upgrade',{method:'POST'}).then(function(r){return r.json();}).then(function(j){
    alert(j.msg);
    if(j.ok)setTimeout(function(){location.reload();},2000);
    else{btn.disabled=false;btn.textContent='升级';}
  });
}
function showHAProxy(){
  var el=document.getElementById('hapStatus');
  if(el&&el.style.display!=='none'){el.style.display='none';return;}
  if(el&&el.style.display==='none'){el.style.display='block';return;}
  var d=document.createElement('div');
  d.id='hapStatus';
  d.style.cssText='background:rgba(13,19,38,0.95);border:1px solid rgba(26,35,64,0.8);border-radius:10px;padding:16px;margin-top:16px';
  d.innerHTML='<div style=font-size:14px;font-weight:600;margin-bottom:12px;color:#d0daf0>HAProxy Status</div><div id=hapLoad style=color:#8899bb;font-size:13px>Loading...</div>';
  document.querySelector('.container').appendChild(d);
  fetch('/api/haproxy').then(function(r){return r.json();}).then(function(r){
    if(!r.ok){document.getElementById('hapLoad').innerHTML='Error: '+r.error;return;}
    var h='<div style=color:#8899bb;font-size:12px;margin-bottom:8px>'+r.total+' backends</div><div style=font-size:12px;color:#d0daf0>';
    r.backends.forEach(function(b){
      var s=b.status||'DOWN';var c=s==='UP'?'#00ff88':(s==='DOWN'?'#ff2255':'#ffbb00');
      h+='<div style=display:flex;gap:10px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:12px>'+
        '<span style=min-width:50px>'+(b.svname||'')+'</span>'+
        '<span style=min-width:140px;color:#8899bb>'+(b.saddr||'')+'</span>'+
        '<span style=color:'+c+'>'+s+'</span>'+
        '<span style=color:#8899bb;margin-left:auto>Cur:'+(b.scur||'0')+'</span></div>';
    });
    document.getElementById('hapLoad').innerHTML=h+'</div>';
  });
}
</script>
</body></html>
'''

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset=utf-8><title>登录</title>
<style>
body{background:#0f172a;color:#f1f5f9;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1e293b;border-radius:16px;padding:32px;width:360px;border:1px solid rgba(255,255,255,.1);box-shadow:0 0 40px rgba(0,0,0,.4)}
h2{color:#d0daf0;font-weight:400;text-align:center;margin-bottom:24px}
input{width:100%;padding:10px 14px;margin:8px 0;border-radius:8px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.3);color:#f1f5f9;font-size:14px;box-sizing:border-box;outline:none}
input:focus{border-color:#667eea}
button{width:100%;padding:10px;border-radius:8px;border:none;background:#667eea;color:white;font-size:14px;cursor:pointer;margin-top:12px}
button:hover{filter:brightness(1.1)}
.error{color:#f87171;font-size:13px;text-align:center;margin-top:8px}
</style></head><body>
<div class=card><h2>登录</h2>
<form method=post>
<input name=username placeholder="账号" required>
<input name=password type=password placeholder="密码" required>
<button type=submit>登录</button>
<div style="margin-top:16px;padding-top:12px;border-top:1px solid rgba(255,255,255,0.08);font-size:12px;color:#64748b;text-align:center">初始账号: admin / admin123</div>
</form>
{% if error %}<div class=error>{{ error }}</div>{% endif %}
</div></body></html>"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username', '')
        pwd = request.form.get('password', '')
        if check_auth(user, pwd):
            session.permanent = True
            session['user'] = user
            return redirect(request.args.get('next', '/'))
        return render_template_string(LOGIN_HTML, error='账号或密码错误')
    return render_template_string(LOGIN_HTML, error='')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

SETTINGS_HTML = """<!DOCTYPE html>
<html><head><meta charset=utf-8><title>设置</title>
<style>
body{background:#0f172a;color:#f1f5f9;font-family:system-ui;padding:20px;max-width:500px;margin:0 auto}
h2{color:#d0daf0;font-weight:400}
.card{background:#1e293b;border-radius:16px;padding:24px;border:1px solid rgba(255,255,255,.1);margin-bottom:16px}
label{font-size:13px;color:#94a3b8;display:block;margin-top:12px;margin-bottom:4px}
input{width:100%;padding:8px 12px;border-radius:8px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.3);color:#f1f5f9;font-size:14px;box-sizing:border-box;outline:none}
input:focus{border-color:#667eea}
.btn{padding:8px 20px;border-radius:8px;border:none;background:#667eea;color:white;cursor:pointer;margin-top:12px;font-size:14px}
.msg{color:#6ee7b7;font-size:13px;margin-top:8px}
a{color:#60a5fa;text-decoration:none;font-size:13px}
</style></head><body>
<h2>设置</h2>
<form method=post>
<div class=card>
<h3 style="font-weight:400;margin:0 0 8px 0">端口与密码</h3>
<label>管理端口</label>
<input name=panel_port value="{{ port }}">
<label>登录账号</label>
<input name=username value="{{ username }}">
<label>登录密码</label>
<input name=password type=password placeholder="新密码(留空不改)">
<label>确认密码</label>
<input name=password2 type=password placeholder="再次输入">
</div>
<button class=btn type=submit>保存</button>
{% if msg %}<div class=msg>{{ msg }}</div>{% endif %}
</form>
<a href=/logout style="display:block;margin-top:12px;color:#f87171">退出登录</a>
</body></html>"""

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    cfg = get_config()
    if request.method == 'POST':
        np = request.form.get('panel_port', '').strip()
        nu = request.form.get('username', '').strip()
        pw = request.form.get('password', '')
        pw2 = request.form.get('password2', '')
        msg = '已保存'
        restart = False
        conn = sqlite3.connect(DB_FILE)
        if np and np.isdigit():
            conn.execute('INSERT OR REPLACE INTO config VALUES (?,?)', ('panel_port', np))
            restart = True
        if nu:
            conn.execute('INSERT OR REPLACE INTO config VALUES (?,?)', ('username', nu))
            session['user'] = nu
        if pw and pw == pw2:
            h = hashlib.sha256(pw.encode()).hexdigest()
            conn.execute('INSERT OR REPLACE INTO config VALUES (?,?)', ('password_hash', h))
        elif pw:
            msg = '两次密码不一致'
        conn.commit()
        conn.close()
        if restart:
            import subprocess as _sp
            _sp.Popen("nohup python3 /root/panel.py >/dev/null 2>&1 &", shell=True)
            _sp.Popen("(sleep 1; kill -9 " + str(os.getpid()) + ") 2>/dev/null &", shell=True)
            return redirect('http://' + request.host.rsplit(':', 1)[0] + ':' + np + '/login')
        cfg = get_config()
        return render_template_string(SETTINGS_HTML, port=cfg.get('panel_port'), username=cfg.get('username',''), msg=msg)
    return render_template_string(SETTINGS_HTML, port=cfg.get('panel_port'), username=cfg.get('username',''), msg='')

if __name__ == '__main__':
    cfg = get_config()
    port = int(cfg.get("panel_port", "8080"))
    app.run(host="0.0.0.0", port=port)
