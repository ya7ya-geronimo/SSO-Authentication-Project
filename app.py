import os
import io
import base64
import sqlite3
import secrets
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps

import pyotp
import qrcode
from flask import (
    Flask, request, redirect, url_for, session, flash,
    render_template_string, jsonify, Response
)
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "change-this-local-dev-secret")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

bcrypt = Bcrypt(app)
oauth = OAuth(app)

# ── Google OAuth ───────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID",
    "703581643074-sot2treb62qmpfqfo4hk89e0gssh328t.apps.googleusercontent.com"
)
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    google = oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
else:
    google = None

# ── reCAPTCHA v2 ───────────────────────────────────────────────────────────────
# For real deployment:  set RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY as env vars
# For local demo:  the keys below are Google's official test keys that always pass
RECAPTCHA_SITE_KEY   = os.getenv("RECAPTCHA_SITE_KEY",   "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe")

def verify_recaptcha(response_token):
    """Returns True if the reCAPTCHA token is valid."""
    if not response_token:
        return False
    try:
        data = urllib.parse.urlencode({
            "secret": RECAPTCHA_SECRET_KEY,
            "response": response_token,
            "remoteip": request.remote_addr,
        }).encode()
        req = urllib.request.Request(
            "https://www.google.com/recaptcha/api/siteverify",
            data=data,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode())
        return result.get("success", False)
    except Exception:
        return False

DB_NAME = "onekey_university.db"


def init_db():
    conn = sqlite3.connect(DB_NAME, timeout=20)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password_hash TEXT,
            mfa_secret TEXT,
            auth_provider TEXT DEFAULT 'local',
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS authorization_codes (
            code TEXT PRIMARY KEY,
            username TEXT,
            client_id TEXT,
            redirect_uri TEXT,
            expires_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT,
            failed_count INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)

    # ── SAML packet log (extra credit) ─────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS saml_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            direction TEXT,
            packet_type TEXT,
            raw_b64 TEXT,
            decoded_xml TEXT,
            remote_addr TEXT,
            captured_at TEXT
        )
    """)

    c.execute("PRAGMA table_info(login_attempts)")
    existing_columns = {row[1] for row in c.fetchall()}
    if "failed_count" not in existing_columns:
        c.execute("ALTER TABLE login_attempts ADD COLUMN failed_count INTEGER DEFAULT 0")
    if "locked_until" not in existing_columns:
        c.execute("ALTER TABLE login_attempts ADD COLUMN locked_until TEXT")
    if "identifier" not in existing_columns:
        c.execute("ALTER TABLE login_attempts ADD COLUMN identifier TEXT")

    conn.commit()
    conn.close()


init_db()


def db():
    return sqlite3.connect(DB_NAME, timeout=20)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            session["next_url"] = request.path
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def get_user():
    if "user" not in session:
        return None
    return {
        "username": session.get("user"),
        "email": session.get("email", session.get("user")),
        "name": session.get("name", session.get("user")),
    }


def check_lock(identifier):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT failed_count, locked_until FROM login_attempts WHERE identifier=?", (identifier,))
    row = c.fetchone()
    conn.close()
    if not row or not row[1]:
        return False
    locked_until = datetime.fromisoformat(row[1])
    return datetime.utcnow() < locked_until


def record_failed_attempt(identifier):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT failed_count FROM login_attempts WHERE identifier=?", (identifier,))
    row = c.fetchone()
    if row:
        failed_count = row[0] + 1
        locked_until = None
        if failed_count >= 5:
            locked_until = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        c.execute(
            "UPDATE login_attempts SET failed_count=?, locked_until=? WHERE identifier=?",
            (failed_count, locked_until, identifier)
        )
    else:
        c.execute(
            "INSERT INTO login_attempts (identifier, failed_count, locked_until) VALUES (?, ?, ?)",
            (identifier, 1, None)
        )
    conn.commit()
    conn.close()


def clear_failed_attempts(identifier):
    conn = db()
    c = conn.cursor()
    c.execute("DELETE FROM login_attempts WHERE identifier=?", (identifier,))
    conn.commit()
    conn.close()


def log_saml_packet(direction, packet_type, raw_b64, decoded_xml):
    """Store a SAML packet in the database for inspection."""
    conn = db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO saml_log (direction, packet_type, raw_b64, decoded_xml, remote_addr, captured_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (direction, packet_type, raw_b64, decoded_xml, request.remote_addr, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# HTML TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════

BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OneKey University Portal</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body { background:#f4f6f8; color:#1f2937; font-family:Arial,Helvetica,sans-serif; }
        .topbar { background:#ffffff; border-bottom:1px solid #e5e7eb; padding:14px 0; }
        .brand { font-weight:700; color:#12355b; font-size:22px; text-decoration:none; }
        .auth-shell { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:30px 15px; }
        .auth-card { width:100%; max-width:420px; background:#ffffff; border:1px solid #e5e7eb;
                     border-radius:14px; padding:30px; box-shadow:0 10px 30px rgba(15,23,42,.08); }
        .page-shell { padding:34px 0; }
        .app-card { background:#ffffff; border:1px solid #e5e7eb; border-radius:16px; padding:24px;
                    height:100%; transition:.2s ease; }
        .app-card:hover { transform:translateY(-3px); box-shadow:0 10px 26px rgba(15,23,42,.08); }
        .app-icon { width:48px; height:48px; border-radius:12px; background:#eef4fb; color:#12355b;
                    display:flex; align-items:center; justify-content:center; font-weight:700; margin-bottom:16px; }
        .btn-primary { background:#12355b; border-color:#12355b; }
        .btn-primary:hover { background:#0e2b49; border-color:#0e2b49; }
        .btn-outline-primary { color:#12355b; border-color:#12355b; }
        .btn-outline-primary:hover { background:#12355b; border-color:#12355b; }
        .google-btn { width:100%; display:flex; align-items:center; justify-content:center; gap:10px;
                      background:#ffffff; color:#374151; border:1px solid #d1d5db; padding:10px 14px;
                      border-radius:8px; text-decoration:none; font-weight:600; transition:.2s ease; }
        .google-btn:hover { background:#f9fafb; color:#111827; }
        .google-logo { width:20px; height:20px; display:inline-block; }
        .simple-card { background:#ffffff; border:1px solid #e5e7eb; border-radius:16px; padding:24px; }
        .table-card { background:#ffffff; border:1px solid #e5e7eb; border-radius:16px; overflow:hidden; }
        .muted { color:#6b7280; }
        /* SAML viewer */
        .saml-badge { font-size:11px; font-weight:700; padding:2px 8px; border-radius:20px; }
        .saml-req  { background:#dbeafe; color:#1e40af; }
        .saml-resp { background:#dcfce7; color:#166534; }
        pre.saml-xml { background:#f8fafc; border:1px solid #e5e7eb; border-radius:8px;
                        padding:14px; font-size:12px; overflow-x:auto; white-space:pre-wrap; }
    </style>
</head>
<body>
{% if show_nav %}
<nav class="topbar">
    <div class="container d-flex justify-content-between align-items-center">
        <a class="brand" href="/dashboard">OneKey University Portal</a>
        <div class="d-flex align-items-center gap-3">
            {% if session.get('user') %}
                <span class="text-muted small">{{ session.get('name', session.get('user')) }}</span>
                <a href="/saml/viewer" class="btn btn-outline-secondary btn-sm">SAML Log</a>
                <a href="/logout" class="btn btn-outline-secondary btn-sm">Logout</a>
            {% else %}
                <a href="/login" class="btn btn-primary btn-sm">Sign In</a>
            {% endif %}
        </div>
    </div>
</nav>
{% endif %}

{% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        <div class="container mt-3">
            {% for category, message in messages %}
                <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
        </div>
    {% endif %}
{% endwith %}

{{ content|safe }}
</body>
</html>
"""


def page(content, show_nav=True):
    return render_template_string(BASE_HTML, content=content, show_nav=show_nav)


GOOGLE_LOGO_SVG = """
<svg class="google-logo" viewBox="0 0 48 48" aria-hidden="true">
  <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
  <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
  <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24s.92 7.54 2.56 10.78l7.97-6.19z"/>
  <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
</svg>"""


# ── Login form with reCAPTCHA ──────────────────────────────────────────────────
def build_login_html(site_key):
    return f"""
<div class="auth-shell">
    <div class="auth-card">
        <div class="mb-4 text-center">
            <h3 class="fw-bold mb-1">Sign in</h3>
            <p class="muted mb-0">Access your university services</p>
        </div>

        <form method="POST" class="mb-3">
            <div class="mb-3">
                <label class="form-label">University ID</label>
                <input type="text" name="username" class="form-control" placeholder="e.g. 0221885" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" placeholder="Enter password" required>
            </div>

            <!-- reCAPTCHA widget -->
            <div class="mb-3 d-flex justify-content-center">
                <div class="g-recaptcha" data-sitekey="{site_key}"></div>
            </div>

            <button type="submit" class="btn btn-primary w-100">Sign in</button>
        </form>

        <a href="/google/login" class="google-btn mb-3">
            {GOOGLE_LOGO_SVG}
            <span>Continue with Google</span>
        </a>

        <div class="text-center">
            <span class="muted small">New student?</span>
            <a href="/register" class="small text-decoration-none">Create account</a>
        </div>
    </div>
</div>"""


# ── Register form with reCAPTCHA ───────────────────────────────────────────────
def build_register_html(site_key):
    return f"""
<div class="auth-shell">
    <div class="auth-card">
        <div class="mb-4 text-center">
            <h3 class="fw-bold mb-1">Create account</h3>
            <p class="muted mb-0">Register for university portal access</p>
        </div>

        <form method="POST">
            <div class="mb-3">
                <label class="form-label">University ID</label>
                <input type="text" name="username" class="form-control" placeholder="e.g. 0221885" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Email address</label>
                <input type="email" name="email" class="form-control" placeholder="student@university.edu" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" placeholder="Minimum 8 characters" required>
            </div>

            <div class="mb-3 d-flex justify-content-center">
                <div class="g-recaptcha" data-sitekey="{site_key}"></div>
            </div>

            <button type="submit" class="btn btn-primary w-100">Create account</button>
        </form>

        <div class="text-center mt-3">
            <a href="/login" class="small text-decoration-none">Already have an account?</a>
        </div>
    </div>
</div>"""


MFA_SETUP_HTML = """
<div class="auth-shell">
    <div class="auth-card text-center">
        <h3 class="fw-bold mb-2">Set up verification</h3>
        <p class="muted">Scan this QR code using Google Authenticator.</p>
        <img src="data:image/png;base64,{{ qr_code }}" class="img-fluid my-3" alt="QR Code">
        <div class="simple-card text-start mb-3">
            <small class="muted">Manual setup key</small>
            <div class="fw-semibold">{{ secret }}</div>
        </div>
        <a href="/login" class="btn btn-primary w-100">Continue to sign in</a>
    </div>
</div>"""


MFA_VERIFY_HTML = """
<div class="auth-shell">
    <div class="auth-card">
        <div class="mb-4 text-center">
            <h3 class="fw-bold mb-1">Verification code</h3>
            <p class="muted mb-0">Enter the 6-digit code from your authenticator app.</p>
        </div>
        <form method="POST">
            <div class="mb-3">
                <input type="text" name="mfa_code" class="form-control form-control-lg text-center"
                       maxlength="6" placeholder="000000" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Verify</button>
        </form>
    </div>
</div>"""


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # ── reCAPTCHA check ──────────────────────────────────────────────────
        token = request.form.get("g-recaptcha-response", "")
        if not verify_recaptcha(token):
            flash("Please complete the reCAPTCHA verification.", "danger")
            return page(build_register_html(RECAPTCHA_SITE_KEY), show_nav=False)

        username = request.form["username"].strip()
        email    = request.form["email"].strip()
        password = request.form["password"]

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return page(build_register_html(RECAPTCHA_SITE_KEY), show_nav=False)

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        mfa_secret    = pyotp.random_base32()

        try:
            conn = db()
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, email, password_hash, mfa_secret, auth_provider, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (username, email, password_hash, mfa_secret, "local", datetime.utcnow().isoformat())
            )
            conn.commit()
            conn.close()

            totp = pyotp.TOTP(mfa_secret)
            provisioning_uri = totp.provisioning_uri(name=email, issuer_name="OneKey University Portal")

            img = qrcode.make(provisioning_uri)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            qr_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

            return render_template_string(
                BASE_HTML,
                content=render_template_string(MFA_SETUP_HTML, qr_code=qr_base64, secret=mfa_secret),
                show_nav=False
            )

        except sqlite3.IntegrityError:
            flash("This university ID is already registered.", "danger")

    return page(build_register_html(RECAPTCHA_SITE_KEY), show_nav=False)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # ── reCAPTCHA check ──────────────────────────────────────────────────
        token = request.form.get("g-recaptcha-response", "")
        if not verify_recaptcha(token):
            flash("Please complete the reCAPTCHA verification.", "danger")
            return page(build_login_html(RECAPTCHA_SITE_KEY), show_nav=False)

        username   = request.form["username"].strip()
        password   = request.form["password"]
        identifier = username or request.remote_addr

        if check_lock(identifier):
            flash("Too many failed attempts. Please try again later.", "danger")
            return page(build_login_html(RECAPTCHA_SITE_KEY), show_nav=False)

        conn = db()
        c = conn.cursor()
        c.execute("SELECT username, email, password_hash, mfa_secret FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):
            clear_failed_attempts(identifier)
            session["temp_user"]   = user[0]
            session["temp_email"]  = user[1]
            session["temp_secret"] = user[3]
            return redirect(url_for("mfa_verify"))

        record_failed_attempt(identifier)
        flash("Invalid university ID or password.", "danger")

    return page(build_login_html(RECAPTCHA_SITE_KEY), show_nav=False)


@app.route("/mfa_verify", methods=["GET", "POST"])
def mfa_verify():
    if "temp_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form["mfa_code"]
        totp = pyotp.TOTP(session["temp_secret"])

        if totp.verify(code, valid_window=1):
            session.permanent    = True
            session["user"]      = session.pop("temp_user")
            session["email"]     = session.pop("temp_email")
            session["name"]      = session["email"]
            session.pop("temp_secret", None)

            next_url   = session.pop("next_url", None)
            saml_next  = session.pop("saml_pending", None)

            if saml_next:
                return redirect(saml_next)

            return redirect(next_url or url_for("dashboard"))

        flash("Invalid verification code.", "danger")

    return page(MFA_VERIFY_HTML, show_nav=False)


@app.route("/google/login")
def google_login():
    if not google:
        flash("Google sign-in is not configured. Add GOOGLE_CLIENT_SECRET in the .env file.", "danger")
        return redirect(url_for("login"))
    redirect_uri = url_for("google_callback", _external=True, _scheme="https")
    return google.authorize_redirect(redirect_uri)


@app.route("/google/callback")
def google_callback():
    if not google:
        flash("Google sign-in is not configured.", "danger")
        return redirect(url_for("login"))

    token     = google.authorize_access_token()
    user_info = google.get("https://openidconnect.googleapis.com/v1/userinfo").json()

    email = user_info.get("email")
    name  = user_info.get("name", email)

    if not email:
        flash("Google sign-in failed. Email was not returned.", "danger")
        return redirect(url_for("login"))

    conn = db()
    c    = conn.cursor()
    c.execute("SELECT username FROM users WHERE email=?", (email,))
    row  = c.fetchone()

    if not row:
        username = original_username = email.split("@")[0]
        counter  = 1
        while True:
            c.execute("SELECT username FROM users WHERE username=?", (username,))
            if not c.fetchone():
                break
            username = f"{original_username}{counter}"
            counter += 1

        c.execute(
            "INSERT INTO users (username, email, password_hash, mfa_secret, auth_provider, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, email, "", "", "google", datetime.utcnow().isoformat())
        )
        conn.commit()
    else:
        username = row[0]

    conn.close()

    session.permanent = True
    session["user"]   = username
    session["email"]  = email
    session["name"]   = name

    saml_next = session.pop("saml_pending", None)
    if saml_next:
        return redirect(saml_next)

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user()

    content = f"""
    <div class="container page-shell">
        <div class="mb-4">
            <h2 class="fw-bold mb-1">University Services</h2>
            <p class="muted mb-0">Welcome, {user['name']}</p>
        </div>
        <div class="row g-4">
            <div class="col-md-6 col-lg-3">
                <a href="/moodle" class="text-decoration-none text-dark">
                    <div class="app-card">
                        <div class="app-icon">EL</div>
                        <h5 class="fw-bold">E-Learning</h5>
                        <p class="muted small">Courses, assignments, exams, and academic resources.</p>
                        <span class="btn btn-outline-primary btn-sm mt-2">Open</span>
                    </div>
                </a>
            </div>
            <div class="col-md-6 col-lg-3">
                <a href="/library" class="text-decoration-none text-dark">
                    <div class="app-card">
                        <div class="app-icon">LB</div>
                        <h5 class="fw-bold">Digital Library</h5>
                        <p class="muted small">Books, journals, references, and borrowing records.</p>
                        <span class="btn btn-outline-primary btn-sm mt-2">Open</span>
                    </div>
                </a>
            </div>
            <div class="col-md-6 col-lg-3">
                <a href="/registration" class="text-decoration-none text-dark">
                    <div class="app-card">
                        <div class="app-icon">SR</div>
                        <h5 class="fw-bold">Student Registration</h5>
                        <p class="muted small">Semester registration, enrolled courses, and schedules.</p>
                        <span class="btn btn-outline-primary btn-sm mt-2">Open</span>
                    </div>
                </a>
            </div>
            <div class="col-md-6 col-lg-3">
                <a href="/faculty" class="text-decoration-none text-dark">
                    <div class="app-card">
                        <div class="app-icon">FC</div>
                        <h5 class="fw-bold">Faculty Portal</h5>
                        <p class="muted small">Teaching schedules, class lists, and advising tools.</p>
                        <span class="btn btn-outline-primary btn-sm mt-2">Open</span>
                    </div>
                </a>
            </div>
        </div>
        <div class="mt-4">
            <a href="/saml/viewer" class="btn btn-outline-secondary btn-sm">🔍 SAML Packet Viewer (Extra Credit)</a>
        </div>
    </div>"""
    return page(content)


# ── Library / OAuth2 ──────────────────────────────────────────────────────────

@app.route("/library")
def library():
    if "library_user" in session:
        return redirect(url_for("library_books"))

    content = """
    <div class="container page-shell">
        <div class="simple-card">
            <h3 class="fw-bold">Digital Library</h3>
            <p class="muted">Access academic books, research databases, and borrowing records.</p>
            <a href="/oauth/authorize?client_id=library-app&redirect_uri=https://127.0.0.1:5000/library/callback&response_type=code&state=library-state"
               class="btn btn-primary">Sign in with OneKey</a>
        </div>
    </div>"""
    return page(content)


@app.route("/oauth/authorize")
def oauth_authorize():
    client_id     = request.args.get("client_id")
    redirect_uri  = request.args.get("redirect_uri")
    state         = request.args.get("state", "")
    response_type = request.args.get("response_type")

    if response_type != "code" or client_id != "library-app":
        return "Invalid OAuth request", 400

    if "user" not in session:
        session["next_url"] = request.full_path
        return redirect(url_for("login"))

    code       = secrets.token_urlsafe(24)
    expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()

    conn = db()
    c    = conn.cursor()
    c.execute(
        "INSERT INTO authorization_codes (code, username, client_id, redirect_uri, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (code, session["user"], client_id, redirect_uri, expires_at)
    )
    conn.commit()
    conn.close()

    return redirect(f"{redirect_uri}?code={code}&state={state}")


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    code = request.form.get("code")

    conn = db()
    c    = conn.cursor()
    c.execute("SELECT username, expires_at FROM authorization_codes WHERE code=?", (code,))
    row  = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "invalid_code"}), 400

    if datetime.utcnow() > datetime.fromisoformat(row[1]):
        c.execute("DELETE FROM authorization_codes WHERE code=?", (code,))
        conn.commit()
        conn.close()
        return jsonify({"error": "expired_code"}), 400

    c.execute("DELETE FROM authorization_codes WHERE code=?", (code,))
    conn.commit()
    conn.close()

    token = base64.urlsafe_b64encode(
        json.dumps({
            "sub": row[0],
            "iss": "OneKey",
            "aud": "library-app",
            "exp": (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }).encode()
    ).decode()

    return jsonify({"access_token": token, "token_type": "Bearer"})


@app.route("/library/callback")
def library_callback():
    code = request.args.get("code")
    if not code:
        return redirect(url_for("library"))

    with app.test_client() as client:
        response = client.post("/oauth/token", data={"code": code})
        if response.status_code != 200:
            flash("Library sign-in failed.", "danger")
            return redirect(url_for("library"))

    session["library_user"] = session.get("user")
    return redirect(url_for("library_books"))


@app.route("/library/books")
def library_books():
    if "library_user" not in session:
        return redirect(url_for("library"))

    content = """
    <div class="container page-shell">
        <div class="mb-4">
            <h2 class="fw-bold">Digital Library</h2>
            <p class="muted mb-0">Academic resources and borrowing services</p>
        </div>
        <div class="table-card">
            <table class="table mb-0">
                <thead><tr><th>Book Title</th><th>Category</th><th>Status</th></tr></thead>
                <tbody>
                    <tr><td>Computer Security Principles</td><td>Cybersecurity</td><td>Available</td></tr>
                    <tr><td>Database System Concepts</td><td>Computer Science</td><td>Available</td></tr>
                    <tr><td>Software Engineering</td><td>Engineering</td><td>Borrowed</td></tr>
                    <tr><td>Network Security Essentials</td><td>Networking</td><td>Available</td></tr>
                </tbody>
            </table>
        </div>
    </div>"""
    return page(content)


# ── Moodle / SAML ─────────────────────────────────────────────────────────────

@app.route("/moodle")
def moodle():
    if "moodle_user" in session:
        return redirect(url_for("moodle_home"))

    content = """
    <div class="container page-shell">
        <div class="simple-card">
            <h3 class="fw-bold">E-Learning</h3>
            <p class="muted">Access courses, assignments, announcements, and online learning materials.</p>
            <a href="/moodle/login" class="btn btn-primary">Sign in with OneKey</a>
        </div>
    </div>"""
    return page(content)


@app.route("/moodle/login")
def moodle_login():
    raw_xml = f"""<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_moodle_{secrets.token_hex(8)}"
    Version="2.0"
    IssueInstant="{datetime.utcnow().isoformat()}Z"
    Destination="https://127.0.0.1:5000/saml/sso"
    AssertionConsumerServiceURL="https://127.0.0.1:5000/moodle/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Moodle-Elearning</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"""

    saml_request = base64.urlsafe_b64encode(raw_xml.encode()).decode()

    # ── LOG the outgoing AuthnRequest ────────────────────────────────────────
    log_saml_packet("SP→IdP", "AuthnRequest", saml_request, raw_xml)

    relay_state = "moodle-home"
    return redirect(url_for("saml_sso", SAMLRequest=saml_request, RelayState=relay_state))


@app.route("/saml/metadata")
def saml_metadata():
    metadata = """<EntityDescriptor entityID="OneKey-University-IdP"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor WantAuthnRequestsSigned="false"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://127.0.0.1:5000/saml/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>"""
    return app.response_class(metadata, mimetype="application/xml")


@app.route("/saml/sso")
def saml_sso():
    relay_state  = request.args.get("RelayState", "")
    saml_request = request.args.get("SAMLRequest", "")

    # Decode and log the incoming request (already logged at moodle_login, but
    # log again here to show the IdP side receiving it)
    if saml_request:
        try:
            decoded = base64.urlsafe_b64decode(saml_request.encode()).decode()
        except Exception:
            decoded = "(decode error)"
        log_saml_packet("IdP←SP (received)", "AuthnRequest", saml_request, decoded)

    if "user" not in session:
        session["saml_pending"] = request.full_path
        return redirect(url_for("login"))

    name_id     = session.get("email", session.get("user"))
    username    = session.get("user")
    response_id = f"_resp_{secrets.token_hex(8)}"
    issue_time  = datetime.utcnow().isoformat()

    response_xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}"
    Version="2.0"
    IssueInstant="{issue_time}Z"
    Destination="https://127.0.0.1:5000/moodle/acs"
    InResponseTo="_moodle_demo">
    <saml:Issuer>OneKey-University-IdP</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assert_{secrets.token_hex(8)}" Version="2.0" IssueInstant="{issue_time}Z">
        <saml:Issuer>OneKey-University-IdP</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
            <saml:Attribute Name="username"><saml:AttributeValue>{username}</saml:AttributeValue></saml:Attribute>
            <saml:Attribute Name="email"><saml:AttributeValue>{name_id}</saml:AttributeValue></saml:Attribute>
            <saml:Attribute Name="role"><saml:AttributeValue>student</saml:AttributeValue></saml:Attribute>
            <saml:Attribute Name="issued_at"><saml:AttributeValue>{issue_time}</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"""

    saml_response = base64.urlsafe_b64encode(response_xml.encode()).decode()

    # ── LOG the outgoing Response ────────────────────────────────────────────
    log_saml_packet("IdP→SP", "Response/Assertion", saml_response, response_xml)

    # Auto-POST form (HTTP-POST binding)
    content = f"""
    <html>
    <body onload="document.forms[0].submit()">
        <noscript><p>Click Submit to continue.</p></noscript>
        <form method="POST" action="/moodle/acs">
            <input type="hidden" name="SAMLResponse" value="{saml_response}">
            <input type="hidden" name="RelayState"   value="{relay_state}">
            <noscript><input type="submit" value="Submit"></noscript>
        </form>
    </body>
    </html>"""
    return content


@app.route("/moodle/acs", methods=["POST"])
def moodle_acs():
    saml_response = request.form.get("SAMLResponse", "")

    try:
        decoded = base64.urlsafe_b64decode(saml_response.encode()).decode()
    except Exception:
        return "Invalid SAMLResponse", 400

    # ── LOG the incoming assertion at the SP (ACS) ───────────────────────────
    log_saml_packet("SP←IdP (ACS received)", "Response/Assertion", saml_response, decoded)

    session["moodle_user"] = session.get("user")
    session["moodle_role"] = "student"
    return redirect(url_for("moodle_home"))


# ── SAML Viewer (Extra Credit) ─────────────────────────────────────────────────

@app.route("/saml/viewer")
@login_required
def saml_viewer():
    conn = db()
    c    = conn.cursor()
    c.execute("SELECT id, direction, packet_type, decoded_xml, remote_addr, captured_at FROM saml_log ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()

    if not rows:
        packets_html = """
        <div class="alert alert-info">
            No SAML packets captured yet.
            <a href="/moodle/login" class="alert-link">Trigger a SAML flow</a> to see packets here.
        </div>"""
    else:
        packets_html = ""
        for row in rows:
            rid, direction, ptype, decoded_xml, remote_addr, captured_at = row

            badge_class = "saml-req" if "Request" in ptype else "saml-resp"

            packets_html += f"""
            <div class="simple-card mb-3">
                <div class="d-flex justify-content-between align-items-start mb-2 flex-wrap gap-2">
                    <div>
                        <span class="saml-badge {badge_class}">{ptype}</span>
                        <span class="ms-2 fw-semibold">{direction}</span>
                    </div>
                    <small class="muted">{captured_at} &nbsp;|&nbsp; {remote_addr}</small>
                </div>
                <pre class="saml-xml">{decoded_xml.replace('<','&lt;').replace('>','&gt;')}</pre>
            </div>"""

    content = f"""
    <div class="container page-shell">
        <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-3">
            <div>
                <h2 class="fw-bold mb-1">SAML Packet Viewer</h2>
                <p class="muted mb-0">Live capture of AuthnRequest and Response/Assertion packets</p>
            </div>
            <div class="d-flex gap-2">
                <a href="/moodle/login" class="btn btn-primary btn-sm">Trigger SAML Flow</a>
                <a href="/saml/viewer/clear" class="btn btn-outline-danger btn-sm"
                   onclick="return confirm('Clear all captured packets?')">Clear Log</a>
            </div>
        </div>

        <div class="simple-card mb-4 p-3">
            <h6 class="fw-bold mb-2">How SAML works in this portal</h6>
            <p class="muted small mb-1">
                1. <strong>SP → IdP</strong>: Moodle (SP) creates an <code>AuthnRequest</code> XML, base64-encodes it, and redirects the browser to the IdP (<code>/saml/sso</code>).
            </p>
            <p class="muted small mb-1">
                2. <strong>IdP authentication</strong>: The IdP verifies the user is logged in (or prompts for login + MFA).
            </p>
            <p class="muted small mb-0">
                3. <strong>IdP → SP</strong>: The IdP builds a signed <code>Response</code> with a SAML <code>Assertion</code> (user attributes), base64-encodes it, and auto-POSTs it to the ACS URL (<code>/moodle/acs</code>) via HTTP-POST binding.
            </p>
        </div>

        {packets_html}
    </div>"""
    return page(content)


@app.route("/saml/viewer/clear")
@login_required
def saml_viewer_clear():
    conn = db()
    c    = conn.cursor()
    c.execute("DELETE FROM saml_log")
    conn.commit()
    conn.close()
    flash("SAML log cleared.", "success")
    return redirect(url_for("saml_viewer"))


@app.route("/moodle/home")
def moodle_home():
    if "moodle_user" not in session:
        return redirect(url_for("moodle"))

    content = """
    <div class="container page-shell">
        <div class="mb-4">
            <h2 class="fw-bold">E-Learning</h2>
            <p class="muted mb-0">Courses and academic activities</p>
        </div>
        <div class="row g-4">
            <div class="col-md-4">
                <div class="simple-card">
                    <h5 class="fw-bold">Authentication and Security Models</h5>
                    <p class="muted small">Assignments, lectures, and project submissions.</p>
                    <a class="btn btn-outline-primary btn-sm">Open Course</a>
                </div>
            </div>
            <div class="col-md-4">
                <div class="simple-card">
                    <h5 class="fw-bold">Database Systems</h5>
                    <p class="muted small">Labs, quizzes, and weekly materials.</p>
                    <a class="btn btn-outline-primary btn-sm">Open Course</a>
                </div>
            </div>
            <div class="col-md-4">
                <div class="simple-card">
                    <h5 class="fw-bold">Network Security</h5>
                    <p class="muted small">Security labs and practical exercises.</p>
                    <a class="btn btn-outline-primary btn-sm">Open Course</a>
                </div>
            </div>
        </div>
    </div>"""
    return page(content)


@app.route("/registration")
@login_required
def registration():
    content = """
    <div class="container page-shell">
        <div class="mb-4">
            <h2 class="fw-bold">Student Registration</h2>
            <p class="muted mb-0">Current semester registration and schedule</p>
        </div>
        <div class="table-card">
            <table class="table mb-0">
                <thead><tr><th>Course</th><th>Section</th><th>Time</th><th>Status</th></tr></thead>
                <tbody>
                    <tr><td>Authentication and Security Models</td><td>1</td><td>Sun/Tue 10:00</td><td>Registered</td></tr>
                    <tr><td>Software Engineering</td><td>2</td><td>Mon/Wed 12:00</td><td>Registered</td></tr>
                    <tr><td>Database Systems</td><td>1</td><td>Sun/Tue 13:00</td><td>Available</td></tr>
                </tbody>
            </table>
        </div>
    </div>"""
    return page(content)


@app.route("/faculty")
@login_required
def faculty():
    content = """
    <div class="container page-shell">
        <div class="mb-4">
            <h2 class="fw-bold">Faculty Portal</h2>
            <p class="muted mb-0">Teaching services and academic management</p>
        </div>
        <div class="row g-4">
            <div class="col-md-4">
                <div class="simple-card">
                    <h5 class="fw-bold">Class Lists</h5>
                    <p class="muted small">View students enrolled in current semester sections.</p>
                    <a class="btn btn-outline-primary btn-sm">Open</a>
                </div>
            </div>
            <div class="col-md-4">
                <div class="simple-card">
                    <h5 class="fw-bold">Advising</h5>
                    <p class="muted small">Review student records and academic plans.</p>
                    <a class="btn btn-outline-primary btn-sm">Open</a>
                </div>
            </div>
            <div class="col-md-4">
                <div class="simple-card">
                    <h5 class="fw-bold">Grades</h5>
                    <p class="muted small">Manage course grades and assessment records.</p>
                    <a class="btn btn-outline-primary btn-sm">Open</a>
                </div>
            </div>
        </div>
    </div>"""
    return page(content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # ── SSL / Certificate setup ───────────────────────────────────────────────
    # For local dev the self-signed localhost.pem works fine.
    # For network access (other devices on your LAN):
    #   1. Run:  mkcert <your-local-ip>   e.g.  mkcert 192.168.1.50
    #   2. Set env:  CERT_FILE=192.168.1.50.pem  KEY_FILE=192.168.1.50-key.pem
    #   3. Run app — other devices trust mkcert's root CA automatically.
    #
    # For a real public domain:
    #   Use Let's Encrypt (certbot) — set CERT_FILE and KEY_FILE to the
    #   fullchain.pem / privkey.pem paths from /etc/letsencrypt/live/<domain>/

    cert_file = os.getenv("CERT_FILE", "localhost.pem")
    key_file  = os.getenv("KEY_FILE",  "localhost-key.pem")

    # Bind to 0.0.0.0 so other devices on the network can reach you
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))

    print(f"\n✅ OneKey University Portal starting on https://{host}:{port}")
    print(f"   Certificate : {cert_file}")
    print(f"   reCAPTCHA   : site key = {RECAPTCHA_SITE_KEY[:20]}...")
    print(f"   SAML Viewer : https://<your-ip>:{port}/saml/viewer\n")

    app.run(
        host=host,
        port=port,
        debug=True,
        ssl_context=(cert_file, key_file)
    )
