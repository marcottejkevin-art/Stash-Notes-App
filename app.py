from flask import session
import os
import json
import base64
import secrets
import sqlite3
import hmac
import time

from datetime import timedelta

from flask import Flask, request, redirect, render_template_string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ==================================================
# STASH
# ==================================================

APP_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(APP_DIR, "stash.db")
CONFIG_FILE = os.path.join(APP_DIR, "stash_config.json")
SESSION_SECRET_FILE = os.path.join(APP_DIR, "stash_session_secret")

app = Flask(__name__)

# ==================================================
# PWA / IPHONE APP SUPPORT
# ==================================================

PWA_HEAD = """
<link rel="manifest" href="/static/manifest.json">
<link rel="icon" href="/static/stash-icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/static/stash-icon.svg">

<meta name="theme-color" content="#111827">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Stash">
"""

@app.after_request
def add_pwa_headers(response):
    content_type = response.headers.get("Content-Type", "")

    if "text/html" in content_type:
        html = response.get_data(as_text=True)

        if "apple-mobile-web-app-capable" not in html:
            html = html.replace(
                "<head>",
                "<head>" + PWA_HEAD,
                1
            )

            response.set_data(html)

    return response



# Generate a permanent Flask secret if one doesn't exist.
if os.path.exists(SESSION_SECRET_FILE):
    with open(SESSION_SECRET_FILE, "r") as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(SESSION_SECRET_FILE, "w") as f:
        f.write(app.secret_key)
    os.chmod(SESSION_SECRET_FILE, 0o600)

app.permanent_session_lifetime = timedelta(hours=8)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
)


# The encryption key is kept only in server memory while Stash is unlocked.


# Automatically lock Stash after 15 minutes of inactivity.
AUTO_LOCK_SECONDS = 900 * 60
LAST_ACTIVITY = None


# CSRF protection token.
CSRF_TOKEN = secrets.token_urlsafe(32)

    
# Login protection
FAILED_LOGIN_ATTEMPTS = 0
LOGIN_LOCKOUT_UNTIL = 0
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60


# ==================================================
# SECURITY HEADERS
# ==================================================

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    return response




# ==================================================
# PER-BROWSER STASH SESSIONS
# ==================================================

SESSION_FERNETS = {}
SESSION_ACTIVITY = {}


def get_session_id():
    return session.get("stash_session_id")


def get_current_fernet():
    sid = get_session_id()

    if not sid:
        return None

    return SESSION_FERNETS.get(sid)


def create_stash_session(fernet):
    sid = os.urandom(32).hex()

    session.clear()
    session["stash_session_id"] = sid
    session.permanent = True

    SESSION_FERNETS[sid] = fernet
    SESSION_ACTIVITY[sid] = time.time()

    return sid


def clear_stash_session():
    sid = get_session_id()

    if sid:
        SESSION_FERNETS.pop(sid, None)
        SESSION_ACTIVITY.pop(sid, None)

    session.clear()


# ==================================================
# DATABASE
# ==================================================

@app.before_request
def check_auto_lock():
    sid = get_session_id()

    if not sid:
        return

    fernet = SESSION_FERNETS.get(sid)

    if fernet is None:
        clear_stash_session()
        return redirect("/login")

    now = time.time()
    last_activity = SESSION_ACTIVITY.get(sid)

    if last_activity is not None:
        if now - last_activity >= AUTO_LOCK_SECONDS:
            clear_stash_session()
            return redirect("/login")

    SESSION_ACTIVITY[sid] = now


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT,
            password TEXT,
            category TEXT,
            notes TEXT
        )
    """)

    db.commit()
    db.close()

    if os.path.exists(DATABASE):
        os.chmod(DATABASE, 0o600)


# ==================================================
# ENCRYPTION
# ==================================================

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=600000
    )

    derived = kdf.derive(password.encode("utf-8"))

    encryption_key = base64.urlsafe_b64encode(derived[:32])
    verifier = derived[32:]

    return encryption_key, verifier


def create_config(password):
    salt = os.urandom(16)

    encryption_key, verifier = derive_key(password, salt)

    config = {
        "salt": base64.b64encode(salt).decode(),
        "verifier": base64.b64encode(verifier).decode()
    }

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

    os.chmod(CONFIG_FILE, 0o600)


def unlock(password):
    if not os.path.exists(CONFIG_FILE):
        return None

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    salt = base64.b64decode(config["salt"])
    stored_verifier = base64.b64decode(config["verifier"])

    encryption_key, verifier = derive_key(password, salt)

    if not hmac.compare_digest(verifier, stored_verifier):
        return None

    return Fernet(encryption_key)


def encrypt(fernet, value):
    if value is None:
        value = ""

    return fernet.encrypt(
        value.encode("utf-8")
    ).decode()


def decrypt(fernet, value):
    if not value:
        return ""

    return fernet.decrypt(
        value.encode("utf-8")
    ).decode()


# ==================================================
# LOGIN PAGE
# ==================================================

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#111827">
<title>Stash</title>

<style>
* {
    box-sizing: border-box;
}

html {
    background: #111827;
}

body {
    margin: 0;
    min-height: 100vh;
    min-height: 100dvh;
    background:
        radial-gradient(circle at 50% 15%, #243b64 0%, #111827 42%, #0b1120 100%);
    color: white;
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display",
                 "SF Pro Text", Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
}

.page {
    min-height: 100vh;
    min-height: 100dvh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding:
        max(28px, env(safe-area-inset-top))
        22px
        max(28px, env(safe-area-inset-bottom));
}

.container {
    width: 100%;
    max-width: 390px;
}

.brand {
    text-align: center;
    margin-bottom: 30px;
}

.app-icon {
    width: 92px;
    height: 92px;
    margin: 0 auto 20px;
    border-radius: 24px;
    background: linear-gradient(145deg, #26334d, #111827);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 52px;
    box-shadow:
        0 18px 45px rgba(0,0,0,.35),
        inset 0 1px 1px rgba(255,255,255,.08);
}

.logo {
    font-size: 36px;
    line-height: 1.1;
    font-weight: 750;
    letter-spacing: -1px;
}

.subtitle {
    margin-top: 9px;
    color: #aab4c5;
    font-size: 16px;
}

.card {
    background: rgba(31, 41, 55, .88);
    border: 1px solid rgba(255,255,255,.07);
    padding: 25px;
    border-radius: 24px;
    box-shadow:
        0 24px 60px rgba(0,0,0,.30),
        inset 0 1px 0 rgba(255,255,255,.04);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
}

h2 {
    margin: 0 0 7px;
    text-align: center;
    font-size: 23px;
    letter-spacing: -.3px;
}

.description {
    text-align: center;
    color: #9ca3af;
    font-size: 14px;
    margin: 0 0 25px;
}

label {
    display: block;
    color: #d1d5db;
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 8px;
}

.password-wrap {
    position: relative;
    margin-bottom: 16px;
}

input[type="password"],
input[type="text"] {
    width: 100%;
    height: 54px;
    padding: 0 72px 0 16px;
    border-radius: 14px;
    border: 1px solid #374151;
    background: #111827;
    color: white;
    font-size: 17px;
    outline: none;
    -webkit-appearance: none;
}

input:focus {
    border-color: #4f8cff;
    box-shadow: 0 0 0 3px rgba(37,99,235,.20);
}

.show-password {
    position: absolute;
    right: 8px;
    top: 7px;
    width: auto;
    height: 40px;
    padding: 0 12px;
    border: none;
    border-radius: 10px;
    background: #374151;
    color: #dbeafe;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
}

.confirm-wrap {
    margin-top: 2px;
}

.unlock {
    width: 100%;
    height: 54px;
    padding: 0 18px;
    border: none;
    border-radius: 14px;
    background: linear-gradient(180deg, #3b82f6, #2563eb);
    color: white;
    font-size: 17px;
    font-weight: 650;
    letter-spacing: -.1px;
    box-shadow: 0 8px 20px rgba(37,99,235,.28);
    cursor: pointer;
    -webkit-tap-highlight-color: transparent;
}

.unlock:active {
    transform: scale(.985);
}

.error {
    background: rgba(127,29,29,.65);
    border: 1px solid rgba(248,113,113,.25);
    color: #fecaca;
    padding: 12px 14px;
    border-radius: 12px;
    margin-bottom: 17px;
    font-size: 14px;
}

.warning {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    color: #9ca3af;
    margin-top: 20px;
    font-size: 12px;
    line-height: 1.5;
    text-align: left;
}

.footer {
    text-align: center;
    color: #667085;
    font-size: 12px;
    margin-top: 22px;
}

@media (max-height: 700px) {
    .page {
        align-items: flex-start;
        padding-top: 35px;
    }

    .brand {
        margin-bottom: 20px;
    }

    .app-icon {
        width: 70px;
        height: 70px;
        font-size: 40px;
        border-radius: 19px;
        margin-bottom: 13px;
    }

    .logo {
        font-size: 30px;
    }
}

/* Folder collapse */
.category.folder-collapsed ~ .entry {
    display: none !important;
}
\n</style>
</head>

<body>

<div class="page">

<div class="container">

<div class="brand">

<div class="app-icon">
🔐
</div>

<div class="logo">Stash</div>

<div class="subtitle">Your private notes</div>

</div>

<div class="card">

{% if setup %}

<h2>Create your Stash</h2>

<p class="description">
Choose a master password to protect your notes.
</p>

{% else %}

<h2>Welcome back</h2>

<p class="description">
Unlock your private notes.
</p>

{% endif %}

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

<form method="POST">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">

<label for="master-password">
Master Password
</label>

<div class="password-wrap">

<input
    id="master-password"
    type="password"
    name="password"
    autocomplete="current-password"
    required
    autofocus
>

<button
    class="show-password"
    type="button"
    onclick="togglePassword()"
>
Show
</button>

</div>

{% if setup %}

<div class="confirm-wrap">

<label for="confirm-password">
Confirm Master Password
</label>

<div class="password-wrap">

<input
    id="confirm-password"
    type="password"
    name="confirm"
    autocomplete="new-password"
    required
>

<button
    class="show-password"
    type="button"
    onclick="toggleConfirmPassword()"
>
Show
</button>

</div>

</div>

{% endif %}

<button class="unlock" type="submit">

{% if setup %}
Create Stash
{% else %}
🔓 Unlock Stash
{% endif %}

</button>

</form>

{% if setup %}

<div class="warning">
<span>⚠️</span>
<span>
Remember your master password. There is no recovery system.
</span>
</div>

{% endif %}

</div>

<div class="footer">
🔒 Protected by your master password
</div>

</div>

</div>

<script>
function togglePassword() {
    const field = document.getElementById("master-password");
    const button = event.currentTarget;

    if (field.type === "password") {
        field.type = "text";
        button.innerText = "Hide";
    } else {
        field.type = "password";
        button.innerText = "Show";
    }
}

function toggleConfirmPassword() {
    const field = document.getElementById("confirm-password");
    const button = event.currentTarget;

    if (field.type === "password") {
        field.type = "text";
        button.innerText = "Hide";
    } else {
        field.type = "password";
        button.innerText = "Show";
    }
}

<style>
.category {
    cursor: pointer;
    user-select: none;
}

.folder-arrow {
    float: right;
    font-size: 14px;
    opacity: 0.7;
    transition: transform 0.2s ease;
}

.category.folder-collapsed .folder-arrow {
    transform: rotate(-90deg);
}
</style>

<script>
function toggleCategory(category) {
    let next = category.nextElementSibling;
    let hide = category.getAttribute("data-collapsed") !== "true";

    category.setAttribute("data-collapsed", hide ? "true" : "false");

    while (next) {
        if (next.classList.contains("category")) {
            break;
        }

        if (next.classList.contains("entry")) {
            next.style.display = hide ? "none" : "";
        }

        next = next.nextElementSibling;
    }

    const arrow = category.querySelector(".folder-arrow");
    if (arrow) {
        arrow.textContent = hide ? "▶" : "▼";
    }
}
</script>

</script>


<style>
.copy-btn {
    margin-top: 10px;
    padding: 10px 18px;
    border: 0;
    border-radius: 12px;
    background: #334155;
    color: white;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
}

.copy-btn:active {
    transform: scale(0.97);
}
</style>

<script>
    } catch (err) {
        // Fall through to the compatibility method below.
    }

    try {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.left = "-9999px";
        area.style.top = "0";
        document.body.appendChild(area);
        area.focus();
        area.select();
        area.setSelectionRange(0, area.value.length);

        const copied = document.execCommand("copy");
        document.body.removeChild(area);

        if (copied) {
            alert("Copied!");
        } else {
            alert("Copy failed. Please copy it manually.");
        }
    } catch (err) {
        alert("Copy failed. Please copy it manually.");
    }
}
</script>

</body>
</html>
"""


# ==================================================
# LOGIN
# ==================================================


def csrf_valid():
    return hmac.compare_digest(
        request.form.get("csrf_token", ""),
        CSRF_TOKEN
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    global FAILED_LOGIN_ATTEMPTS
    global LOGIN_LOCKOUT_UNTIL

    setup = not os.path.exists(CONFIG_FILE)
    error = None

    if request.method == "POST":

        now = time.time()

        if now < LOGIN_LOCKOUT_UNTIL:
            remaining = int(LOGIN_LOCKOUT_UNTIL - now) + 1
            error = f"Too many failed attempts. Try again in {remaining} seconds."

        else:

            password = request.form.get("password", "")

            if setup:

                confirm = request.form.get("confirm", "")

                if len(password) < 12:
                    error = "Master password must be at least 12 characters."

                elif password != confirm:
                    error = "The passwords do not match."

                else:
                    create_config(password)

                    fernet = unlock(password)
                    create_stash_session(fernet)

                    FAILED_LOGIN_ATTEMPTS = 0
                    LOGIN_LOCKOUT_UNTIL = 0

                    return redirect("/")

            else:

                fernet = unlock(password)

                if fernet is None:

                    FAILED_LOGIN_ATTEMPTS += 1

                    if FAILED_LOGIN_ATTEMPTS >= MAX_FAILED_LOGIN_ATTEMPTS:
                        LOGIN_LOCKOUT_UNTIL = now + LOGIN_LOCKOUT_SECONDS
                        FAILED_LOGIN_ATTEMPTS = 0
                        error = "Too many failed attempts. Try again in 60 seconds."
                    else:
                        remaining = MAX_FAILED_LOGIN_ATTEMPTS - FAILED_LOGIN_ATTEMPTS
                        error = f"Incorrect master password. {remaining} attempts remaining."

                else:

                    create_stash_session(fernet)

                    FAILED_LOGIN_ATTEMPTS = 0
                    LOGIN_LOCKOUT_UNTIL = 0

                    return redirect("/")

    return render_template_string(
        LOGIN_HTML,
        setup=setup,
        error=error,
        csrf_token=CSRF_TOKEN
    )


# ==================================================
# MAIN PAGE
# ==================================================

MAIN_HTML = """
<!DOCTYPE html>
<html lang="en">

<head>

<meta name="viewport"
      content="width=device-width, initial-scale=1, viewport-fit=cover">

<meta name="theme-color" content="#0b1220">

<title>Stash</title>

<style>

* {
    box-sizing: border-box;
}

html {
    background: #0b1220;
}

body {
    margin: 0;
    background:
        radial-gradient(
            circle at top,
            #17284a 0%,
            #0f1a2e 38%,
            #0b1220 72%
        );
    color: #f8fafc;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "SF Pro Display",
        "SF Pro Text",
        Arial,
        sans-serif;
    min-height: 100vh;
    padding-bottom: env(safe-area-inset-bottom);
}

/* --------------------------------
   HEADER
-------------------------------- */

header {
    position: sticky;
    top: 0;
    z-index: 20;

    padding:
        calc(12px + env(safe-area-inset-top))
        18px
        12px;

    background: rgba(11, 18, 32, .88);

    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);

    border-bottom: 1px solid rgba(255,255,255,.07);

    display: flex;
    align-items: center;
    justify-content: space-between;
}

.header-title {
    display: flex;
    align-items: center;
    gap: 10px;
}

.header-icon {
    width: 40px;
    height: 40px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 12px;

    background: linear-gradient(
        145deg,
        #3b82f6,
        #2563eb
    );

    font-size: 21px;

    box-shadow:
        0 6px 18px rgba(37,99,235,.25);
}

.header-name {
    font-size: 22px;
    font-weight: 750;
    letter-spacing: -.4px;
}

.lock {
    display: flex;
    align-items: center;
    gap: 6px;

    padding: 9px 12px;

    border-radius: 12px;

    color: #bfdbfe;
    background: rgba(59,130,246,.12);

    text-decoration: none;

    font-size: 14px;
    font-weight: 650;
}

/* --------------------------------
   MAIN
-------------------------------- */

.container {
    width: 100%;
    max-width: 720px;

    margin: 0 auto;

    padding:
        18px
        16px
        40px;
}

/* --------------------------------
   SEARCH
-------------------------------- */

.search-wrap {
    position: relative;
    margin-bottom: 16px;
}

.search-icon {
    position: absolute;
    left: 15px;
    top: 50%;

    transform: translateY(-50%);

    font-size: 18px;
    opacity: .7;

    pointer-events: none;
}

.search {
    width: 100%;

    margin: 0;

    padding:
        14px
        16px
        14px
        45px;

    border-radius: 15px;

    border: 1px solid rgba(255,255,255,.09);

    background: rgba(31,41,55,.78);

    color: white;

    font-size: 16px;

    outline: none;

    box-shadow:
        0 8px 24px rgba(0,0,0,.12);
}

.search::placeholder {
    color: #94a3b8;
}

.search:focus {
    border-color: #3b82f6;

    box-shadow:
        0 0 0 3px rgba(59,130,246,.16);
}

/* --------------------------------
   ADD ENTRY
-------------------------------- */

.add-card {
    margin-bottom: 22px;

    border-radius: 18px;

    background: rgba(31,41,55,.88);

    border: 1px solid rgba(255,255,255,.08);

    overflow: hidden;

    box-shadow:
        0 12px 30px rgba(0,0,0,.16);
}

.add-summary {
    list-style: none;

    cursor: pointer;

    padding: 17px 18px;

    display: flex;
    align-items: center;
    justify-content: space-between;

    font-size: 17px;
    font-weight: 700;
}

.add-summary::-webkit-details-marker {
    display: none;
}

.add-left {
    display: flex;
    align-items: center;
    gap: 10px;
}

.add-circle {
    width: 32px;
    height: 32px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 10px;

    background: #2563eb;

    font-size: 21px;
}

.chevron {
    color: #94a3b8;
    transition: transform .2s ease;
}

details[open] .chevron {
    transform: rotate(180deg);
}

.add-form {
    padding: 0 18px 18px;
    border-top: 1px solid rgba(255,255,255,.07);
}

label {
    display: block;

    margin-top: 15px;
    margin-bottom: 7px;

    font-size: 14px;
    font-weight: 650;

    color: #cbd5e1;
}

input,
textarea,
select {
    width: 100%;

    padding: 13px 14px;

    border-radius: 12px;

    border: 1px solid #374151;

    background: #111827;

    color: white;

    font-size: 16px;

    outline: none;
}

input:focus,
textarea:focus,
select:focus {
    border-color: #3b82f6;

    box-shadow:
        0 0 0 3px rgba(59,130,246,.14);
}

textarea {
    min-height: 90px;
    resize: vertical;
}

.add-button {
    width: 100%;

    margin-top: 18px;

    padding: 14px;

    border: none;
    border-radius: 13px;

    background: linear-gradient(
        135deg,
        #3b82f6,
        #2563eb
    );

    color: white;

    font-size: 16px;
    font-weight: 700;

    cursor: pointer;

    box-shadow:
        0 8px 20px rgba(37,99,235,.22);
}

/* --------------------------------
   CATEGORY
-------------------------------- */

.category {
    display: flex;
    align-items: center;
    gap: 8px;

    margin:
        25px
        4px
        10px;

    color: #bfdbfe;

    font-size: 15px;
    font-weight: 750;

    text-transform: uppercase;
    letter-spacing: .5px;
}

/* --------------------------------
   ENTRY CARD
-------------------------------- */

.entry {
    background: rgba(31,41,55,.91);

    border: 1px solid rgba(255,255,255,.07);

    padding: 17px;

    border-radius: 17px;

    margin-bottom: 12px;

    box-shadow:
        0 10px 25px rgba(0,0,0,.13);
}

.entry-name {
    font-size: 20px;
    font-weight: 750;

    letter-spacing: -.2px;

    margin-bottom: 5px;
}

.category-name {
    color: #93c5fd;

    font-size: 13px;

    margin-bottom: 15px;
}

.field {
    margin: 10px 0;

    color: #e2e8f0;

    font-size: 15px;

    word-break: break-word;
}

.field strong {
    color: #94a3b8;
}

.password-box {
    display: flex;
    gap: 8px;
    align-items: center;

    margin-top: 7px;
}

.password-box input {
    margin: 0;

    flex: 1;

    min-width: 0;

    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        monospace;

    letter-spacing: .5px;
}

.show {
    width: auto;

    flex-shrink: 0;

    padding: 11px 15px;

    background: #374151;

    color: white;

    border: none;

    border-radius: 10px;

    font-size: 14px;
    font-weight: 650;

    cursor: pointer;
}

/* --------------------------------
   ACTION BUTTONS
-------------------------------- */

.entry-actions {
    display: flex;

    gap: 10px;

    margin-top: 15px;

    width: 100%;
}

.entry-actions a,
.entry-actions form {
    flex: 1;

    margin: 0;
}

.edit-button,
.delete-button {
    width: 100%;

    min-height: 48px;

    display: flex;

    align-items: center;
    justify-content: center;

    gap: 7px;

    box-sizing: border-box;

    border-radius: 12px;

    font-size: 15px;

    font-weight: 650;

    cursor: pointer;

    text-decoration: none;
}

.edit-button {
    background: #eaf1ff;

    color: #2463d4;

    border: 1px solid #9dbcf7;
}

.delete-button {
    background: #fff0f0;

    color: #d93636;

    border: 1px solid #f0a5a5;
}

.edit-button:active,
.delete-button:active,
.show:active,
.add-button:active {
    transform: scale(.98);
}

/* --------------------------------
   NOTES
-------------------------------- */

.notes {
    margin-top: 13px;

    padding: 12px 13px;

    border-radius: 11px;

    background: rgba(15,23,42,.65);

    color: #cbd5e1;

    font-size: 14px;

    line-height: 1.45;

    white-space: pre-wrap;

    word-break: break-word;
}

/* --------------------------------
   EMPTY STATE
-------------------------------- */

.empty {
    text-align: center;

    color: #94a3b8;

    padding: 45px 20px;
}

.empty-icon {
    font-size: 42px;
    margin-bottom: 10px;
}

.empty-title {
    color: #e2e8f0;

    font-size: 18px;
    font-weight: 700;

    margin-bottom: 5px;
}

/* --------------------------------
   MOBILE
-------------------------------- */

@media (max-width: 480px) {

    .container {
        padding-left: 13px;
        padding-right: 13px;
    }

    .entry {
        padding: 16px;
    }

    .entry-name {
        font-size: 19px;
    }

}

</style>

<script>

function togglePassword(id, button) {

    const field = document.getElementById(id);

    if (field.type === "password") {

        field.type = "text";
        button.innerText = "Hide";

    } else {

        field.type = "password";
        button.innerText = "Show";

    }
}


function searchEntries() {

    const query =
        document
        .getElementById("search")
        .value
        .trim()
        .toLowerCase();

    document
        .querySelectorAll(".entry")
        .forEach(function(entry) {

            const text =
                entry.innerText.toLowerCase();

            entry.style.display =
                text.includes(query) ? "" : "none";

        });

    document
        .querySelectorAll(".category")
        .forEach(function(category) {

            let next = category.nextElementSibling;
            let found = false;

            while (next && !next.classList.contains("category")) {

                if (
                    next.classList.contains("entry") &&
                    next.style.display !== "none"
                ) {
                    found = true;
                }

                next = next.nextElementSibling;
            }

            category.style.display =
                found ? "" : "none";

        });
}


function toggleCategory(category) {
    let next = category.nextElementSibling;
    let hide = category.getAttribute("data-collapsed") !== "true";

    category.setAttribute("data-collapsed", hide ? "true" : "false");

    while (next && !next.classList.contains("category")) {
        if (next.classList.contains("entry")) {
            next.style.display = hide ? "none" : "";
        }
        next = next.nextElementSibling;
    }

    const arrow = category.querySelector(".folder-arrow");
    if (arrow) {
        arrow.textContent = hide ? "▶" : "▼";
    }
}

</script>

</head>

<body>

<header>

<div class="header-title">

<div class="header-icon">
🔐
</div>

<div class="header-name">
Stash
</div>

</div>

<a class="lock" href="/logout">
🔒 Lock
</a>

</header>


<div class="container">


<div class="search-wrap">

<div class="search-icon">
🔎
</div>

<input
    class="search"
    id="search"
    type="search"
    autocomplete="off"
    placeholder="Search Stash..."
    oninput="searchEntries()"
>

</div>


<details class="add-card">

<summary class="add-summary">

<div class="add-left">

<div class="add-circle">
＋
</div>

<span>Add Entry</span>

</div>

<div class="chevron">
⌄
</div>

</summary>


<div class="add-form">

<form action="/add" method="POST">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">


<label>Service / Name</label>

<input
    name="name"
    placeholder="Example: Steam"
    autocomplete="off"
    required
>


<label>Username</label>

<input
    name="username"
    placeholder="Username or email"
    autocomplete="off"
>


<label>Password</label>

<input
    type="password"
    name="password"
    placeholder="Password"
    autocomplete="new-password"
>


<label>Category</label>

<select name="category">

<option>Personal</option>
<option>Gaming</option>
<option>Homelab</option>
<option>Work</option>
<option>Finance</option>
<option>Shopping</option>
<option>Other</option>

</select>


<label>Notes</label>

<textarea
    name="notes"
    placeholder="Anything else you want to remember..."
></textarea>


<button
    class="add-button"
    type="submit"
>
＋ Add to Stash
</button>


</form>

</div>

</details>


{% if entries %}

{% set namespace = namespace(category="") %}

{% for entry in entries %}

{% if entry["category"] != namespace.category %}

{% set namespace.category = entry["category"] %}

<div class="category" onclick="toggleCategory(this)">
📁 {{ entry["category"] }}
<span class="folder-arrow">▼</span>
</div>

{% endif %}


<div class="entry">


<div class="entry-name">
{{ entry["name"] }}
</div>


<div class="category-name">
📁 {{ entry["category"] }}
</div>


<div class="field">

👤 <strong>Username:</strong>

<span id="username-{{ entry["id"] }}">{{ entry["username"] }}</span>
    

</div>


<div class="field">

🔑 <strong>Password:</strong>

<div class="password-box">

<input
    id="password-{{ entry['id'] }}"
    type="password"
    value="{{ entry['password'] }}"
    readonly
    autocomplete="off"
>
    

<button
    type="button"
    class="show"
    onclick="togglePassword(
        'password-{{ entry['id'] }}',
        this
    )"
>
Show
</button>

</div>

</div>


{% if entry["notes"] %}

<div class="notes">

📝 {{ entry["notes"] }}

</div>

{% endif %}


<div class="entry-actions">


<a
    class="edit-button"
    href="/edit/{{ entry['id'] }}"
>
✏️ Edit
</a>


<form
    method="post"
    action="/delete/{{ entry['id'] }}"
    onsubmit="return confirm('Delete this Stash entry? This cannot be undone.');"
>
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">

<button
    class="delete-button"
    type="submit"
>
🗑️ Delete
</button>

</form>


</div>


</div>

{% endfor %}

{% else %}

<div class="empty">

<div class="empty-icon">
🔐
</div>

<div class="empty-title">
Your Stash is empty
</div>

<div>
Tap <strong>Add Entry</strong> to save your first note.
</div>

</div>

{% endif %}


</div>

</body>
</html>
"""



# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    fernet = get_current_fernet()

    if fernet is None:
        return redirect("/login")

    db = get_db()

    rows = db.execute("""
        SELECT *
        FROM entries
        ORDER BY category, name
    """).fetchall()

    db.close()

    entries = []

    for row in rows:

        try:

            entries.append({

                "id": row["id"],

                "name": decrypt(
                    fernet,
                    row["name"]
                ),

                "username": decrypt(
                    fernet,
                    row["username"]
                ),

                "password": decrypt(
                    fernet,
                    row["password"]
                ),

                "category": decrypt(
                    fernet,
                    row["category"]
                ),

                "notes": decrypt(
                    fernet,
                    row["notes"]
                )
            })

        except Exception:
            pass

    return render_template_string(
        MAIN_HTML,
        entries=entries,
        csrf_token=CSRF_TOKEN
    )


# ==================================================
# ADD
# ==================================================

@app.route("/add", methods=["POST"])
def add():

    if not csrf_valid():
        return "Invalid request.", 403

    fernet = get_current_fernet()

    if fernet is None:
        return redirect("/login")

    name = request.form.get("name", "").strip()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    category = request.form.get("category", "Other")
    notes = request.form.get("notes", "")

    if not name:
        return redirect("/")

    db = get_db()

    db.execute("""
        INSERT INTO entries
        (name, username, password, category, notes)
        VALUES (?, ?, ?, ?, ?)
    """, (
        encrypt(fernet, name),
        encrypt(fernet, username),
        encrypt(fernet, password),
        encrypt(fernet, category),
        encrypt(fernet, notes)
    ))

    db.commit()
    db.close()

    return redirect("/")


# ==================================================
# LOCK
# ==================================================


# ==============================
# EDIT
# ==============================

@app.route("/edit/<int:entry_id>", methods=["GET", "POST"])
def edit(entry_id):
    fernet = get_current_fernet()

    if fernet is None:
        return redirect("/login")

    db = get_db()
    row = db.execute(
        "SELECT * FROM entries WHERE id = ?",
        (entry_id,)
    ).fetchone()

    if row is None:
        db.close()
        return redirect("/")

    entry = {
        "id": row["id"],
        "name": decrypt(fernet, row["name"]),
        "username": decrypt(fernet, row["username"]),
        "password": decrypt(fernet, row["password"]),
        "category": decrypt(fernet, row["category"]),
        "notes": decrypt(fernet, row["notes"]),
    }

    if request.method == "POST":
        if not csrf_valid():
            return "Invalid request.", 403

        name = request.form.get("name", "").strip()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        category = request.form.get("category", "Other")
        notes = request.form.get("notes", "")

        if not name:
            db.close()
            return "Service/Name is required.", 400

        db.execute(
            """
            UPDATE entries
            SET name=?, username=?, password=?, category=?, notes=?
            WHERE id=?
            """,
            (
                encrypt(fernet, name),
                encrypt(fernet, username),
                encrypt(fernet, password),
                encrypt(fernet, category),
                encrypt(fernet, notes),
                entry_id,
            ),
        )

        db.commit()
        db.close()

        return redirect("/")

    db.close()

    EDIT_HTML = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edit Stash Entry</title>
<style>
body {
    font-family: system-ui, sans-serif;
    max-width: 700px;
    margin: 0 auto;
    padding: 20px;
    background: #f5f5f5;
}
.card {
    background: white;
    padding: 20px;
    border-radius: 16px;
    box-shadow: 0 2px 12px rgba(0,0,0,.08);
}
input, select, textarea {
    width: 100%;
    box-sizing: border-box;
    padding: 12px;
    margin: 6px 0 14px;
    border: 1px solid #ccc;
    border-radius: 10px;
    font-size: 16px;
}
textarea {
    min-height: 120px;
    resize: vertical;
}
button, .button {
    display: inline-block;
    padding: 12px 18px;
    border: 0;
    border-radius: 10px;
    font-size: 16px;
    text-decoration: none;
    cursor: pointer;
    background: #111;
    color: white;
}
.cancel {
    background: #777;
    margin-left: 8px;
}

/* FINAL EDIT / DELETE BUTTON STYLE */
.entry-actions {
    display: flex !important;
    flex-direction: row !important;
    gap: 12px !important;
    margin-top: 18px !important;
    width: 100% !important;
}

.entry-actions a.edit-button,
.entry-actions form,
.entry-actions form button.delete-button {
    box-sizing: border-box !important;
}

.entry-actions a.edit-button {
    flex: 1 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 7px !important;
    min-height: 48px !important;
    padding: 12px 16px !important;
    border-radius: 12px !important;
    border: 1px solid #9dbcf7 !important;
    background: #eaf1ff !important;
    color: #2463d4 !important;
    text-decoration: none !important;
    font-size: 16px !important;
    font-weight: 600 !important;
}

.entry-actions form {
    flex: 1 !important;
    margin: 0 !important;
}

.entry-actions button.delete-button {
    width: 100% !important;
    min-height: 48px !important;
    padding: 12px 16px !important;
    border-radius: 12px !important;
    border: 1px solid #f0a5a5 !important;
    background: #fff0f0 !important;
    color: #d93636 !important;
    font-size: 16px !important;
    font-weight: 600 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 7px !important;
    cursor: pointer !important;
}

.entry-actions a.edit-button:active,
.entry-actions button.delete-button:active {
    transform: scale(0.98) !important;
}

</style>
</head>
<body>
<div class="card">
<h1>Edit Entry</h1>

<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">

<label>Service / Name</label>
<input name="name" value="{{ entry['name'] }}" required>

<label>Username</label>
<input name="username" value="{{ entry['username'] }}">

<label>Password</label>
<input id="password" name="password" type="password" value="{{ entry['password'] }}">

<label>
<input type="checkbox" style="width:auto"
onclick="document.getElementById('password').type=this.checked?'text':'password'">
Show password
</label>

<label>Category</label>
<select name="category">
{% for c in ["Personal","Gaming","Homelab","Work","Finance","Shopping","Other"] %}
<option value="{{ c }}" {% if entry['category'] == c %}selected{% endif %}>{{ c }}</option>
{% endfor %}
</select>

<label>Notes</label>
<textarea name="notes">{{ entry['notes'] }}</textarea>

<button type="submit">Save Changes</button>
<a class="button cancel" href="/">Cancel</a>

</form>
</div>
</body>
</html>
"""

    return render_template_string(EDIT_HTML, entry=entry, csrf_token=CSRF_TOKEN)


# ==============================
# DELETE
# ==============================

@app.route("/delete/<int:entry_id>", methods=["POST"])
def delete(entry_id):
    if not csrf_valid():
        return "Invalid request.", 403

    fernet = get_current_fernet()

    if fernet is None:
        return redirect("/login")

    db = get_db()

    db.execute(
        "DELETE FROM entries WHERE id=?",
        (entry_id,)
    )

    db.commit()
    db.close()

    return redirect("/")


@app.route("/logout")
def logout():

    clear_stash_session()

    return redirect("/login")


# ==================================================
# START
# ==================================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=5000
    )
