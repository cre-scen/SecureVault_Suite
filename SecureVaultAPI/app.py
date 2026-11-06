import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, abort, g, jsonify, request

import keys
from schema import CURRENT_VERSION, get_version, utc_now_iso

load_dotenv()
app = Flask(__name__)
# Request bodies over 512 KB are refused with 413 before they're parsed.
# The largest valid body is a 64 KB secret, which JSON escaping can grow a few times.
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024

# Paths are resolved relative to this file, so the app works from any directory.
# Each can be overridden with an env var (used by the tests to stay off real files).
# LOG_PATH and BLOCKLIST_PATH are shared with LogSentinel: override both sides.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.getenv("VAULT_LOG_PATH") or os.path.join(BASE_DIR, "app.log")
DB_PATH = os.getenv("VAULT_DB_PATH") or os.path.join(BASE_DIR, "test_vault.db")
BLOCKLIST_PATH = os.getenv("VAULT_BLOCKLIST_PATH") or os.path.join(os.path.dirname(BASE_DIR), "blocklist.txt")

@app.before_request
def check_blocklist():
    # Read the blocklist file
    try:
        # The blocklist lives in the folder above this one
        with open(BLOCKLIST_PATH, "r") as f:
            lines = f.read().splitlines()
            
            banned_ips = []
            for line in lines:
                ip = line.split(',')[0]  # Extract just the IP address from the line
                banned_ips.append(ip)
        
        
        # Check if the current user's IP is in that list
        if request.remote_addr in banned_ips:
            audit("request", "blocked")
            abort(403)
            
    except FileNotFoundError:
        # If the file doesn't exist yet, just keep going
        pass

# Root logger setup; Werkzeug's access-log lines (IP + status) also land here,
# which is what LogSentinel parses. The handler is attached explicitly rather than
# via logging.basicConfig(), which silently does nothing if the root logger
# already has a handler (pytest and some libraries add one).
handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3)
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
_root_logger = logging.getLogger()
_root_logger.setLevel(logging.INFO)
_root_logger.addHandler(handler)

# Pre-M4 shared key. Read only to warn that it's ignored now (design decision D4).
VALID_API_KEY = os.getenv('VALID_API_KEY')

# Encryption at rest: secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
# before they reach the database. The key lives only in .env, never in the DB.
ENCRYPTION_KEY = os.getenv('VAULT_ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise RuntimeError("VAULT_ENCRYPTION_KEY is not set. See .env.example")
fernet = Fernet(ENCRYPTION_KEY.encode())


# --- Audit logging ------------------------------------------------------------
# One line per decision, written *after* the outcome is known:
#   AUDIT action=get result=not_found ip=127.0.0.1 name=db_password
# Secret values are never logged. Anything the client controls (the secret
# name) is escaped and length-capped first: app.log is also LogSentinel's input,
# so a raw newline in a name could forge an access-log line and get an
# arbitrary IP blocked (log injection, CWE-117).
MAX_LOGGED_LEN = 100


def _safe(value):
    """Render client-controlled input as one bounded, printable-ASCII token."""
    text = json.dumps(str(value), ensure_ascii=True)[1:-1]  # escapes \n \r \x1b " \\ and non-ASCII
    if len(text) > MAX_LOGGED_LEN:
        text = text[:MAX_LOGGED_LEN] + "...[truncated]"
    return text


_WARN_RESULTS = {"unauthorized", "rate_limited", "blocked", "decrypt_failed", "locked"}


def audit(action, result, name=None, reason=None):
    """user= and key= come from the authenticated request (set in authenticate()).
    key= is the public key ID only. reason= says why auth failed; clients never see it."""
    level = logging.WARNING if result in _WARN_RESULTS else logging.INFO
    logging.log(level, "AUDIT action=%s result=%s%s ip=%s user=%s key=%s name=%s",
                action, result, "" if reason is None else f" reason={reason}",
                request.remote_addr, g.get("user_name", "-"), g.get("key_id", "-"),
                "-" if name is None else _safe(name))


# --- Failed-auth rate limiting ------------------------------------------------
# After AUTH_FAIL_LIMIT failed keys from one IP within AUTH_FAIL_WINDOW seconds,
# every authenticated request from that IP gets 429 until the oldest failure ages
# out, even one with the right key, so an attacker can't tell when a guess is
# correct. 5 in 60s matches LogSentinel: the first 5 failures still reach the log
# as 401s, so LogSentinel still blocks the IP; this covers the gap before it does
# (or when it isn't running). In-memory and per-process: it resets on restart
# and isn't shared between workers (see docs/threat-model.md).
AUTH_FAIL_LIMIT = int(os.getenv("VAULT_AUTH_FAIL_LIMIT", "5"))
AUTH_FAIL_WINDOW = int(os.getenv("VAULT_AUTH_FAIL_WINDOW", "60"))
_auth_failures = defaultdict(deque)
_auth_lock = threading.Lock()
_now = time.monotonic  # indirection so tests can control time
_wall = time.time      # wall clock, for lock times stored in the DB (must survive restarts)


def reset_rate_limiter():
    """Clear all in-memory limiter state (per-IP failures and per-key request rate).
    Key lockouts live in the DB and are deliberately not cleared here."""
    with _auth_lock:
        _auth_failures.clear()
    with _key_rate_lock:
        _key_requests.clear()


def _retry_after(ip):
    """Seconds until `ip` may try again, or 0 if it isn't rate-limited."""
    now = _now()
    with _auth_lock:
        window = _auth_failures.get(ip)
        if not window:
            return 0
        while window and now - window[0] >= AUTH_FAIL_WINDOW:
            window.popleft()
        if not window:
            del _auth_failures[ip]  # don't keep state for IPs that went quiet
            return 0
        if len(window) < AUTH_FAIL_LIMIT:
            return 0
        return max(1, math.ceil(AUTH_FAIL_WINDOW - (now - window[0])))


def _record_failure(ip):
    with _auth_lock:
        _auth_failures[ip].append(_now())


# --- Per-key limits (M4) ----------------------------------------------------
# Request rate (D6): at most KEY_RATE_LIMIT authenticated requests per key in
# KEY_RATE_WINDOW seconds. In memory, like the IP limiter.
# Lockout (D5): KEY_LOCK_THRESHOLD bad secrets for one key within
# KEY_LOCK_WINDOW seconds lock that key for KEY_LOCK_DURATION seconds, from any
# mix of IPs. Stored in the DB so a restart doesn't clear it. A lock only stops
# authentication; it never touches data. `vault_cli.py key unlock` clears it.
KEY_RATE_LIMIT = int(os.getenv("VAULT_KEY_RATE_LIMIT", "60"))
KEY_RATE_WINDOW = int(os.getenv("VAULT_KEY_RATE_WINDOW", "60"))
KEY_LOCK_THRESHOLD = int(os.getenv("VAULT_KEY_LOCK_THRESHOLD", "10"))
KEY_LOCK_WINDOW = int(os.getenv("VAULT_KEY_LOCK_WINDOW", "900"))
KEY_LOCK_DURATION = int(os.getenv("VAULT_KEY_LOCK_DURATION", "900"))
_key_requests = defaultdict(deque)
_key_rate_lock = threading.Lock()


def _key_rate_retry_after(key_id):
    """Count this request against key_id. Return 0 if allowed, else seconds to wait."""
    now = _now()
    with _key_rate_lock:
        window = _key_requests[key_id]
        while window and now - window[0] >= KEY_RATE_WINDOW:
            window.popleft()
        if len(window) >= KEY_RATE_LIMIT:
            return max(1, math.ceil(KEY_RATE_WINDOW - (now - window[0])))
        window.append(now)
        return 0


def _record_bad_secret(conn, key_id):
    """Count a bad secret; lock the key once it hits the threshold. Returns True if it locked."""
    now = _wall()
    conn.execute("DELETE FROM key_failures WHERE key_id = ? AND at <= ?", (key_id, now - KEY_LOCK_WINDOW))
    conn.execute("INSERT INTO key_failures (key_id, at) VALUES (?, ?)", (key_id, now))
    (count,) = conn.execute("SELECT COUNT(*) FROM key_failures WHERE key_id = ?", (key_id,)).fetchone()
    locked = count >= KEY_LOCK_THRESHOLD
    if locked:
        conn.execute("UPDATE api_keys SET locked_until = ? WHERE key_id = ?", (now + KEY_LOCK_DURATION, key_id))
        conn.execute("DELETE FROM key_failures WHERE key_id = ?", (key_id,))
    conn.commit()
    return locked


def _check_key(conn, header):
    """Return (row, None) for a usable key, or (None, reason) for any failure."""
    parsed = keys.parse(header)
    if parsed is None:
        return None, "malformed"
    key_id, secret = parsed
    g.key_id = key_id  # validated hex, safe to log
    try:
        row = conn.execute(
            "SELECT k.key_id, k.key_hash, k.revoked, k.locked_until, u.id AS user_id, "
            "u.name AS user_name, u.disabled FROM api_keys k JOIN users u ON u.id = k.user_id "
            "WHERE k.key_id = ?", (key_id,)).fetchone()
    except sqlite3.OperationalError:
        return None, "no_schema"  # pre-M4 DB: fail closed until it's migrated
    if row is None:
        return None, "unknown_key"
    if row["revoked"]:
        return None, "revoked"
    if row["disabled"]:
        return None, "disabled"
    if row["locked_until"] is not None and row["locked_until"] > _wall():
        return None, "locked"
    if not keys.verify(secret, row["key_hash"]):
        if _record_bad_secret(conn, key_id):
            audit("key_lock", "locked", reason="bad_secret_threshold")
        return None, "bad_secret"
    return row, None


def authenticate(action, name=None):
    """Return an error response if the request may not proceed, else None.
    On success, g.user_id / g.user_name / g.key_id identify the caller.

    Every auth failure gets the same 401 body (D2); only the audit log says why."""
    ip = request.remote_addr
    retry = _retry_after(ip)
    if retry:
        audit(action, "rate_limited", name, reason="ip_failures")
        return _too_many(retry, "Too many failed attempts. Try again later.")
    conn = get_db_connection()
    try:
        row, reason = _check_key(conn, request.headers.get("X-API-Key", ""))
        if row is not None:
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (utc_now_iso(), row["key_id"]))
            conn.commit()
    finally:
        conn.close()
    if row is None:
        _record_failure(ip)
        audit(action, "unauthorized", name, reason=reason)
        return jsonify({"error": "Unauthorized"}), 401
    g.user_id, g.user_name = row["user_id"], row["user_name"]
    retry = _key_rate_retry_after(row["key_id"])
    if retry:
        audit(action, "rate_limited", name, reason="key_rate")
        return _too_many(retry, "Too many requests for this key. Try again later.")
    return None


def _too_many(retry, message):
    resp = jsonify({"error": message})
    resp.status_code = 429
    resp.headers["Retry-After"] = str(retry)
    return resp


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# --- Input validation ----------------------------------------------------------
SECRET_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
MAX_SECRET_BYTES = 64 * 1024


def _invalid_secret_input(data):
    """Return an error message for a bad add-secret body, else None."""
    if not isinstance(data, dict):
        return "Body must be a JSON object with 'name' and 'secret'"
    name, secret = data.get("name"), data.get("secret")
    if not name or not secret:
        return "Both 'name' and 'secret' are required"
    if not isinstance(name, str) or not isinstance(secret, str):
        return "'name' and 'secret' must be strings"
    if not SECRET_NAME_RE.fullmatch(name):
        return "'name' must be 1-128 characters from A-Z a-z 0-9 _ . -"
    if len(secret.encode()) > MAX_SECRET_BYTES:
        return f"'secret' must be at most {MAX_SECRET_BYTES} bytes"
    return None


@app.route('/')
def home():
    return {"message": "SecureVault API is active"}

@app.route('/add-secret', methods=['POST'])
def add_secret():
    denied = authenticate("add")
    if denied:
        return denied
    data = request.get_json(silent=True)
    data = {} if data is None else data
    problem = _invalid_secret_input(data)
    if problem:
        audit("add", "bad_request", data.get("name") if isinstance(data, dict) else None)
        return jsonify({"error": problem}), 400
    name, secret = data["name"], data["secret"]
    conn = get_db_connection()
    try:
        encrypted = fernet.encrypt(secret.encode()).decode()
        conn.execute('INSERT INTO secrets (owner_id, name, secret_data) VALUES (?, ?, ?)',
                     (g.user_id, name, encrypted))
        conn.commit()
    except sqlite3.IntegrityError:
        audit("add", "duplicate", name)
        return jsonify({"error": f"Secret '{name}' already exists"}), 409
    finally:
        conn.close()

    audit("add", "created", name)
    return {"message": f"Secret '{name}' saved!"}, 201

@app.route('/secret/<name>', methods=['GET'])
def get_secret(name):
    denied = authenticate("get", name)
    if denied:
        return denied
    conn = get_db_connection()
    # Owner filter: another user's secret is indistinguishable from a missing one (D3)
    secret = conn.execute('SELECT secret_data FROM secrets WHERE owner_id = ? AND name = ?',
                          (g.user_id, name)).fetchone()
    conn.close()

    if not secret:
        audit("get", "not_found", name)
        return jsonify({"error": "Secret not found"}), 404

    try:
        plaintext = fernet.decrypt(secret['secret_data'].encode()).decode()
    except InvalidToken:
        # Wrong key, tampered data, or a row stored before encryption was added
        audit("get", "decrypt_failed", name)
        return jsonify({"error": "Secret could not be decrypted"}), 500

    audit("get", "ok", name)
    return jsonify({"name": name, "secret": plaintext}), 200


def run_server():
    """Dev server. Binds to 127.0.0.1 unless VAULT_HOST says otherwise (e.g. the
    lab box's LAN address, with the host firewall deciding who may connect).
    The Werkzeug debugger allows arbitrary code execution, so it is off unless
    VAULT_DEBUG is exactly "1", and it refuses to run on a non-loopback address."""
    if VALID_API_KEY:
        print("[!] VALID_API_KEY is set but ignored since M4. Remove it from .env; "
              "use per-user keys from vault_cli.py.")
    conn = get_db_connection()
    try:
        if get_version(conn) < CURRENT_VERSION:
            print("[!] Database is pre-M4; every request will get 401. "
                  "Run: python vault_cli.py migrate --owner NAME")
    finally:
        conn.close()
    host = os.getenv("VAULT_HOST", "127.0.0.1")
    port = int(os.getenv("VAULT_PORT", "5000"))
    debug = os.getenv("VAULT_DEBUG") == "1"
    if debug and host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit(f"[-] Refusing to start: VAULT_DEBUG=1 with VAULT_HOST={host} would expose the debugger.")
    if debug:
        print("[!] VAULT_DEBUG=1: the Werkzeug debugger is ON. Never expose this server to a network.")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_server()
