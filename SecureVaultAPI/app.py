import hmac
import json
import logging
import math
import os
import sqlite3
import threading
import time
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, request

load_dotenv()
app = Flask(__name__)

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

VALID_API_KEY = os.getenv('VALID_API_KEY')

# Encryption at rest: secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
# before they reach the database. The key lives only in .env, never in the DB.
ENCRYPTION_KEY = os.getenv('VAULT_ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise RuntimeError("VAULT_ENCRYPTION_KEY is not set. See .env.example")
fernet = Fernet(ENCRYPTION_KEY.encode())


def api_key_valid():
    """Constant-time API key check that fails closed if VALID_API_KEY is not set."""
    if not VALID_API_KEY:
        return False
    provided = request.headers.get('X-API-Key', '')
    return hmac.compare_digest(provided.encode(), VALID_API_KEY.encode())


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


_WARN_RESULTS = {"unauthorized", "rate_limited", "blocked", "decrypt_failed"}


def audit(action, result, name=None):
    level = logging.WARNING if result in _WARN_RESULTS else logging.INFO
    logging.log(level, "AUDIT action=%s result=%s ip=%s name=%s",
                action, result, request.remote_addr, "-" if name is None else _safe(name))


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


def reset_rate_limiter():
    with _auth_lock:
        _auth_failures.clear()


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


def require_api_key(action, name=None):
    """Return an error response if the request may not proceed, else None."""
    ip = request.remote_addr
    retry = _retry_after(ip)
    if retry:
        audit(action, "rate_limited", name)
        resp = jsonify({"error": "Too many failed attempts. Try again later."})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry)
        return resp
    if not api_key_valid():
        _record_failure(ip)
        audit(action, "unauthorized", name)
        return jsonify({"error": "Unauthorized"}), 401
    return None


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    return {"message": "SecureVault API is active"}

@app.route('/add-secret', methods=['POST'])
def add_secret():
    denied = require_api_key("add")
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    name = data.get('name')
    secret = data.get('secret')
    if not name or not secret:
        audit("add", "bad_request", name)
        return jsonify({"error": "Both 'name' and 'secret' are required"}), 400
    conn = get_db_connection()
    try:
        encrypted = fernet.encrypt(secret.encode()).decode()
        conn.execute('INSERT INTO secrets (name, secret_data) VALUES (?, ?)', (name, encrypted))
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
    denied = require_api_key("get", name)
    if denied:
        return denied
    conn = get_db_connection()
    secret = conn.execute('SELECT secret_data FROM secrets WHERE name = ?', (name,)).fetchone()
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
    """Dev server on localhost only. The Werkzeug debugger allows arbitrary code
    execution, so it is off unless VAULT_DEBUG is exactly "1"."""
    if not VALID_API_KEY:
        print("[!] VALID_API_KEY is not set; all authenticated requests will be rejected. See .env.example")
    debug = os.getenv("VAULT_DEBUG") == "1"
    if debug:
        print("[!] VAULT_DEBUG=1: the Werkzeug debugger is ON. Never expose this server to a network.")
    app.run(host="127.0.0.1", port=5000, debug=debug)


if __name__ == "__main__":
    run_server()
