import sqlite3
import os
import hmac
import logging
from flask import Flask, request, jsonify, abort, render_template
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet, InvalidToken

load_dotenv()
app = Flask(__name__)

# Paths are resolved relative to this file, so the app works from any directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "app.log")
DB_PATH = os.path.join(BASE_DIR, "test_vault.db")
BLOCKLIST_PATH = os.path.join(os.path.dirname(BASE_DIR), "blocklist.txt")

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
            abort(403)
            
    except FileNotFoundError:
        # If the file doesn't exist yet, just keep going
        pass

# Root logger setup; Werkzeug's access-log lines (IP + status) also land here,
# which is what LogSentinel parses
handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3)
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

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


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    return {"message": "SecureVault API is active"}

@app.route('/add-secret', methods=['POST'])
def add_secret():
    if not api_key_valid():
        return jsonify({"error": "Unauthorized"}), 401 
    data = request.get_json(silent=True) or {}
    name = data.get('name')
    secret = data.get('secret')
    if not name or not secret:
        return jsonify({"error": "Both 'name' and 'secret' are required"}), 400
    conn = get_db_connection()
    try:
        encrypted = fernet.encrypt(secret.encode()).decode()
        conn.execute('INSERT INTO secrets (name, secret_data) VALUES (?, ?)', (name, encrypted))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": f"Secret '{name}' already exists"}), 409
    finally:
        conn.close()

    return {"message": f"Secret '{name}' saved!"}, 201

@app.route('/secret/<name>', methods=['GET'])
def get_secret(name):
    if not api_key_valid():
        logging.warning(f"401 UNAUTHORIZED: Invalid Key Attempt.")
        return jsonify({"error": "Unauthorized"}), 401
    logging.info(f"200 OK: Secret Successfully Added/Retrieved.")
    conn = get_db_connection()
    secret = conn.execute('SELECT secret_data FROM secrets WHERE name = ?', (name,)).fetchone()
    conn.close()

    if not secret:
        return jsonify({"error": "Secret not found"}), 404

    try:
        plaintext = fernet.decrypt(secret['secret_data'].encode()).decode()
    except InvalidToken:
        # Wrong key, tampered data, or a row stored before encryption was added
        logging.error(f"DECRYPTION FAILED for secret '{name}'")
        return jsonify({"error": "Secret could not be decrypted"}), 500

    return jsonify({"name": name, "secret": plaintext}), 200


if __name__ == "__main__":
    if not VALID_API_KEY:
        print("[!] VALID_API_KEY is not set; all authenticated requests will be rejected. See .env.example")
    app.run(debug=True)
