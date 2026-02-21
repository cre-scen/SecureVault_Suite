import sqlite3
import os
import logging
from xml.sax import handler
from flask import Flask, request, jsonify, abort, render_template
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler

load_dotenv()
app = Flask(__name__)

@app.before_request
def check_blocklist():
    # Read the blocklist file
    try:
        # We use '../' to look in the folder above this one
        with open("../blocklist.txt", "r") as f:
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

logging.basicConfig(handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3))
logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

VALID_API_KEY = os.getenv('VALID_API_KEY')
def get_db_connection():
    conn = sqlite3.connect('test_vault.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    return {"message": "SecureVault API is active"}

@app.route('/add-secret', methods=['POST'])
def add_secret():
    api_key = request.headers.get('X-API-Key')
    if api_key != VALID_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401 
    data = request.get_json()
    name = data.get('name')
    secret = data.get('secret')
    conn = get_db_connection()
    conn.execute('INSERT INTO secrets (name, secret_data) VALUES (?, ?)', (name, secret))
    conn.commit()
    conn.close()

    return {"message": f"Secret '{name}' saved!"}, 201

@app.route('/secret/<name>', methods=['GET'])
def get_secret(name):
    api_key = request.headers.get('X-API-Key')
    if api_key != VALID_API_KEY:
        logging.warning(f"401 UNAUTHORIZED: Invalid Key Attempt.")
        return jsonify({"error": "Unauthorized"}), 401
    logging.info(f"200 OK: Secret Successfully Added/Retrieved.")
    conn = get_db_connection()
    secret = conn.execute('SELECT secret_data FROM secrets WHERE name = ?', (name,)).fetchone()
    conn.close()

    if secret:
        return jsonify({"name": name, "secret": secret['secret_data']}), 200
    else:
        return jsonify({"error": "Secret not found"}), 404
    
app.run(debug=True) 