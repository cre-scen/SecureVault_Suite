import sqlite3
import os 
import logging
from dotenv import load_dotenv 
from flask import Flask, request, jsonify

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(message)s')

load_dotenv()
app = Flask(__name__)

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