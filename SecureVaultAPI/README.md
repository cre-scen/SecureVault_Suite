# SecureVault API

A lightweight Flask API for storing and retrieving secrets, encrypted at rest and protected by API-key authentication and an IP blocklist. Part of [SecureVault Suite](../README.md).

## Features

- **Encryption at rest:** secrets are encrypted with Fernet (AES-128-CBC with HMAC-SHA256 authentication) before they reach the database, so a stolen database file reveals nothing without the key. Tampered or wrongly keyed data is rejected, not returned.
- **Persistent storage:** SQLite, with parameterised queries throughout.
- **API-key authentication:** checks the `X-API-Key` header using a constant-time comparison. Requests are rejected if no key is configured (fails closed).
- **Secrets kept out of source:** the API key and encryption key are loaded from a `.env` file, which is excluded from Git. The app refuses to start without an encryption key.
- **IP blocklist middleware:** returns `403` for any client IP listed in `blocklist.txt` (maintained by LogSentinel).
- **Structured logging:** a rotating log file (`app.log`, 1 MB x 3) records client IP and status for every request.
- **Clear error semantics:** `400`, `401`, `403`, `404`, `409` and `500` responses with JSON error bodies.

## Endpoints

| Method | Endpoint | Auth | Success | Errors |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | None | `200` health message | |
| `POST` | `/add-secret` | `X-API-Key` | `201` created | `400` missing fields, `401`, `409` duplicate name |
| `GET` | `/secret/<name>` | `X-API-Key` | `200` secret returned | `401`, `404` not found, `500` could not be decrypted |

Any endpoint returns `403` if the client IP is on the blocklist.

## Setup

```bash
pip install -r ../requirements.txt
cp .env.example .env      # set VALID_API_KEY and VAULT_ENCRYPTION_KEY
python db_test.py         # create the table, encrypt old plaintext rows, add a test record
python app.py
```

Generate the keys with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"                          # VALID_API_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # VAULT_ENCRYPTION_KEY
```

Back up `VAULT_ENCRYPTION_KEY` securely (e.g. in a password manager). If it is lost, stored secrets cannot be recovered.

## Usage

```bash
# Store a secret
curl -X POST http://127.0.0.1:5000/add-secret \
  -H "X-API-Key: $VALID_API_KEY" -H "Content-Type: application/json" \
  -d '{"name": "db_password", "secret": "example-value"}'

# Retrieve it
curl -H "X-API-Key: $VALID_API_KEY" http://127.0.0.1:5000/secret/db_password
```

## Security notes

- Upgrading from an older version: run `python db_test.py` once. It encrypts any existing plaintext rows and is safe to re-run.
- The encryption key lives in `.env` beside the database. In production it belongs in a secrets manager or KMS, with key rotation.
- Use a production WSGI server (e.g. Gunicorn) with `debug` disabled behind HTTPS for any real deployment.
