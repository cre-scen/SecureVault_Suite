# SecureVault API

A lightweight Flask API for storing and retrieving secrets, protected by API-key authentication and an IP blocklist. Part of [SecureVault Suite](../README.md).

## Features

- **Persistent storage:** SQLite, with parameterised queries throughout.
- **API-key authentication:** checks the `X-API-Key` header using a constant-time comparison. Requests are rejected if no key is configured (fails closed).
- **Secrets kept out of source:** the key is loaded from a `.env` file, which is excluded from Git.
- **IP blocklist middleware:** returns `403` for any client IP listed in `blocklist.txt` (maintained by LogSentinel).
- **Structured logging:** a rotating log file (`app.log`, 1 MB x 3) records client IP and status for every request.
- **Clear error semantics:** `400`, `401`, `403`, `404` and `409` responses with JSON error bodies.

## Endpoints

| Method | Endpoint | Auth | Success | Errors |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | None | `200` health message | |
| `POST` | `/add-secret` | `X-API-Key` | `201` created | `400` missing fields, `401`, `409` duplicate name |
| `GET` | `/secret/<name>` | `X-API-Key` | `200` secret returned | `401`, `404` not found |

Any endpoint returns `403` if the client IP is on the blocklist.

## Setup

```bash
pip install -r ../requirements.txt
cp .env.example .env      # set VALID_API_KEY to a long random value
python db_test.py         # create the table and a test record
python app.py
```

Generate a strong key with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

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

- Secrets are stored in plaintext. Encrypting at rest (e.g. with Fernet from the `cryptography` package) is the next step.
- Use a production WSGI server (e.g. Gunicorn) with `debug` disabled behind HTTPS for any real deployment.
