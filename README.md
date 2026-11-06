# SecureVault Suite

[![CI](https://github.com/cre-scen/SecureVault_Suite/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cre-scen/SecureVault_Suite/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-API-000000?logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-storage-003B57?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

A compact security "vertical slice" covering both sides of the problem: a **Flask API** that stores secrets **encrypted at rest** behind per-user API keys, and **LogSentinel**, a monitor that detects brute-force attempts against that API and blocks the source IP.

## Architecture

```
  Client ──► SecureVault API (Flask) ── writes ──► app.log
                 ▲                                │
                 │ 403 for blocked IPs            │ tails
                 │                                ▼
           blocklist.txt ◄── appends ────── LogSentinel
                                                  │
                                                  ▼
                                     threat_report.py ──► CSV digest
```

1. The API logs every request, including the client IP and status code.
2. LogSentinel tails the log and counts `401` responses **per IP** in a sliding 60-second window.
3. Five failures within the window trigger an alert, and the IP is appended to `blocklist.txt` with a timestamp and geolocation.
4. API middleware checks every request against the blocklist and returns `403 Forbidden` for blocked IPs.
5. `threat_report.py` summarises blocked IPs and origins and exports a CSV.

## Components

| Component | Description |
| :--- | :--- |
| [`SecureVaultAPI/`](SecureVaultAPI/) | Flask + SQLite secrets API with encryption at rest, per-user hashed API keys, per-owner secrets and an IP blocklist middleware |
| [`LogSentinel/`](LogSentinel/) | Real-time log monitor, brute-force detection, blocklist and threat reporting |
| [`docs/`](docs/) | [Threat model](docs/threat-model.md), [scan results](docs/security-baseline.md), weekly retrospectives |

## Quick start

```bash
git clone https://github.com/cre-scen/SecureVault_Suite.git
cd SecureVault_Suite
python -m venv venv
# Windows: venv\Scripts\activate    Linux/macOS: source venv/bin/activate
pip install -r requirements.txt

cd SecureVaultAPI
cp .env.example .env        # then set VAULT_ENCRYPTION_KEY  (Windows: copy .env.example .env)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # generates VAULT_ENCRYPTION_KEY
python db_test.py           # creates the schema, encrypts any old plaintext rows
python vault_cli.py user create martin   # prints your API key ONCE: store it now
python app.py               # terminal 1: API on http://127.0.0.1:5000
```

Upgrading a vault from before M4? Run `python vault_cli.py migrate --owner martin` instead of `user create`. It backs up the DB, gives every existing secret to that user and prints their first key. The old `VALID_API_KEY` stops working (remove it from `.env`).

In a second terminal (with the virtual environment activated):

```bash
cd LogSentinel
python sentinel.py          # terminal 2: starts monitoring app.log
```

## Running tests

```bash
pip install -r requirements-dev.txt   # from the repo root, venv active
pytest -q                             # 124 tests: per-user auth, ownership/IDOR, migration, key limits, CLI, validation, encryption, tampering, blocklist, audit log, log injection, rate limiting, debug default, LogSentinel
ruff check .
bandit -r SecureVaultAPI LogSentinel
pip-audit -r requirements.txt
```

The tests never touch your real vault: `tests/conftest.py` generates a throwaway Fernet key, creates test users `alice` and `bob` with their own keys, and points every runtime file at a temp directory through these env vars, which you can also use yourself:

| Variable | Default |
|---|---|
| `VAULT_DB_PATH` | `SecureVaultAPI/test_vault.db` |
| `VAULT_LOG_PATH` | `SecureVaultAPI/app.log` (read by LogSentinel too) |
| `VAULT_BLOCKLIST_PATH` | `blocklist.txt` in the repo root (read by the API and LogSentinel) |
| `VAULT_REPORT_PATH` | `LogSentinel/Daily_Security_Report.csv` |

If you override the log or blocklist path, set it the same way for the API and LogSentinel, or the detect-and-block loop breaks.

The LogSentinel test starts a real Werkzeug server on a random localhost port, because the Flask test client doesn't write the access-log lines LogSentinel parses.

Current scan results: [docs/security-baseline.md](docs/security-baseline.md).

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs all of the above on every PR and every push to `main`, on Python 3.11 and 3.13. Bandit runs against [`.bandit-baseline.json`](.bandit-baseline.json), which is empty since M3, so any finding fails the build. Dependabot opens weekly update PRs for pip packages and the SHA-pinned actions.

## Authentication and users

Each user has their own API keys, sent in the `X-API-Key` header. A key looks like `sv_<key_id>_<secret>`: the 12-hex `key_id` is public and appears in logs, while the 256-bit secret is shown once at creation and only its SHA-256 hash is stored. Every secret belongs to one user, so nobody can read or overwrite anyone else's.

| Endpoint | Auth | Success | Errors |
|---|---|---|---|
| `GET /` | none | `200` health check | `403` blocked IP |
| `POST /add-secret` `{"name", "secret"}` | key | `201` | `400` bad body (name 1–128 chars `A-Za-z0-9_.-`, secret a string up to 64 KB), `401`, `409` you already have that name, `413` body over 512 KB, `429` |
| `GET /secret/<name>` | key | `200` `{"name", "secret"}` | `401`, `404` not found *or not yours* (same response), `429`, `500` can't decrypt |

Every authentication failure returns the same `401 {"error": "Unauthorized"}`: missing, malformed, unknown, wrong, revoked, locked, or from a disabled user. The reason is recorded only in the audit log (`reason=`).

Limits: 5 failed attempts per IP in 60 s gives `429` (and LogSentinel bans the IP), 60 requests per key per minute gives `429`, and 10 wrong secrets for one key within 15 minutes, from any IPs, locks that key for 15 minutes.

Manage users and keys with `SecureVaultAPI/vault_cli.py`:

| Command | Does |
|---|---|
| `user create NAME` | New user and their first key (shown once) |
| `user list` | Users, key IDs and status; never secrets or hashes |
| `user disable NAME` | All their keys stop working immediately |
| `key issue NAME` | An extra key, for rotating without downtime |
| `key revoke KEY_ID` | Kill one key for good |
| `key unlock KEY_ID` | Clear a lockout |
| `migrate --owner NAME` | Upgrade a pre-M4 database |

## Demo: simulated brute-force attack

Send five requests with a wrong key within a minute (on Windows use `curl.exe`):

```bash
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code}\n" -H "X-API-Key: wrong" http://127.0.0.1:5000/secret/test
done
```

Expected result:

- The API returns `401` five times.
- LogSentinel prints `Hit detected from 127.0.0.1. Count: 1/5` … `5/5`, then a **SECURITY ALERT** banner, and blocks the IP.
- Any further request from that IP returns `403`.
- If LogSentinel isn't running, the API's own rate limiter answers the 6th attempt within the minute with `429`, even with the right key.
- `python LogSentinel/threat_report.py` prints a threat digest and writes `Daily_Security_Report.csv`.

> Testing from your own machine blocks `127.0.0.1`. Delete `blocklist.txt` to reset.

## Project structure

```
SecureVault_Suite/
├── SecureVaultAPI/
│   ├── app.py            # Flask API, encryption, auth, limits, blocklist middleware, logging
│   ├── keys.py           # API key format, generation and hashing
│   ├── schema.py         # Schema versions and the pre-M4 migration
│   ├── accounts.py       # User and key management
│   ├── vault_cli.py      # Admin CLI for users and keys
│   ├── db_test.py        # Database setup and plaintext-to-encrypted migration
│   └── .env.example
├── LogSentinel/
│   ├── sentinel.py       # Log tailing and brute-force detection
│   └── threat_report.py  # Threat digest and CSV export
├── docs/retrospectives/
├── requirements.txt
└── LICENSE
```

Runtime files (`app.log`, `blocklist.txt`, `test_vault.db`, reports) are generated locally and excluded from version control.

## Known limitations

This is a learning project, not production software:

- The encryption key sits in `.env` on the same machine as the database. Production systems keep it in a secrets manager or KMS, and rotate it.
- Every user with a key has the same powers; roles come in M5.
- Anyone who knows a key ID can lock that key with 10 wrong secrets from several IPs. The lock never touches data and expires after 15 minutes (`vault_cli.py key unlock` clears it sooner).
- It runs on Flask's development server, bound to `127.0.0.1`. The Werkzeug debugger is off unless you set `VAULT_DEBUG=1`; never do that on a reachable host.
- The per-IP and per-key request limits are in-memory and per-process, so they reset on restart. Key lockouts are stored in the database and survive restarts.
- Firewall-level blocking (M3b) is set up for the lab box only: LogSentinel pushes each ban into an expiring nftables set through a root-owned helper. See [deploy/firewall/](deploy/firewall/README.md). Anywhere else, blocking is application-level only.

The full threat model, including what is still missing and which milestone adds it, is in [docs/threat-model.md](docs/threat-model.md).

## License

[MIT](LICENSE)
