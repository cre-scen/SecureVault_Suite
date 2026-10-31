# SecureVault Suite

![Python](https://img.shields.io/badge/Python-3-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-API-000000?logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-storage-003B57?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

A compact security "vertical slice" covering both sides of the problem: a **Flask API** that stores secrets **encrypted at rest** behind API-key authentication, and **LogSentinel**, a monitor that detects brute-force attempts against that API and blocks the source IP.

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
| [`SecureVaultAPI/`](SecureVaultAPI/) | Flask + SQLite secrets API with encryption at rest, `X-API-Key` auth and an IP blocklist middleware |
| [`LogSentinel/`](LogSentinel/) | Real-time log monitor, brute-force detection, blocklist and threat reporting |
| [`docs/`](docs/) | Weekly development retrospectives |

## Quick start

```bash
git clone https://github.com/cre-scen/SecureVault_Suite.git
cd SecureVault_Suite
python -m venv venv
# Windows: venv\Scripts\activate    Linux/macOS: source venv/bin/activate
pip install -r requirements.txt

cd SecureVaultAPI
cp .env.example .env        # then set VALID_API_KEY and VAULT_ENCRYPTION_KEY  (Windows: copy .env.example .env)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # generates VAULT_ENCRYPTION_KEY
python db_test.py           # creates the table, encrypts any old plaintext rows, adds a test record
python app.py               # terminal 1: API on http://127.0.0.1:5000
```

In a second terminal (with the virtual environment activated):

```bash
cd LogSentinel
python sentinel.py          # terminal 2: starts monitoring app.log
```

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
- `python LogSentinel/threat_report.py` prints a threat digest and writes `Daily_Security_Report.csv`.

> Testing from your own machine blocks `127.0.0.1`. Delete `blocklist.txt` to reset.

## Project structure

```
SecureVault_Suite/
├── SecureVaultAPI/
│   ├── app.py            # Flask API, encryption, auth, blocklist middleware, logging
│   ├── db_test.py        # Database setup, plaintext-to-encrypted migration, smoke test
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
- There is a single shared API key, with no per-user accounts or key rotation.
- It runs on Flask's development server with `debug=True`.
- Blocking is application-level only. A production setup would push blocks to the firewall (e.g. `ufw`, `iptables`) or a WAF.

## License

[MIT](LICENSE)
