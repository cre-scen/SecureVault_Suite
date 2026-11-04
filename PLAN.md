# SecureVault_Suite plan

Status values: NEXT, IN PROGRESS, DONE (with date).
Each milestone ships with its tests, a security check and a README update before the next one starts.

## Already done
- Flask API with add/get secret, parameterised SQL, JSON errors (400/401/403/404/409/500)
- Fernet encryption at rest, plus a plaintext migration in `db_test.py`
- Constant-time `X-API-Key` check that fails closed
- LogSentinel: sliding-window brute-force detection, blocklist, CSV threat report
- README with an architecture diagram, demo and known limitations

## Known issues found in review (to fix in the milestones below)
- `app.run(debug=True)`: the Werkzeug debugger allows code execution if it's reachable (M3)
- `get_secret` logs "200 OK ... Added/Retrieved" *before* checking whether the secret exists, and never logs which secret was requested. `add_secret` logs nothing (M3)
- `DB_PATH`, `LOG_PATH` and `BLOCKLIST_PATH` are hardcoded, and the log handler is created on import, so tests would touch real files (M1)
- `requirements.txt` has no version pins (M1)
- No rate limiting beyond LogSentinel's after-the-fact block (M3)
- `request.remote_addr` will be wrong behind a reverse proxy (M7)
- No host firewall: banned IPs still reach the app and are only refused inside it (fixed in M3b)
- Secret `name` is stored in plaintext, so the metadata shows what the vault holds (backlog: ingest pipeline)
- Only text secrets are accepted; no file or binary ingest (backlog: ingest pipeline)
- Bandit baseline (run 2026-11-02): B201 High `app.py:124` (debug=True); B310 Medium `sentinel.py:40` (urlopen). The URL there is a fixed https address, so B310 is likely a false positive: confirm, then suppress it with a justified `# nosec` (M3)

---

## M1: Test harness and tooling (DONE 2026-11-04)
- Make `DB_PATH`, `LOG_PATH` and `BLOCKLIST_PATH` overridable via env vars. Defaults stay unchanged.
- Pin `requirements.txt`. Add `requirements-dev.txt` with pytest, ruff, bandit and pip-audit.
- Add `pyproject.toml` with pytest and ruff config.
- Add `tests/conftest.py`, which sets a test key and temp paths before importing the app.
- Tests:
  - missing key returns 401, wrong key returns 401
  - add returns 201, duplicate name returns 409, missing fields return 400
  - get returns 200 with the right value, unknown name returns 404
  - the stored DB value is not the plaintext
  - a tampered ciphertext returns 500
  - a blocklisted IP returns 403
  - the app refuses to start without `VAULT_ENCRYPTION_KEY`
  - LogSentinel's regex counts one 401 line per request

**Done when:** `pytest -q` passes, running the tests creates or changes no files in `SecureVaultAPI/` or the repo root, ruff passes, bandit and pip-audit output is recorded (findings listed, not fixed), and the README has a "Running tests" section.

## M2: CI pipeline (DONE 2026-11-04)
- GitHub Actions on push and PR: pytest, ruff, bandit, pip-audit.
- Actions pinned to commit SHAs. `permissions: contents: read`.
- `.github/dependabot.yml` for pip and github-actions.
- Me, in GitHub settings: turn on secret scanning and push protection.

**Done when:** a PR shows a green run, and a deliberately failing test turns it red (shown once, then reverted). Then add the README badge.

## M3: Threat model and quick hardening (DONE 2026-11-04)
- `docs/threat-model.md`, one page: assets (secrets, Fernet key, API key, logs), trust boundaries, top threats, existing vs missing controls.
- Make debug mode env-driven and off by default.
- Fix audit logging: log after the outcome, with client IP, secret name and result, never the secret value. Log `add_secret` too.
- Rate-limit failed auth per IP, so it's blocked in the app, not only after the fact.
- Remove B201 and B310 from `.bandit-baseline.json` once they're fixed or justifiably suppressed.
- Found in M3 review and fixed: log injection through the secret name could forge LogSentinel lines and get any IP blocked. Logged input is now escaped and capped, and LogSentinel's regex is anchored.

**Done when:** each fix has a test, the threat model's "missing controls" maps to M4–M7, and `.bandit-baseline.json` has no entries left.

## M3b: Host firewall (DONE 2026-11-04)
Runs on a lab box (the Chromebook Xubuntu machine or a VirtualBox VM), not on my laptop. Independent of M4–M6, so it can be done before or alongside them.
- nftables, default-deny inbound. Allow SSH only from my admin IP, and the API port only from the lab subnet: `5000` until M7 adds TLS, then `443` instead. SQLite is a file, so no database port is ever open.
- Rules live in `deploy/firewall/`, load at boot, and are documented.
- LogSentinel also pushes each ban into an nftables set with a timeout (e.g. 1 hour), so banned IPs are dropped before they reach Python. `blocklist.txt` stays as the app-level fallback.
- LogSentinel never runs as root. It calls a small helper (`deploy/firewall/ban-ip`) that validates its one argument is an IP and does nothing else; sudoers allows the LogSentinel user to run only that helper.
- Bans expire on their own; manual unban is documented.

**Done when:** an nmap scan from another lab VM shows only the allowed ports; a simulated brute force from that VM puts its IP in the set and its next connections are dropped (no HTTP response at all); the ban expires after the timeout; tests show the helper rejects anything that isn't an IP; the threat model is updated.

Done on the Chromebook lab box with a Kali VM as the attacker. Evidence: [docs/m3b-firewall-evidence.md](docs/m3b-firewall-evidence.md). LogSentinel ran as the admin user `cardinal` in that run, not a dedicated account.

### M3b follow-up: LogSentinel as its own user (IN PROGRESS)
- A system user `securevault-sentinel` (no login, no home) runs LogSentinel through `deploy/firewall/securevault-sentinel.service`, sandboxed with `ProtectHome=yes` and `ProtectSystem=strict`, from a root-owned copy in `/opt/securevault/`.
- The sudoers rule names only that user; `cardinal` loses passwordless access to the helper.
- `app.log` moves to `/var/log/securevault/` and `blocklist.txt` to `/var/lib/securevault/`, shared through the `securevault` group. The API is started with those paths and `umask 027`.

**Done when:** the static tests in `tests/test_sentinel_deploy.py` pass (done), and on the lab box the "Check the separation" steps in `deploy/firewall/README.md` give the expected results, and a brute force from Kali is banned and dropped with the service running. Then update the threat model's residual risks and the evidence doc.

## M4: Per-user authentication (NEXT)
- A users table with per-user API keys stored hashed. Decide the scheme in the plan and justify it.
- Each secret has an owner. User A cannot read or overwrite user B's secret (IDOR test).
- A CLI to create a user and issue a key (shown once).
- A migration path off the single shared key.
- Validate `name`/`secret` types in `add_secret` (a non-string `secret` currently returns `500`, not `400`).

**Done when:** auth tests, cross-user access tests and migration tests pass, and the README endpoints table is updated.

## M5: RBAC
- Roles: admin, writer, reader.

**Done when:** a role-by-endpoint test matrix passes.

## M6: Key management
- Rotate the Fernet key with `MultiFernet`, using a re-encrypt script.
- Document the backup and recovery procedure.

**Done when:** a rotation round-trip test passes, the old key can be retired, and the runbook is in `docs/`.

## M7: Packaging and final audit
- Dockerfile (non-root, gunicorn, debug off), Trivy in CI, correct client IP behind a proxy.
- TLS at the proxy; switch the M3b firewall rule from `5000` to `443`.
- Refresh the README demo.
- Run an independent audit in a fresh session and write it to `docs/security-assessment.md`. Every finding is fixed or documented.

## Backlog (not committed; decide after M7)

### Ingest pipeline (text + PDF)
Depends on M4 (owners) and M6 (key rotation).
- One pipeline for every type: receive → validate → encrypt → store → audit log → LogSentinel.
- Types: text secrets (existing) and PDF uploads only.
- Validate before any crypto runs: size limit, and the real type checked from the file contents, not the name or `Content-Type`.
- Encrypt: Fernet for small items; chunked AES-GCM for files so they are never fully in memory.
- Store: metadata (owner, type, size, key version) in the DB; file contents on disk as encrypted blobs with random names; partial uploads cleaned up.
- Stop storing `name` in plaintext: keep a keyed HMAC of it for lookups (a plain hash can be reversed by guessing common names) and store the name itself encrypted.
- Audit log: who, type, size, result. Never content.
- LogSentinel rules for rejected uploads and unusual volume.

Done when: tests cover each rejection (oversize, wrong type, renamed file), a large-file round trip, cross-user access to files, and key rotation with files present; the README documents the pipeline with a diagram.

### More data types
Images, structured JSON records, logs through the same pipeline. Only after the ingest pipeline shows what one type costs.

## Out of scope for now
Frontend, PostgreSQL, FastAPI migration (revisit only if M4 needs it).
