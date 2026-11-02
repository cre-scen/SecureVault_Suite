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
- Bandit baseline (run 2026-11-02): B201 High `app.py:124` (debug=True); B310 Medium `sentinel.py:40` (urlopen). The URL there is a fixed https address, so B310 is likely a false positive: confirm, then suppress it with a justified `# nosec` (M3)

---

## M1: Test harness and tooling (NEXT)
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

## M2: CI pipeline
- GitHub Actions on push and PR: pytest, ruff, bandit, pip-audit.
- Actions pinned to commit SHAs. `permissions: contents: read`.
- `.github/dependabot.yml` for pip and github-actions.
- Me, in GitHub settings: turn on secret scanning and push protection.

**Done when:** a PR shows a green run, and a deliberately failing test turns it red (shown once, then reverted). Then add the README badge.

## M3: Threat model and quick hardening
- `docs/threat-model.md`, one page: assets (secrets, Fernet key, API key, logs), trust boundaries, top threats, existing vs missing controls.
- Make debug mode env-driven and off by default.
- Fix audit logging: log after the outcome, with client IP, secret name and result, never the secret value. Log `add_secret` too.
- Rate-limit failed auth per IP, so it's blocked in the app, not only after the fact.

**Done when:** each fix has a test, and the threat model's "missing controls" maps to M4–M7.

## M4: Per-user authentication
- A users table with per-user API keys stored hashed. Decide the scheme in the plan and justify it.
- Each secret has an owner. User A cannot read or overwrite user B's secret (IDOR test).
- A CLI to create a user and issue a key (shown once).
- A migration path off the single shared key.

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
- Refresh the README demo.
- Run an independent audit in a fresh session and write it to `docs/security-assessment.md`. Every finding is fixed or documented.

## Out of scope for now
Frontend, PostgreSQL, FastAPI migration (revisit only if M4 needs it).
