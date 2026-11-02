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
- Bandit baseline (run 2026-11-02, line numbers after M1): B201 High `app.py:129` (debug=True); B310 Medium `sentinel.py:41` (urlopen). The URL there is a fixed https address, so B310 is likely a false positive: confirm, then suppress it with a justified `# nosec` (M3)

Found in the 2026-11-02 assessment (verified by running the API):
- The app never creates its own table. On a fresh DB, `/add-secret` raises an unhandled 500; only `db_test.py` creates the schema (M3)
- No input type checks: `{"secret": 123}` or `{"name": ["a"]}` crash with a 500 (M3)
- No request size limit (`MAX_CONTENT_LENGTH` unset); a 1 MB secret is accepted (M3)

Found by reading:
- LogSentinel's regex only matches IPv4 (`sentinel.py:24`), so IPv6 failures are never counted (M3)
- **Constraint for M3:** once the secret name is logged, it's attacker-controlled text. It must be escaped (no raw newlines), or someone could forge a log line that LogSentinel reads as a 401 from any IP and get that IP blocked

---

## M1: Test harness and tooling (DONE 2026-11-02, pending review)
Result: 24 passed, 4 strict xfail (known bugs above). ruff clean. bandit: the 2 baseline findings only. pip-audit: no known vulnerabilities. A test run leaves no files in `SecureVaultAPI/`, `LogSentinel/` or the repo root. The detect-and-block loop was re-checked end to end with the real API and LogSentinel processes. `threat_report.py` also got the blocklist override, because it reads the same file.
- Make `DB_PATH`, `LOG_PATH` and `BLOCKLIST_PATH` overridable via env vars (`VAULT_DB_PATH`, `VAULT_LOG_PATH`, `VAULT_BLOCKLIST_PATH`) in **all three** of `app.py`, `sentinel.py` and `db_test.py`, so the API and LogSentinel can't point at different files. Defaults stay unchanged.
- Tests build the schema by calling `db_test.main()` on a temp DB, so the schema isn't copied into the tests.
- The "refuses to start without a key" test runs in a subprocess, because the app raises at import.
- Known bugs that M3 will fix are recorded as strict `xfail` tests, so they turn into failures the moment they're fixed and have to be promoted to real tests.
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

## M2: CI pipeline (NEXT)
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
