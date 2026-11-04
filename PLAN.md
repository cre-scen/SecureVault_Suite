# SecureVault_Suite plan

Status values: NEXT, IN PROGRESS, DONE (with date).
Each milestone ships with its tests, a security check and a README update before the next one starts.

## Order
M4 → M3c → M5 → M3d → M6 → M7 → M8 → M9, then the backlog.
M3c and M3d run on the lab box and can slot in between code milestones, but M3d must be done before M6 goes live.

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
- LogSentinel runs as the admin user `cardinal`, not a dedicated account (M3c)
- The lab box disk is not encrypted, so anyone with the drive can read the key file (M3d)
- Swap and core dumps are on, so a key held in RAM can end up on disk (M3c)
- One Fernet key file protects everything and never rotates (M6)

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

Done on the Chromebook lab box with a Kali VM as the attacker. Evidence: [docs/m3b-firewall-evidence.md](docs/m3b-firewall-evidence.md). LogSentinel runs as the admin user `cardinal`, not a dedicated account; that is recorded as a residual risk in the threat model.

## M3c: Lab box hardening, part 1 (service isolation and memory)
Runs on the Chromebook. Closes the M3b residual risk.
- Dedicated system users `securevault` and `logsentinel` with no login shell. sudoers for `ban-ip` moves to `logsentinel`.
- systemd units for both with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes` and explicit `ReadWritePaths` for the DB, log and blocklist only.
- Swap off (or encrypted swap), so a key held in RAM is never paged to disk.
- Core dumps off for the vault service (`LimitCORE=0`) and system-wide.
- Unattended security updates on.
- Unit files and settings live in `deploy/host/` and are documented.

**Done when:** `systemd-analyze security` scores for both units are recorded; `swapon --show` is empty (or shows only encrypted swap); a forced crash of the vault produces no core file; the `securevault` user can't read `/home/cardinal`; the threat model is updated.

## M3d: Disk encryption (reinstall)
Must be done before M6 goes live, because the machine share is only protected if the disk is.
- Reinstall Xubuntu on the Chromebook with LUKS full-disk encryption and a strong boot passphrase.
- No TPM unlock: the Chromebook's security chip only implements part of TPM 2.0 and can't seal LUKS keys, so unlock is passphrase only.
- Rebuild from the `chromebook-to-linux-lab` runbook (SSH hardening, firewall, Docker, M3c), which also tests that the runbook is complete.

**Done when:** `lsblk -f` shows the root filesystem on a `crypto_LUKS` device; the box won't boot without the passphrase; M3b and M3c checks pass again after the rebuild.

## M4: Per-user authentication (NEXT)
- A users table with per-user API keys stored hashed. Decide the scheme in the plan and justify it.
- Each secret has an owner. User A cannot read or overwrite user B's secret (IDOR test).
- A CLI to create a user and issue a key (shown once).
- A migration path off the single shared key.
- Validate `name`/`secret` types in `add_secret` (a non-string `secret` currently returns `500`, not `400`).
- Per-key limits (see Limits): request rate per key, and a key locks after repeated failures.

**Done when:** auth tests, cross-user access tests, migration tests and per-key limit tests pass, and the README endpoints table is updated.

## M5: RBAC
- Roles: admin, writer, reader.

**Done when:** a role-by-endpoint test matrix passes.

## M6: Split-key encryption and daily rotation
Replaces the single key file. Depends on M3d (encrypted disk) and M4 (owners).

Key hierarchy (envelope encryption):
- A 16-byte master seed is split with Shamir secret sharing (pycryptodome), 2-of-3: share 1 on the machine, share 2 on the USB drive, share 3 printed as a paper recovery code kept offline. Any two shares unlock; one alone reveals nothing.
- The master key (KEK) is derived with HKDF from the recombined seed. It exists only in RAM and is never written to disk.
- The KEK wraps a keyring of data keys (DEKs). Each secret is encrypted with a DEK and stores that DEK's version.

Unlock and lock:
- Plugging in the USB lets the vault read share 2 and unlock. Until then the API returns `503 Locked`.
- A udev rule signals the vault when the USB is removed; the vault drops the KEK and DEKs from memory and locks. Python can't guarantee memory is wiped, which is recorded in the threat model.
- Recovery: machine share plus the paper code unlocks if the USB is lost. A runbook covers making a new USB share and retiring the old one.

Rotation:
- Every 24 hours while unlocked, a new DEK is created and becomes the key for new writes.
- A background job re-encrypts older secrets to the newest DEK, then retires DEKs nothing uses.
- Shares are not re-split daily. Re-split only on suspected compromise of a share, with a documented procedure.
- Rotation can't run while locked; it catches up on the next unlock.

Limits: unlock attempts are limited (see Limits).

**Done when:** tests show one share alone can't unlock, any two can, a wrong share fails cleanly, removing the USB locks the API within seconds, a DEK rotation round trip works with old secrets still readable, retired DEKs are gone from the keyring, and the recovery path works with the paper share; the runbook is in `docs/`; the threat model is updated.

## M7: Packaging and final audit
- Dockerfile (non-root, gunicorn, debug off), Trivy in CI, correct client IP behind a proxy.
- TLS at the proxy; switch the M3b firewall rule from `5000` to `443`.
- Refresh the README demo.
- Run an independent audit in a fresh session and write it to `docs/security-assessment.md`. Every finding is fixed or documented.

## M8: Phone as a share source
The phone holds share 2 as an alternative to the USB drive. Platform TBD (Android or iPhone); the protocol is the same either way. Depends on M6 and M7 (TLS).

Pairing (once, in person):
- Pairing mode is opened only from a CLI on the Chromebook and shows a QR code.
- The QR code carries the vault's public key and a one-time pairing token. The phone pins the vault key and registers its own device public key.

Unlock (mutual authentication):
1. The vault sends a challenge signed with its key: a fresh nonce, a timestamp and the vault's ephemeral X25519 public key.
2. The phone checks the signature against the pinned vault key and rejects anything unsigned, expired or already seen.
3. You approve with a fingerprint. The phone's signing key and share live in Android Keystore or the iOS Secure Enclave and need biometric auth on every use, not just screen unlock. An app PIN is the fallback.
4. The phone signs the nonce with its device key and sends its share encrypted to the session key (X25519 + HKDF), so the share never crosses the network readable.
5. The vault checks the device is paired and not revoked, verifies the signature and nonce, then combines shares.

Device management:
- `vault devices list` and `vault devices revoke <id>` on the Chromebook. Revoking takes effect immediately.
- Every pairing, unlock, failure and revocation goes to `app.log`; LogSentinel alerts on repeated failures.

Crypto: Ed25519 signatures and X25519 from Python's `cryptography` on the vault side. If the phone's Keystore doesn't support Ed25519, the device key uses ECDSA P-256 instead; confirm against the actual phone.

**Done when:** tests cover a wrong vault key (phone refuses), a replayed or expired challenge (vault refuses), a revoked device (vault refuses), an unpaired device (vault refuses), and the limits below; a real unlock from the phone works on the lab LAN; the threat model is updated.

## M9: Firmware hardening (last)
Highest risk of bricking the Chromebook, so it goes last and only after checking the exact CAREENA steps.
- Turn on UEFI Secure Boot in the MrChromebox Full ROM firmware.
- Reconnect the battery and re-enable firmware write protection.

**Done when:** the box boots with Secure Boot on (`mokutil --sb-state`), an unsigned boot USB is refused, and the write-protect state is recorded; the stock firmware backup is confirmed safe before starting.

## Limits
Starting values, to be tuned with tests. Every limit hit is logged and visible to LogSentinel.

| Where | Limit | Milestone |
|---|---|---|
| Failed API auth per IP | In-app rate limit, then LogSentinel ban and nftables drop | M3, M3b (done) |
| Requests per API key | 60 per minute; over that returns `429` | M4 |
| Failed auth per API key | 10 failures in 10 minutes locks the key until an admin unlocks it | M4 |
| Unlock attempts | 5 failed in 15 minutes, then locked for 15 minutes, doubling on each repeat | M6 |
| Pairing | Opened only from the Chromebook CLI; QR valid 2 minutes, single use; at most 3 paired devices | M8 |
| Phone unlock requests | One open challenge at a time, expires in 60 seconds; at most 3 requests per 5 minutes, so the phone can't be spammed with approval prompts | M8 |
| Uploads | Size limit per file and per user per day | Backlog: ingest pipeline |

## Backlog (not committed; decide after M9)

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
Frontend, PostgreSQL, FastAPI migration (revisit only if M4 needs it). Running the vault from a USB drive.
