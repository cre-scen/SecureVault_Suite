# Threat model

Scope: SecureVault API + LogSentinel as shipped in this repo, run on one host on the Flask dev server. Written at M3 (2026-11-04); updated at M3b (2026-11-04), when it moved onto the lab box (`192.168.0.103`) behind a host firewall. Method: list the assets, draw the trust boundaries, walk the data flows, and map every threat to a control or to the milestone that adds it.

## Assets

| Asset | Where it lives | Impact if lost |
|---|---|---|
| Stored secrets | `test_vault.db`, Fernet-encrypted | The whole point of the vault |
| Fernet key (`VAULT_ENCRYPTION_KEY`) | `.env`, same host as the DB | Decrypts every secret; losing it loses every secret |
| API key (`VALID_API_KEY`) | `.env`; sent in `X-API-Key` | Full read/write to every secret |
| `app.log` | `SecureVaultAPI/` | Audit trail, and **LogSentinel's only input** |
| `blocklist.txt` | Repo root | Decides who is refused; corrupting it is a DoS |

## Trust boundaries

1. **Client → API** (HTTP). Everything in a request is untrusted: path, headers, body, and the secret name.
2. **API → `app.log` → LogSentinel.** LogSentinel turns log text into blocking decisions, so any request data that reaches the log crosses into a security control.
3. **LogSentinel → `blocklist.txt` → API.** File-based; anyone with write access to the host can edit it.
4. **LogSentinel → ipapi.co** (outbound HTTPS, optional enrichment). Skipped for private and loopback addresses.
5. **LogSentinel → sudo → ban helper → nftables** (M3b). The only path from the unprivileged log parser to root. The helper re-validates its one argument, because sudo passes arguments through unchecked.
6. **LAN → host** (M3b). ufw decides who reaches which port; the nftables ban table runs before it.

## Threats and controls

| # | Threat (STRIDE) | Control now | Status |
|---|---|---|---|
| T1 | API-key brute force (S) | Constant-time compare; in-app limit of 5 failures/IP/60s returns `429`, even for a correct key; LogSentinel blocks at 5 × `401` in 60s | **Mitigated (M3)** |
| T2 | Log injection: a newline in a secret name forges an access-log line, so LogSentinel blocks an IP the attacker chose (T, D) | Client input escaped and length-capped before logging; LogSentinel regex anchored to the start of Werkzeug's line, so the IP can't come from request data. Tests replay the attack | **Fixed (M3)**, found in M3 review |
| T3 | Remote code execution via the Werkzeug debugger (E) | Debug off unless `VAULT_DEBUG=1`; server bound to `127.0.0.1` | **Fixed (M3)** |
| T4 | Audit gaps / repudiation (R) | One `AUDIT` line per decision (IP, action, name, result), written after the outcome; adds and failures included; never the value | **Fixed (M3)** |
| T5 | Stolen DB file (I) | Fernet (AES-128-CBC + HMAC-SHA256); tampering returns `500`, never data | Mitigated |
| T6 | Key and DB stolen together from the host (I) | None: the key sits in `.env` next to the DB | Missing → **M6** (rotation, backup) and secrets manager (out of scope) |
| T7 | One leaked API key exposes every secret; no per-user boundary (E) | None | Missing → **M4** per-user hashed keys + ownership/IDOR tests, **M5** RBAC |
| T8 | Key compromise with no way to rotate (I) | None | Missing → **M6** `MultiFernet` rotation |
| T9 | Wrong client IP behind a reverse proxy, so the blocklist and rate limit hit the proxy (S, D) | Not deployed behind a proxy | Missing → **M7** |
| T10 | Rate limit is per-process and in-memory, so it resets on restart and isn't shared across workers (D) | Fine for the single-process dev server | Missing → **M7** (gunicorn: shared store or proxy-level limit) |
| T11 | Credentials sniffed in transit (I) | Localhost only | Missing → **M7** (TLS at the proxy) |
| T12 | Vulnerable dependency or tampered CI action (T) | Pinned requirements; pip-audit and bandit in CI; actions pinned to SHAs; Dependabot | Mitigated (M1/M2) |
| T13 | Blocklist DoS via a shared NAT/proxy IP: one attacker locks out everyone behind it (D) | Firewall bans expire after 1 hour; the admin laptop is on a never-ban list. The app-level `blocklist.txt` entry is still permanent until edited | **Partly mitigated (M3b)**; the permanent app-level block is accepted |
| T14 | Banned or unwanted traffic still reaches the app; any other open port on the host is exposed (D, E) | ufw default-deny inbound: SSH from the admin laptop (`192.168.0.101`) only, API port `5000` from `192.168.0.0/24` only. LogSentinel bans go into an expiring nftables set that drops packets before ufw or Python. Verified from Kali: before `22/tcp open`; after `5000/tcp open` only; banned IP got no HTTP response, then `403` after expiry ([evidence](m3b-firewall-evidence.md)) | **Mitigated (M3b)** |
| T16 | Root code execution through the ban path: a crafted log line or argument makes the root helper run something else (E) | LogSentinel stays unprivileged; the regex takes the IP only from Werkzeug's socket field (T2); the root-owned helper accepts one canonical unicast IPv4 address, refuses the never-ban list, and calls `nft` with a fixed argv, no shell, Python in isolated mode. Tested in CI and live (injection and CIDR refused) | **Mitigated (M3b)** |
| T15 | Secret names stored in plaintext reveal what the vault holds (I) | None | Missing → **backlog** (keyed HMAC for lookup, name stored encrypted) |

## Residual risks accepted at M3

- **Rate-limit lockout:** a legitimate user on an attacker's IP is locked out for up to 60 seconds. This is deliberate; the alternative leaks whether a guess was right.
- **Secret names are logged** (escaped). Names should not themselves be sensitive.
- **IPv4 only:** LogSentinel's regex ignores IPv6 clients, so they are rate-limited by the API but never blocklisted.
- `add_secret` assumes `name` and `secret` are strings; a non-string `secret` raises a `500` instead of a `400`. Low impact (needs a valid key); fold into M4's input validation.

## Residual risks accepted at M3b

- **LogSentinel runs as the admin user `cardinal`**, who has full sudo with a password. The sudoers rule limits what it can do *without* a password, but if `sudo` was used in the same terminal session in the last few minutes, the cached credentials let that session run anything. Mitigation in use: start LogSentinel in a fresh session and never run `sudo` there. A dedicated unprivileged account is the proper fix, and needs `app.log` and `blocklist.txt` ownership reworked.
- **The API is open to the whole lab subnet** while it runs, on the dev server, with one shared key. Covered by M4 (per-user keys) and M7 (gunicorn, TLS, port `443`).
- **Bans are IPv4 only** (`banned_v4`), matching LogSentinel's IPv4-only regex. ufw has no IPv6 allow rules, so IPv6 can't reach the API or SSH at all.
- **Reloading the ban table clears every ban** (restart of `securevault-firewall.service`, or a reboot). `blocklist.txt` still refuses those IPs at the app level.
- **SSH access depends on the admin laptop's DHCP reservation.** If its address changes (different adapter, replaced Wi-Fi card), SSH is refused; the fallback is the lab box's own console.
