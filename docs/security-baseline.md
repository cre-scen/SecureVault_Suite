# Security scan baseline

Updated at the end of M3 (2026-11-04). Tool versions: bandit 1.9.4, pip-audit 2.10.1, Python 3.13.

## bandit: `bandit -r SecureVaultAPI LogSentinel`

348 lines scanned. **0 issues.** 1 issue deliberately suppressed with a documented reason.

| ID | Status | Detail |
|---|---|---|
| B201 (High) `app.run(debug=True)` | **Fixed in M3** | Debug is off unless `VAULT_DEBUG=1`, and the server binds to `127.0.0.1` |
| B310 (Medium) `urlopen` in `sentinel.py` | **Suppressed in M3** (`# nosec B310`) | Confirmed false positive: the URL is always `https://ipapi.co/<ip>/json/`, where `<ip>` is the normalised output of `ipaddress.ip_address()` on an IP the regex already restricted to dotted IPv4. `ipaddress` rejects path-like input such as `1.2.3.4/../x`, so the scheme and path can't be changed |

### History
- M1 (2026-11-04): B201 High at `app.py:128`, B310 Medium at `sentinel.py:41`. Recorded, not fixed.
- M2: both stored in `.bandit-baseline.json` so CI failed only on new findings.
- M3: both resolved. `.bandit-baseline.json` is now empty, so CI fails on **any** bandit finding.

## pip-audit: `pip-audit -r requirements.txt`

```
No known vulnerabilities found
```

Covers flask 3.1.3, python-dotenv 1.2.4 and cryptography 50.0.2, plus their resolved dependencies at scan time. Transitive dependencies (e.g. Werkzeug) are not pinned in `requirements.txt`, so a later install can resolve different versions. CI re-runs this scan on every PR and push to `main`.

## Found by review, not by scanners

Log injection (CWE-117) through the secret name, found while planning M3's audit logging. Neither bandit nor pip-audit flags it. See T2 in [threat-model.md](threat-model.md).
