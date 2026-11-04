# Security scan baseline

Recorded at the end of M1 (2026-11-04). Findings are listed here, not fixed; each is assigned to a milestone in `PLAN.md`.

Tool versions: bandit 1.9.4, pip-audit 2.10.1, Python 3.13.

## bandit: `bandit -r SecureVaultAPI LogSentinel`

274 lines scanned, 0 skipped via `# nosec`.

| ID | Severity / confidence | Location | Finding | Plan |
|---|---|---|---|---|
| B201 | High / Medium | `SecureVaultAPI/app.py:128` | `app.run(debug=True)` exposes the Werkzeug debugger, which allows arbitrary code execution if it's reachable | M3: debug off by default, env-driven |
| B310 | Medium / High | `LogSentinel/sentinel.py:41` | `urlopen` would accept `file://` and custom schemes | M3: the URL is a fixed `https://ipapi.co/...` string with only the IP interpolated, and the IP has already been parsed by `ipaddress`, so it is likely a false positive. Confirm, then suppress with a justified `# nosec B310` |

## pip-audit: `pip-audit -r requirements.txt`

```
No known vulnerabilities found
```

Covers flask 3.1.3, python-dotenv 1.2.4 and cryptography 50.0.2, plus their resolved dependencies at scan time. Transitive dependencies (e.g. Werkzeug) are not pinned in `requirements.txt`, so a later install can resolve different versions. Re-run this scan in CI (M2).
