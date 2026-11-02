# SecureVault_Suite: guide for Claude Code

## What this is
Portfolio project (github.com/cre-scen/SecureVault_Suite). It has two parts that form one loop:
- `SecureVaultAPI/app.py`: Flask + SQLite secrets API. Fernet encryption at rest, `X-API-Key` auth (constant-time compare, fails closed), IP blocklist middleware, rotating log.
- `LogSentinel/sentinel.py`: tails the API's log. 5 x `401` from one IP within 60s appends that IP to `blocklist.txt`, and the API then returns `403`. `threat_report.py` exports a CSV digest.

The detect-and-block loop is the headline feature. Never break it.

## Coupled paths (change both sides or neither)
| File | Written by | Read by |
|---|---|---|
| `SecureVaultAPI/app.log` | app.py | sentinel.py |
| `blocklist.txt` (repo root) | sentinel.py | app.py, threat_report.py |
| `SecureVaultAPI/test_vault.db` | app.py, db_test.py | app.py |
| `SecureVaultAPI/.env` | me | app.py, db_test.py |

`.env` holds `VALID_API_KEY` and `VAULT_ENCRYPTION_KEY`. Never read it, print it, log it or commit it.

## Commands (repo root, venv active)
- Install: `pip install -r requirements.txt` (add `-r requirements-dev.txt` once M1 lands)
- API: `cd SecureVaultAPI && python app.py` (runs on 127.0.0.1:5000)
- Monitor: `cd LogSentinel && python sentinel.py`
- Tests: `pytest -q` (from M1)
- Lint: `ruff check .`
- Security: `bandit -r SecureVaultAPI LogSentinel` and `pip-audit -r requirements.txt`

## Status
Milestones and definitions of done are in `PLAN.md`. Work only on the milestone marked **NEXT**. Update its status when it's done.

## Rules
- Plan first: list the files you'll touch, the security implications, and the tests that prove the definition of done. Wait for my OK before structural changes.
- Write tests before implementing, and show them failing first.
- Never claim tests or scans passed without pasting the real output. Never weaken, skip or delete a test to make it pass.
- Label claims **VERIFIED** (you ran it) or **FROM READING**.
- No new dependency without saying why, and what the alternative is.
- No stub or placeholder code presented as finished.
- Don't restructure folders or rename files unless the milestone says so.
- Security testing only against localhost or my VirtualBox lab. LogSentinel geolocates IPs through ipapi.co, so tests must use loopback or private IPs, or mock it.
- Known limitations listed in README (key in `.env` next to the DB, dev server, single shared key) are accepted until their milestone. Don't fix them early.
- Git: don't commit, push, rewrite history or change git config. I commit myself. Never add Co-Authored-By, Claude-Session or "Generated with Claude Code" lines to commit messages, PR text or docs you draft.

## About me
Backend developer moving into security, aiming at SOC roles. Comfortable with Linux, Git, networking and Python. Skip the basics. Explain security reasoning and anything non-obvious. When I say "explain for interview", cover what it does, why, the threat it addresses, alternatives, and how I can test it myself.

## Report format
Files changed, what changed, tests and scans run (real output), remaining issues, recommended next step.
