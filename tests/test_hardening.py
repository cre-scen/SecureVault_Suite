"""M3 hardening: audit logging, log-injection defence, rate limiting, debug default."""

import logging
from urllib.parse import quote

import pytest

import sentinel

VICTIM_IP = "203.0.113.77"  # TEST-NET-3 documentation address, never routable
# A line LogSentinel would count as a 401 from VICTIM_IP if it reached the log as-is
FORGED = f'\n{VICTIM_IP} - - [x] "x" 401 \n'


def audit_lines(caplog):
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("AUDIT ")]


def read_log(app_module):
    for h in logging.getLogger().handlers:
        h.flush()
    with open(app_module.LOG_PATH, encoding="utf-8") as f:
        return f.read().splitlines()


def sentinel_401_ips(lines):
    hits = (sentinel.ACCESS_LOG_RE.search(line) for line in lines)
    return [m.group("ip") for m in hits if m and m.group("status") == "401"]


# --- Audit logging -----------------------------------------------------------

def test_get_unknown_secret_is_logged_as_not_found(client, auth, caplog):
    caplog.set_level(logging.INFO)
    client.get("/secret/missing_one", headers=auth)
    lines = audit_lines(caplog)
    assert any("action=get" in m and "result=not_found" in m and "name=missing_one" in m for m in lines), lines
    # The old bug: "200 OK" was logged before the lookup
    assert not any("200 OK" in r.getMessage() for r in caplog.records)


def test_successful_get_logs_ip_name_result_but_never_the_value(client, auth, caplog):
    client.post("/add-secret", json={"name": "db_pw", "secret": "VALUE-MUST-NOT-BE-LOGGED"}, headers=auth)
    caplog.set_level(logging.INFO)
    client.get("/secret/db_pw", headers=auth, environ_base={"REMOTE_ADDR": "10.1.2.3"})
    lines = audit_lines(caplog)
    assert any(
        "action=get" in m and "result=ok" in m and "ip=10.1.2.3" in m and "name=db_pw" in m for m in lines
    ), lines
    assert not any("VALUE-MUST-NOT-BE-LOGGED" in r.getMessage() for r in caplog.records)


def test_add_secret_is_audited_without_the_value(client, auth, caplog):
    caplog.set_level(logging.INFO)
    client.post("/add-secret", json={"name": "new_one", "secret": "ADD-VALUE-SECRET"}, headers=auth)
    client.post("/add-secret", json={"name": "new_one", "secret": "ADD-VALUE-SECRET"}, headers=auth)
    lines = audit_lines(caplog)
    assert any("action=add" in m and "result=created" in m and "name=new_one" in m for m in lines), lines
    assert any("action=add" in m and "result=duplicate" in m for m in lines), lines
    assert not any("ADD-VALUE-SECRET" in r.getMessage() for r in caplog.records)


def test_failed_auth_is_audited(client, caplog):
    caplog.set_level(logging.INFO)
    client.get("/secret/x", headers={"X-API-Key": "wrong"})
    client.post("/add-secret", json={"name": "a", "secret": "b"})
    lines = audit_lines(caplog)
    assert any("action=get" in m and "result=unauthorized" in m for m in lines), lines
    assert any("action=add" in m and "result=unauthorized" in m for m in lines), lines


# --- Log injection -----------------------------------------------------------

def test_unauthenticated_name_cannot_forge_a_sentinel_line(client, app_module):
    """A newline in the URL must not let an attacker get an arbitrary IP blocked."""
    client.get("/secret/" + quote(FORGED, safe=""), headers={"X-API-Key": "wrong"})
    lines = read_log(app_module)
    assert VICTIM_IP not in sentinel_401_ips(lines), lines


def test_authenticated_decrypt_failure_cannot_forge_a_sentinel_line(client, auth, app_module):
    import sqlite3

    name = "evil" + FORGED
    with sqlite3.connect(app_module.DB_PATH) as conn:
        conn.execute("INSERT INTO secrets (name, secret_data) VALUES (?, ?)", (name, "not-a-fernet-token"))
    assert client.get("/secret/" + quote(name, safe=""), headers=auth).status_code == 500
    assert VICTIM_IP not in sentinel_401_ips(read_log(app_module))


def test_logged_names_are_single_line_escaped_and_capped(client, auth, caplog):
    caplog.set_level(logging.INFO)
    client.get("/secret/" + quote("a\nb\rc\x1b[31m\"d", safe=""), headers=auth)
    client.get("/secret/" + "L" * 5000, headers=auth)
    for m in audit_lines(caplog):
        assert "\n" not in m and "\r" not in m and "\x1b" not in m, repr(m)
        assert len(m) < 400, len(m)
    assert any("a\\nb\\rc" in m for m in audit_lines(caplog))


def test_sentinel_regex_only_trusts_the_start_of_werkzeug_lines():
    real = '2026-11-04 12:00:00,000 - 127.0.0.1 - - [04/Nov/2026 12:00:00] "GET /secret/x HTTP/1.1" 401 -'
    # Forged pattern inside an otherwise legitimate single log line
    inside = f'2026-11-04 12:00:00,000 - AUDIT action=get result=unauthorized ip=127.0.0.1 name={VICTIM_IP} - - [x] "x" 401 '
    # Forged pattern on its own line (if escaping ever regressed)
    bare = f'{VICTIM_IP} - - [x] "x" 401 '
    assert sentinel_401_ips([real]) == ["127.0.0.1"]
    assert sentinel_401_ips([inside]) == []
    assert sentinel_401_ips([bare]) == []


# --- Rate limiting -----------------------------------------------------------

def test_sixth_failure_in_window_is_rate_limited(client):
    bad = {"X-API-Key": "wrong"}
    codes = [client.get("/secret/x", headers=bad).status_code for _ in range(6)]
    assert codes == [401] * 5 + [429]
    resp = client.get("/secret/x", headers=bad)
    assert resp.status_code == 429
    assert 1 <= int(resp.headers["Retry-After"]) <= 60


def test_rate_limited_ip_gets_429_even_with_the_right_key(client, auth):
    for _ in range(5):
        client.get("/secret/x", headers={"X-API-Key": "wrong"})
    # Otherwise an attacker could tell when a guess is correct
    assert client.get("/secret/x", headers=auth).status_code == 429
    assert client.post("/add-secret", json={"name": "a", "secret": "b"}, headers=auth).status_code == 429


def test_rate_limit_is_per_ip(client, auth):
    for _ in range(5):
        client.get("/secret/x", headers={"X-API-Key": "wrong"}, environ_base={"REMOTE_ADDR": "10.0.0.1"})
    other = {"REMOTE_ADDR": "10.0.0.2"}
    assert client.get("/secret/x", headers=auth, environ_base=other).status_code == 404


def test_rate_limit_expires_after_the_window(client, auth, app_module, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(app_module, "_now", lambda: now[0])
    for _ in range(5):
        client.get("/secret/x", headers={"X-API-Key": "wrong"})
    assert client.get("/secret/x", headers=auth).status_code == 429
    now[0] += 61
    assert client.get("/secret/x", headers=auth).status_code == 404


def test_rate_limited_requests_are_audited(client, caplog):
    caplog.set_level(logging.INFO)
    for _ in range(6):
        client.get("/secret/x", headers={"X-API-Key": "wrong"})
    assert any("result=rate_limited" in m for m in audit_lines(caplog))


# --- Debug mode --------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [(None, False), ("0", False), ("true", False), ("1", True)])
def test_debug_is_off_unless_vault_debug_is_1(app_module, monkeypatch, value, expected):
    calls = {}
    monkeypatch.setattr(app_module.app, "run", lambda **kw: calls.update(kw))
    if value is None:
        monkeypatch.delenv("VAULT_DEBUG", raising=False)
    else:
        monkeypatch.setenv("VAULT_DEBUG", value)
    app_module.run_server()
    assert calls["debug"] is expected
    assert calls["host"] == "127.0.0.1"
