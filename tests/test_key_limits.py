"""M4: per-key request rate (D6) and per-key lockout after bad secrets (D5)."""

import sqlite3
from contextlib import closing

import pytest

import accounts
import keys


@pytest.fixture
def clock(app_module, monkeypatch):
    """Control both clocks: monotonic (in-memory limits) and wall (lockout in the DB)."""
    t = {"mono": 1000.0, "wall": 1_800_000_000.0}
    monkeypatch.setattr(app_module, "_now", lambda: t["mono"])
    monkeypatch.setattr(app_module, "_wall", lambda: t["wall"])

    def advance(seconds):
        t["mono"] += seconds
        t["wall"] += seconds

    return advance


def bad_attempts(client, user, n, first_ip=1):
    """n wrong secrets for user's key, each from a different IP so the per-IP limit stays out of it."""
    for i in range(n):
        wrong = f"sv_{user.key_id}_{keys.generate()[1]}"
        resp = client.get("/secret/x", headers={"X-API-Key": wrong},
                          environ_base={"REMOTE_ADDR": f"10.9.0.{first_ip + i}"})
        assert resp.status_code == 401


def fresh_ip(n=200):
    return {"REMOTE_ADDR": f"10.8.0.{n}"}


# --- Rate per key --------------------------------------------------------------

def test_61st_request_in_a_minute_gets_429_with_retry_after(client, alice, clock):
    codes = [client.get("/secret/x", headers=alice.headers).status_code for _ in range(61)]
    assert codes == [404] * 60 + [429]
    resp = client.get("/secret/x", headers=alice.headers)
    assert resp.status_code == 429
    assert 1 <= int(resp.headers["Retry-After"]) <= 60


def test_rate_window_slides(client, alice, clock):
    for _ in range(30):
        client.get("/secret/x", headers=alice.headers)
    clock(30)
    for _ in range(30):
        client.get("/secret/x", headers=alice.headers)
    assert client.get("/secret/x", headers=alice.headers).status_code == 429
    clock(31)  # the first 30 have aged out, the second 30 haven't
    codes = [client.get("/secret/x", headers=alice.headers).status_code for _ in range(31)]
    assert codes == [404] * 30 + [429]


def test_one_keys_rate_does_not_affect_another(client, alice, bob, clock):
    for _ in range(61):
        client.get("/secret/x", headers=alice.headers)
    assert client.get("/secret/x", headers=bob.headers).status_code == 404


def test_rate_limited_key_is_audited(client, alice, clock, caplog):
    import logging
    caplog.set_level(logging.INFO)
    for _ in range(61):
        client.get("/secret/x", headers=alice.headers)
    assert any("result=rate_limited" in r.getMessage() and "reason=key_rate" in r.getMessage()
               for r in caplog.records)


# --- Lockout -------------------------------------------------------------------

def test_nine_bad_secrets_do_not_lock(client, alice, clock):
    bad_attempts(client, alice, 9)
    assert client.get("/secret/x", headers=alice.headers, environ_base=fresh_ip()).status_code == 404


def test_ten_bad_secrets_lock_the_key_even_against_the_right_secret(client, alice, clock):
    bad_attempts(client, alice, 10)
    resp = client.get("/secret/x", headers=alice.headers, environ_base=fresh_ip())
    assert (resp.status_code, resp.get_json()) == (401, {"error": "Unauthorized"})


def test_failures_older_than_the_window_do_not_count(client, alice, clock):
    bad_attempts(client, alice, 9)
    clock(15 * 60 + 1)
    bad_attempts(client, alice, 1, first_ip=50)
    assert client.get("/secret/x", headers=alice.headers, environ_base=fresh_ip()).status_code == 404


def test_lock_lives_in_the_db_and_survives_an_app_reload(client, alice, clock, app_module):
    bad_attempts(client, alice, 10)
    app_module.reset_rate_limiter()  # all in-memory state gone, as after a restart
    with sqlite3.connect(app_module.DB_PATH) as conn:
        (locked_until,) = conn.execute("SELECT locked_until FROM api_keys WHERE key_id = ?",
                                       (alice.key_id,)).fetchone()
    assert locked_until is not None
    assert client.get("/secret/x", headers=alice.headers, environ_base=fresh_ip()).status_code == 401


def test_lock_expires_after_15_minutes(client, alice, clock):
    bad_attempts(client, alice, 10)
    clock(15 * 60 - 5)
    assert client.get("/secret/x", headers=alice.headers, environ_base=fresh_ip(201)).status_code == 401
    clock(10)
    assert client.get("/secret/x", headers=alice.headers, environ_base=fresh_ip(202)).status_code == 404


def test_cli_unlock_clears_the_lock(client, alice, clock, app_module):
    bad_attempts(client, alice, 10)
    with closing(accounts.connect(app_module.DB_PATH)) as conn:
        accounts.unlock_key(conn, alice.key_id)
    assert client.get("/secret/x", headers=alice.headers, environ_base=fresh_ip()).status_code == 404


def test_locking_one_key_does_not_affect_another(client, alice, bob, clock):
    bad_attempts(client, alice, 10)
    assert client.get("/secret/x", headers=bob.headers, environ_base=fresh_ip()).status_code == 404


def test_lock_is_audited_and_locked_attempts_say_so(client, alice, clock, caplog):
    import logging
    caplog.set_level(logging.INFO)
    bad_attempts(client, alice, 10)
    client.get("/secret/x", headers=alice.headers, environ_base=fresh_ip())
    msgs = [r.getMessage() for r in caplog.records]
    assert any("action=key_lock" in m and f"key={alice.key_id}" in m for m in msgs), msgs
    assert any("reason=locked" in m for m in msgs), msgs


def test_lock_never_touches_data(client, alice, clock, app_module):
    client.post("/add-secret", json={"name": "keep", "secret": "me"}, headers=alice.headers)
    bad_attempts(client, alice, 10)
    with closing(accounts.connect(app_module.DB_PATH)) as conn:
        accounts.unlock_key(conn, alice.key_id)
    assert client.get("/secret/keep", headers=alice.headers, environ_base=fresh_ip()).get_json()["secret"] == "me"
