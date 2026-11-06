"""M4: per-user API keys. Every failure looks the same from outside (D2)."""

import logging
import sqlite3
from contextlib import closing

import accounts
import keys
from conftest import TEST_API_KEY

UNAUTHORIZED = {"error": "Unauthorized"}


def audit_lines(caplog):
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("AUDIT ")]


def read_log(app_module):
    for h in logging.getLogger().handlers:
        h.flush()
    with open(app_module.LOG_PATH, encoding="utf-8") as f:
        return f.read()


# --- Key format ----------------------------------------------------------------

def test_generated_key_has_the_documented_format():
    key_id, secret, full = keys.generate()
    assert full == f"sv_{key_id}_{secret}"
    assert len(key_id) == 12 and all(c in "0123456789abcdef" for c in key_id)
    assert len(secret) == 43
    assert keys.parse(full) == (key_id, secret)


def test_generated_keys_are_unique():
    assert len({keys.generate()[2] for _ in range(200)}) == 200


def test_parse_rejects_anything_off_format():
    good_id, good_secret, _ = keys.generate()
    for bad in ("", "wrong", TEST_API_KEY, f"sv_{good_id}", f"xx_{good_id}_{good_secret}",
                f"sv_{good_id.upper()}_{good_secret}", f"sv_{good_id}_{good_secret}x",
                f"sv_{good_id}_{good_secret[:-1]}", f"sv_{good_id}_{good_secret[:-1]}!"):
        assert keys.parse(bad) is None, bad


def test_hash_is_sha256_and_verify_is_exact():
    _, secret, _ = keys.generate()
    stored = keys.hash_secret(secret)
    assert len(stored) == 64 and stored != secret
    assert keys.verify(secret, stored)
    assert not keys.verify(secret[:-1] + ("A" if secret[-1] != "A" else "B"), stored)


# --- Success -----------------------------------------------------------------

def test_valid_key_gets_200(client, alice):
    client.post("/add-secret", json={"name": "s", "secret": "v"}, headers=alice.headers)
    assert client.get("/secret/s", headers=alice.headers).status_code == 200


def test_only_the_hash_is_stored(client, alice, app_module):
    with sqlite3.connect(app_module.DB_PATH) as conn:
        rows = conn.execute("SELECT * FROM api_keys").fetchall()
    dumped = repr(rows)
    assert alice.secret not in dumped and alice.key not in dumped
    assert keys.hash_secret(alice.secret) in dumped


# --- Every failure is the same 401 --------------------------------------------

def _all_401_bodies(client, headers):
    get = client.get("/secret/x", headers=headers)
    add = client.post("/add-secret", json={"name": "a", "secret": "b"}, headers=headers)
    return [(get.status_code, get.get_json()), (add.status_code, add.get_json())]


def test_missing_malformed_unknown_and_wrong_keys_get_identical_401(client, alice, app_module):
    unknown_id, unknown_secret, unknown = keys.generate()
    wrong_secret = keys.generate()[1]
    cases = {
        "missing": {},
        "malformed": {"X-API-Key": "not-a-key"},
        "old shared key": {"X-API-Key": TEST_API_KEY},
        "unknown id": {"X-API-Key": unknown},
        "wrong secret": {"X-API-Key": f"sv_{alice.key_id}_{wrong_secret}"},
    }
    for label, headers in cases.items():
        app_module.reset_rate_limiter()
        assert _all_401_bodies(client, headers) == [(401, UNAUTHORIZED)] * 2, label


def test_revoked_key_gets_identical_401(client, alice, app_module):
    with closing(accounts.connect(app_module.DB_PATH)) as conn:
        accounts.revoke_key(conn, alice.key_id)
    assert _all_401_bodies(client, alice.headers) == [(401, UNAUTHORIZED)] * 2


def test_disabled_user_gets_identical_401_on_every_key(client, alice, app_module):
    with closing(accounts.connect(app_module.DB_PATH)) as conn:
        second = accounts.issue_key(conn, "alice")
        accounts.disable_user(conn, "alice")
    assert _all_401_bodies(client, alice.headers) == [(401, UNAUTHORIZED)] * 2
    app_module.reset_rate_limiter()
    assert _all_401_bodies(client, {"X-API-Key": second}) == [(401, UNAUTHORIZED)] * 2


def test_audit_log_records_why_auth_failed(client, alice, caplog, app_module):
    caplog.set_level(logging.INFO)
    client.get("/secret/x", headers={"X-API-Key": "nope"})
    client.get("/secret/x", headers={"X-API-Key": keys.generate()[2]})
    client.get("/secret/x", headers={"X-API-Key": f"sv_{alice.key_id}_{keys.generate()[1]}"})
    with closing(accounts.connect(app_module.DB_PATH)) as conn:
        accounts.revoke_key(conn, alice.key_id)
    app_module.reset_rate_limiter()
    client.get("/secret/x", headers=alice.headers)
    lines = audit_lines(caplog)
    for reason in ("malformed", "unknown_key", "bad_secret", "revoked"):
        assert any("result=unauthorized" in m and f"reason={reason}" in m for m in lines), (reason, lines)


def test_successful_requests_are_audited_with_user_and_key_id(client, alice, caplog):
    caplog.set_level(logging.INFO)
    client.get("/secret/missing", headers=alice.headers)
    assert any("user=alice" in m and f"key={alice.key_id}" in m for m in audit_lines(caplog))


def test_full_key_and_secret_never_reach_the_log(client, alice, app_module):
    client.post("/add-secret", json={"name": "s", "secret": "v"}, headers=alice.headers)
    client.get("/secret/s", headers=alice.headers)
    wrong = f"sv_{alice.key_id}_{keys.generate()[1]}"
    client.get("/secret/s", headers={"X-API-Key": wrong})
    log = read_log(app_module)
    assert alice.key_id in log
    for leaked in (alice.key, alice.secret, wrong, wrong.rsplit("_", 1)[1]):
        assert leaked not in log


def test_failed_key_auth_still_feeds_logsentinel(client):
    """D2 keeps LogSentinel unchanged: failures are still plain 401s from one IP."""
    codes = [client.get("/secret/x", headers={"X-API-Key": keys.generate()[2]}).status_code
             for _ in range(6)]
    assert codes == [401] * 5 + [429]
