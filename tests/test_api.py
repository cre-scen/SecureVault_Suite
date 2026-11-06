import os
import sqlite3
import subprocess
import sys

import pytest

from conftest import API_DIR, TMP_DIR


def add(client, auth, name="db_password", secret="hunter2"):
    return client.post("/add-secret", json={"name": name, "secret": secret}, headers=auth)


# --- Authentication ---------------------------------------------------------

def test_missing_key_returns_401(client):
    assert client.get("/secret/anything").status_code == 401
    assert client.post("/add-secret", json={"name": "a", "secret": "b"}).status_code == 401


def test_wrong_key_returns_401(client):
    bad = {"X-API-Key": "wrong-key"}
    assert client.get("/secret/anything", headers=bad).status_code == 401
    assert client.post("/add-secret", json={"name": "a", "secret": "b"}, headers=bad).status_code == 401


# --- Add secret --------------------------------------------------------------

def test_add_returns_201(client, auth):
    assert add(client, auth).status_code == 201


def test_duplicate_name_returns_409(client, auth):
    add(client, auth)
    assert add(client, auth, secret="different").status_code == 409


def test_missing_fields_return_400(client, auth):
    for body in ({}, {"name": "only-name"}, {"secret": "only-secret"}, {"name": "", "secret": ""}):
        assert client.post("/add-secret", json=body, headers=auth).status_code == 400, body
    # Not JSON at all
    resp = client.post("/add-secret", data="not json", headers=auth)
    assert resp.status_code == 400


@pytest.mark.parametrize("body", [
    {"name": "ok_name", "secret": 123},
    {"name": "ok_name", "secret": ["a"]},
    {"name": "ok_name", "secret": {"a": 1}},
    {"name": 123, "secret": "value"},
    {"name": ["a"], "secret": "value"},
    {"name": "has space", "secret": "value"},
    {"name": "../etc/passwd", "secret": "value"},
    {"name": "n" * 129, "secret": "value"},
    {"name": "ok_name", "secret": "x" * (64 * 1024 + 1)},
])
def test_invalid_types_and_values_return_400_not_500(client, auth, body):
    assert client.post("/add-secret", json=body, headers=auth).status_code == 400


def test_json_that_is_not_an_object_returns_400(client, auth):
    assert client.post("/add-secret", json=["name", "secret"], headers=auth).status_code == 400


def test_name_and_secret_at_the_limits_are_accepted(client, auth):
    assert add(client, auth, name="n" * 128, secret="x" * (64 * 1024)).status_code == 201
    assert add(client, auth, name="a.b-c_D9", secret="v").status_code == 201


# --- Get secret --------------------------------------------------------------

def test_get_returns_200_with_right_value(client, auth):
    add(client, auth, name="api_token", secret="s3cr3t-value")
    resp = client.get("/secret/api_token", headers=auth)
    assert resp.status_code == 200
    assert resp.get_json() == {"name": "api_token", "secret": "s3cr3t-value"}


def test_unknown_name_returns_404(client, auth):
    assert client.get("/secret/does-not-exist", headers=auth).status_code == 404


# --- Encryption at rest ------------------------------------------------------

def test_stored_value_is_not_plaintext(client, auth, app_module):
    add(client, auth, name="enc_check", secret="plaintext-marker-123")
    with sqlite3.connect(app_module.DB_PATH) as conn:
        (stored,) = conn.execute(
            "SELECT secret_data FROM secrets WHERE name = ?", ("enc_check",)
        ).fetchone()
    assert "plaintext-marker-123" not in stored
    # And it is a real Fernet token for that value under the app's key
    assert app_module.fernet.decrypt(stored.encode()) == b"plaintext-marker-123"


def test_tampered_ciphertext_returns_500(client, auth, app_module):
    add(client, auth, name="tamper_me", secret="original")
    with sqlite3.connect(app_module.DB_PATH) as conn:
        (stored,) = conn.execute(
            "SELECT secret_data FROM secrets WHERE name = ?", ("tamper_me",)
        ).fetchone()
        # Flip one character in the middle of the token: the HMAC check must fail
        i = len(stored) // 2
        tampered = stored[:i] + ("A" if stored[i] != "A" else "B") + stored[i + 1:]
        conn.execute("UPDATE secrets SET secret_data = ? WHERE name = ?", (tampered, "tamper_me"))
    resp = client.get("/secret/tamper_me", headers=auth)
    assert resp.status_code == 500
    assert "original" not in resp.get_data(as_text=True)


# --- Blocklist ---------------------------------------------------------------

def test_blocklisted_ip_returns_403(client, auth, app_module):
    with open(app_module.BLOCKLIST_PATH, "w") as f:
        f.write("10.0.0.66,2026-11-04 12:00:00,Local Network\n")
    blocked = {"REMOTE_ADDR": "10.0.0.66"}
    # Blocked even with a valid key, on every route
    assert client.get("/secret/x", headers=auth, environ_base=blocked).status_code == 403
    assert client.get("/", environ_base=blocked).status_code == 403
    # Other IPs are unaffected
    assert client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.67"}).status_code == 200


# --- Startup -----------------------------------------------------------------

def test_app_refuses_to_start_without_encryption_key():
    env = dict(os.environ)
    # Empty, not deleted: python-dotenv won't override a set variable,
    # so a developer's real .env can't leak a key into this test.
    env["VAULT_ENCRYPTION_KEY"] = ""
    env["VAULT_LOG_PATH"] = os.path.join(TMP_DIR, "startup-check.log")
    result = subprocess.run(
        [sys.executable, "-B", "-c", "import app"],
        cwd=API_DIR, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "VAULT_ENCRYPTION_KEY is not set" in result.stderr


# --- Isolation ---------------------------------------------------------------

def test_runtime_paths_are_overridable(app_module):
    """Tests must never touch the real vault, log or blocklist."""
    for path in (app_module.DB_PATH, app_module.LOG_PATH, app_module.BLOCKLIST_PATH):
        assert os.path.dirname(path) == TMP_DIR, path
