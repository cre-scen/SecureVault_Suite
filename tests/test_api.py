"""Behaviour of the SecureVault API as it stands today."""

import os
import subprocess
import sys

import pytest
from conftest import API_DIR


def add(client, auth, name="db_password", secret="example-value"):
    return client.post("/add-secret", json={"name": name, "secret": secret}, headers=auth)


# --- Authentication -------------------------------------------------------

@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong"}], ids=["missing", "wrong"])
def test_add_secret_rejects_bad_key(client, headers):
    response = client.post("/add-secret", json={"name": "a", "secret": "b"}, headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong"}], ids=["missing", "wrong"])
def test_get_secret_rejects_bad_key(client, auth, headers):
    add(client, auth)
    response = client.get("/secret/db_password", headers=headers)
    assert response.status_code == 401
    assert "example-value" not in response.get_data(as_text=True)


def test_health_endpoint_needs_no_key(client):
    assert client.get("/").status_code == 200


# --- Storing and retrieving -----------------------------------------------

def test_add_secret_returns_201(client, auth):
    assert add(client, auth).status_code == 201


def test_duplicate_name_returns_409(client, auth):
    add(client, auth)
    assert add(client, auth, secret="other").status_code == 409


@pytest.mark.parametrize(
    "body",
    [{}, {"name": "only-name"}, {"secret": "only-secret"}, {"name": "", "secret": "x"}],
    ids=["empty", "no-secret", "no-name", "blank-name"],
)
def test_missing_fields_return_400(client, auth, body):
    assert client.post("/add-secret", json=body, headers=auth).status_code == 400


def test_get_returns_the_stored_value(client, auth):
    add(client, auth)
    response = client.get("/secret/db_password", headers=auth)
    assert response.status_code == 200
    assert response.get_json() == {"name": "db_password", "secret": "example-value"}


def test_unknown_name_returns_404(client, auth):
    assert client.get("/secret/does-not-exist", headers=auth).status_code == 404


# --- Encryption at rest ---------------------------------------------------

def test_database_holds_ciphertext_not_plaintext(client, auth, db):
    add(client, auth)
    (stored,) = db.execute("SELECT secret_data FROM secrets WHERE name = 'db_password'").fetchone()
    assert "example-value" not in stored
    assert stored.startswith("gAAAA")  # Fernet token prefix


def test_tampered_ciphertext_is_rejected_not_returned(client, auth, db):
    add(client, auth)
    db.execute("UPDATE secrets SET secret_data = 'not-a-valid-token' WHERE name = 'db_password'")
    db.commit()
    response = client.get("/secret/db_password", headers=auth)
    assert response.status_code == 500
    assert response.get_json() == {"error": "Secret could not be decrypted"}


# --- IP blocklist ---------------------------------------------------------

def test_blocklisted_ip_gets_403_even_with_valid_key(client, auth, blocklist_path):
    add(client, auth)
    blocklist_path.write_text("10.0.0.66,2026-11-02 12:00:00,Local Network\n")
    response = client.get(
        "/secret/db_password", headers=auth, environ_base={"REMOTE_ADDR": "10.0.0.66"}
    )
    assert response.status_code == 403


def test_other_ips_are_not_blocked(client, auth, blocklist_path):
    add(client, auth)
    blocklist_path.write_text("10.0.0.66,2026-11-02 12:00:00,Local Network\n")
    response = client.get(
        "/secret/db_password", headers=auth, environ_base={"REMOTE_ADDR": "10.0.0.7"}
    )
    assert response.status_code == 200


# --- Startup --------------------------------------------------------------

def test_app_refuses_to_start_without_encryption_key(tmp_path):
    env = dict(os.environ)
    # Empty rather than unset: load_dotenv() would otherwise fill it in from a
    # developer's real .env, and the test would pass for the wrong reason.
    env["VAULT_ENCRYPTION_KEY"] = ""
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    code = f"import sys; sys.path.insert(0, {str(API_DIR)!r}); import app"
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, cwd=tmp_path, capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "VAULT_ENCRYPTION_KEY is not set" in result.stderr


# --- Known bugs (fixed in M3; strict, so fixing them fails these on purpose) ---

@pytest.mark.xfail(strict=True, reason="Known issue: no type checks, crashes with 500 (M3)")
@pytest.mark.parametrize(
    "body", [{"name": "n", "secret": 123}, {"name": ["a"], "secret": "s"}], ids=["int", "list"]
)
def test_non_string_fields_should_return_400(client, auth, body):
    assert client.post("/add-secret", json=body, headers=auth).status_code == 400


@pytest.mark.xfail(strict=True, reason="Known issue: no MAX_CONTENT_LENGTH (M3)")
def test_oversized_secret_should_be_rejected(client, auth):
    response = add(client, auth, name="big", secret="A" * 1_000_000)
    assert response.status_code == 413
