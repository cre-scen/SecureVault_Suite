"""M4: each secret has an owner, and nobody can see or touch another user's (IDOR)."""

import sqlite3

import pytest


def add(client, user, name, secret):
    return client.post("/add-secret", json={"name": name, "secret": secret}, headers=user.headers)


def test_bob_gets_404_for_alices_secret(client, alice, bob):
    add(client, alice, "db_password", "alice-value")
    resp = client.get("/secret/db_password", headers=bob.headers)
    assert resp.status_code == 404
    assert "alice-value" not in resp.get_data(as_text=True)


def test_404_for_someone_elses_secret_matches_404_for_a_missing_one(client, alice, bob):
    """D3: a 403 would confirm the name exists for another user."""
    add(client, alice, "exists_for_alice", "v")
    theirs = client.get("/secret/exists_for_alice", headers=bob.headers)
    missing = client.get("/secret/exists_for_nobody", headers=bob.headers)
    assert (theirs.status_code, theirs.get_json()) == (missing.status_code, missing.get_json())


def test_bob_writing_alices_name_does_not_change_alices_value(client, alice, bob):
    add(client, alice, "shared_name", "alice-value")
    assert add(client, bob, "shared_name", "bob-value").status_code == 201
    assert client.get("/secret/shared_name", headers=alice.headers).get_json()["secret"] == "alice-value"
    assert client.get("/secret/shared_name", headers=bob.headers).get_json()["secret"] == "bob-value"


def test_duplicate_is_only_within_one_owner(client, alice, bob):
    add(client, alice, "n", "1")
    assert add(client, alice, "n", "2").status_code == 409
    assert add(client, bob, "n", "3").status_code == 201


def test_secret_rows_must_have_an_owner(client, app_module):
    with sqlite3.connect(app_module.DB_PATH) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO secrets (name, secret_data) VALUES ('orphan', 'x')")


def test_secret_owner_must_be_a_real_user(client, app_module):
    with sqlite3.connect(app_module.DB_PATH) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("INSERT INTO secrets (owner_id, name, secret_data) VALUES (9999, 'ghost', 'x')")


def test_rows_are_written_with_the_callers_owner_id(client, alice, bob, app_module):
    add(client, bob, "bobs", "v")
    with sqlite3.connect(app_module.DB_PATH) as conn:
        (owner,) = conn.execute("SELECT owner_id FROM secrets WHERE name = 'bobs'").fetchone()
    assert owner == bob.user_id != alice.user_id
