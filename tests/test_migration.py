"""M4: upgrading a pre-M4 (v0) vault in place, and the hard cut off the shared key (D4)."""

import glob
import os
import sqlite3
from contextlib import closing

import pytest

import schema
from conftest import TEST_API_KEY, TMP_DIR


def make_v0_db(path, fernet, rows):
    """Build a database exactly as the pre-M4 db_test.py did."""
    for old in glob.glob(path + "*"):
        os.remove(old)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, "
                     "secret_data TEXT NOT NULL)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name)")
        for name, value in rows:
            conn.execute("INSERT INTO secrets (name, secret_data) VALUES (?, ?)",
                         (name, fernet.encrypt(value.encode()).decode()))
        conn.commit()


@pytest.fixture
def v0_db(app_module):
    path = os.path.join(TMP_DIR, "v0_vault.db")
    make_v0_db(path, app_module.fernet, [("db_password", "hunter2"), ("api_token", "tok-123")])
    return path


def version(path):
    with closing(sqlite3.connect(path)) as conn:
        return conn.execute("PRAGMA user_version").fetchone()[0]


def test_v0_upgrades_with_every_secret_owned_and_decryptable(v0_db, app_module, monkeypatch):
    result = schema.migrate(v0_db, owner="martin")
    assert result.migrated and result.secrets_assigned == 2
    assert version(v0_db) == schema.CURRENT_VERSION == 1

    with closing(sqlite3.connect(v0_db)) as conn:
        owners = conn.execute("SELECT DISTINCT u.name FROM secrets s JOIN users u ON u.id = s.owner_id").fetchall()
    assert owners == [("martin",)]

    # The new key works through the real API and old values still decrypt
    monkeypatch.setattr(app_module, "DB_PATH", v0_db)
    app_module.reset_rate_limiter()
    with app_module.app.test_client() as c:
        h = {"X-API-Key": result.key}
        assert c.get("/secret/db_password", headers=h).get_json()["secret"] == "hunter2"
        assert c.get("/secret/api_token", headers=h).get_json()["secret"] == "tok-123"


def test_old_shared_key_is_rejected_after_migration(v0_db, app_module, monkeypatch):
    schema.migrate(v0_db, owner="martin")
    assert os.environ["VALID_API_KEY"] == TEST_API_KEY  # still set, and still ignored
    monkeypatch.setattr(app_module, "DB_PATH", v0_db)
    app_module.reset_rate_limiter()
    with app_module.app.test_client() as c:
        assert c.get("/secret/db_password", headers={"X-API-Key": TEST_API_KEY}).status_code == 401


def test_backup_is_taken_before_changing_anything(v0_db):
    result = schema.migrate(v0_db, owner="martin")
    assert os.path.exists(result.backup_path)
    assert result.backup_path.startswith(v0_db + ".bak-")
    assert version(result.backup_path) == 0
    with closing(sqlite3.connect(result.backup_path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 2


def test_rerunning_is_a_no_op(v0_db):
    schema.migrate(v0_db, owner="martin")
    with closing(sqlite3.connect(v0_db)) as conn:
        before = conn.execute("SELECT * FROM api_keys").fetchall()
    again = schema.migrate(v0_db, owner="martin")
    assert not again.migrated and again.key is None and again.backup_path is None
    with closing(sqlite3.connect(v0_db)) as conn:
        assert conn.execute("SELECT * FROM api_keys").fetchall() == before


def test_failure_mid_migration_rolls_back(v0_db, monkeypatch):
    def boom(conn, owner_id):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(schema, "_rebuild_secrets", boom)
    with pytest.raises(RuntimeError, match="simulated failure"):
        schema.migrate(v0_db, owner="martin")
    assert version(v0_db) == 0
    with closing(sqlite3.connect(v0_db)) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert tables == {"secrets"}
        assert conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 2


def test_app_refuses_a_v0_database_with_401_not_500(v0_db, app_module, monkeypatch):
    monkeypatch.setattr(app_module, "DB_PATH", v0_db)
    app_module.reset_rate_limiter()
    with app_module.app.test_client() as c:
        assert c.get("/secret/db_password", headers={"X-API-Key": TEST_API_KEY}).status_code == 401


def test_init_creates_v1_on_a_new_database():
    path = os.path.join(TMP_DIR, "fresh.db")
    if os.path.exists(path):
        os.remove(path)
    with closing(sqlite3.connect(path)) as conn:
        schema.init_db(conn)
    assert version(path) == 1


def test_init_refuses_to_silently_upgrade_a_v0_database(v0_db):
    with closing(sqlite3.connect(v0_db)) as conn, pytest.raises(schema.NeedsMigration):
        schema.init_db(conn)
    assert version(v0_db) == 0
