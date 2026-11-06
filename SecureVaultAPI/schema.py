"""Database schema versions and the v0 -> v1 migration (M4).

PRAGMA user_version holds the version:
  0  pre-M4: one `secrets` table, names unique across the whole vault, no owners
  1  M4: users, api_keys, key_failures; every secret has an owner; names unique per owner
"""

import os
import sqlite3
from collections import namedtuple
from contextlib import closing
from datetime import datetime, timezone

CURRENT_VERSION = 1

MigrationResult = namedtuple("MigrationResult", "migrated backup_path key secrets_assigned")


class NeedsMigration(RuntimeError):
    """The database is v0 with data; run `vault_cli.py migrate --owner NAME`."""


# One statement per entry, so migrate() can run them with conn.execute inside its
# own transaction (executescript would COMMIT first).
_AUTH_STATEMENTS = ["""
CREATE TABLE users (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    disabled    INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at  TEXT NOT NULL
)""", """
CREATE TABLE api_keys (
    key_id       TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    key_hash     TEXT NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    locked_until REAL,              -- Unix time, NULL when not locked
    created_at   TEXT NOT NULL,
    last_used_at TEXT
)""", """
CREATE TABLE key_failures (       -- bad secrets per key, for the lockout (D5)
    key_id  TEXT NOT NULL REFERENCES api_keys(key_id),
    at      REAL NOT NULL           -- Unix time
)""", """
CREATE INDEX idx_key_failures ON key_failures(key_id, at)
"""]

_SECRETS_V1 = """
CREATE TABLE {table} (
    id          INTEGER PRIMARY KEY,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    name        TEXT NOT NULL,
    secret_data TEXT NOT NULL,
    UNIQUE (owner_id, name)
)
"""


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_version(conn):
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def init_db(conn):
    """Create the v1 schema on a new database. No-op on v1. Refuses a v0 database
    that already has a secrets table: that needs an owner, so it's an explicit migrate."""
    version = get_version(conn)
    if version == CURRENT_VERSION:
        return
    if version > CURRENT_VERSION:
        raise RuntimeError(f"Database schema v{version} is newer than this code (v{CURRENT_VERSION})")
    if "secrets" in _tables(conn):
        raise NeedsMigration("Database is pre-M4 (v0). Run: python vault_cli.py migrate --owner NAME")
    # Explicit BEGIN: Python's sqlite3 doesn't open a transaction for DDL on its own
    conn.execute("BEGIN")
    try:
        for statement in (*_AUTH_STATEMENTS, _SECRETS_V1.format(table="secrets")):
            conn.execute(statement)
        conn.execute(f"PRAGMA user_version = {CURRENT_VERSION}")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def _backup(db_path):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = f"{db_path}.bak-{stamp}"
    with closing(sqlite3.connect(db_path)) as src, closing(sqlite3.connect(backup_path)) as dst:
        src.backup(dst)  # consistent copy, even if the file is open elsewhere
    os.chmod(backup_path, 0o600)
    return backup_path


def _rebuild_secrets(conn, owner_id):
    """SQLite can't change a UNIQUE constraint in place: copy into a new table and swap."""
    # conn.execute, not executescript: executescript COMMITs first, which would
    # break the rollback guarantee of migrate()
    conn.execute(_SECRETS_V1.format(table="secrets_new"))
    conn.execute("INSERT INTO secrets_new (id, owner_id, name, secret_data) "
                 "SELECT id, ?, name, secret_data FROM secrets", (owner_id,))
    conn.execute("DROP TABLE secrets")  # also drops the old idx_secrets_name
    conn.execute("ALTER TABLE secrets_new RENAME TO secrets")


def migrate(db_path, owner):
    """Upgrade db_path to v1, giving every existing secret to `owner`, and issue
    the owner's first key. Re-running on a v1 database changes nothing."""
    import accounts  # local import: accounts uses this module's schema helpers

    accounts.validate_user_name(owner)
    with closing(sqlite3.connect(db_path)) as conn:
        version = get_version(conn)
        if version == CURRENT_VERSION:
            return MigrationResult(False, None, None, 0)
        if version > CURRENT_VERSION:
            raise RuntimeError(f"Database schema v{version} is newer than this code")
        has_secrets = "secrets" in _tables(conn)

    backup_path = _backup(db_path) if has_secrets else None

    conn = sqlite3.connect(db_path, isolation_level=None)  # we manage the transaction
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in _AUTH_STATEMENTS:
                conn.execute(statement)
            owner_id, key = accounts.create_user(conn, owner, commit=False)
            if has_secrets:
                assigned = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
                _rebuild_secrets(conn, owner_id)
            else:
                assigned = 0
                conn.execute(_SECRETS_V1.format(table="secrets"))
            conn.execute(f"PRAGMA user_version = {CURRENT_VERSION}")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return MigrationResult(True, backup_path, key, assigned)
