"""User and API key management (M4). Used by vault_cli.py, the migration and the tests.

Every function takes an open sqlite3 connection and commits its own change
unless told not to (the migration runs them inside its own transaction).
Functions raise AccountError with a human-readable message on bad input.
"""

import re
import sqlite3

import keys
from schema import utc_now_iso

USER_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


class AccountError(ValueError):
    pass


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def validate_user_name(name):
    if not isinstance(name, str) or not USER_NAME_RE.fullmatch(name):
        raise AccountError("User names are 1-64 characters from A-Z a-z 0-9 _ . -")


def _user_id(conn, name):
    row = conn.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise AccountError(f"No such user: {name}")
    return row[0]


def _insert_key(conn, user_id):
    key_id, secret, full_key = keys.generate()
    conn.execute("INSERT INTO api_keys (key_id, user_id, key_hash, created_at) VALUES (?, ?, ?, ?)",
                 (key_id, user_id, keys.hash_secret(secret), utc_now_iso()))
    return full_key


def create_user(conn, name, commit=True):
    """Create a user with one key. Returns (user_id, full_key); the key is not stored."""
    validate_user_name(name)
    try:
        cur = conn.execute("INSERT INTO users (name, created_at) VALUES (?, ?)", (name, utc_now_iso()))
    except sqlite3.IntegrityError:
        raise AccountError(f"User already exists: {name}") from None
    full_key = _insert_key(conn, cur.lastrowid)
    if commit:
        conn.commit()
    return cur.lastrowid, full_key


def issue_key(conn, name):
    """An extra key for an existing user, e.g. to rotate without downtime."""
    full_key = _insert_key(conn, _user_id(conn, name))
    conn.commit()
    return full_key


def _update_key(conn, key_id, sql, params=()):
    cur = conn.execute(sql, (*params, key_id))
    if cur.rowcount == 0:
        raise AccountError(f"No such key: {key_id}")
    conn.commit()


def revoke_key(conn, key_id):
    _update_key(conn, key_id, "UPDATE api_keys SET revoked = 1 WHERE key_id = ?")


def unlock_key(conn, key_id):
    conn.execute("DELETE FROM key_failures WHERE key_id = ?", (key_id,))
    _update_key(conn, key_id, "UPDATE api_keys SET locked_until = NULL WHERE key_id = ?")


def disable_user(conn, name):
    user_id = _user_id(conn, name)
    conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user_id,))
    conn.commit()


def list_users(conn):
    """Users and their keys' public details. Never returns hashes."""
    return conn.execute(
        "SELECT u.name, u.disabled, k.key_id, k.revoked, k.locked_until, k.created_at, k.last_used_at "
        "FROM users u LEFT JOIN api_keys k ON k.user_id = u.id ORDER BY u.name, k.created_at"
    ).fetchall()
