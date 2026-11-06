"""Test setup: point every runtime file at a temp dir *before* the app is imported.

app.py and sentinel.py read their paths and keys at import time, so the
environment has to be in place first. Real values in SecureVaultAPI/.env are
never used: python-dotenv does not override variables that are already set.
"""

import os
import sys
import tempfile
from contextlib import closing
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

# Don't write __pycache__ into SecureVaultAPI/ or LogSentinel/
sys.dont_write_bytecode = True

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_DIR = os.path.join(REPO_ROOT, "SecureVaultAPI")
SENTINEL_DIR = os.path.join(REPO_ROOT, "LogSentinel")

TMP_DIR = tempfile.mkdtemp(prefix="securevault-tests-")
# The pre-M4 shared key. Still set in the environment so tests can prove the
# app ignores it after M4 (decision D4: hard cut).
TEST_API_KEY = "test-key-" + "x" * 32

os.environ["VALID_API_KEY"] = TEST_API_KEY
os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["VAULT_DB_PATH"] = os.path.join(TMP_DIR, "test_vault.db")
os.environ["VAULT_LOG_PATH"] = os.path.join(TMP_DIR, "app.log")
os.environ["VAULT_BLOCKLIST_PATH"] = os.path.join(TMP_DIR, "blocklist.txt")
os.environ["VAULT_REPORT_PATH"] = os.path.join(TMP_DIR, "Daily_Security_Report.csv")

sys.path.insert(0, API_DIR)
sys.path.insert(0, SENTINEL_DIR)

import accounts  # noqa: E402
import app as vault_app  # noqa: E402
import db_test  # noqa: E402
import keys  # noqa: E402


@pytest.fixture
def app_module():
    return vault_app


@pytest.fixture
def client():
    """Fresh, initialised database and an empty blocklist for every test."""
    for path in (vault_app.DB_PATH, vault_app.BLOCKLIST_PATH):
        if os.path.exists(path):
            os.remove(path)
    db_test.main()  # the real schema/init path
    vault_app.reset_rate_limiter()  # failed-auth counts must not leak between tests
    vault_app.app.config["TESTING"] = True
    with vault_app.app.test_client() as c:
        yield c


@pytest.fixture
def make_user(client):
    """Create a user with one API key in the test DB; returns its details."""

    def _make(name):
        with closing(accounts.connect(vault_app.DB_PATH)) as conn:
            user_id, full_key = accounts.create_user(conn, name)
        key_id, secret = keys.parse(full_key)
        return SimpleNamespace(name=name, user_id=user_id, key=full_key, key_id=key_id,
                               secret=secret, headers={"X-API-Key": full_key})

    return _make


@pytest.fixture
def alice(make_user):
    return make_user("alice")


@pytest.fixture
def bob(make_user):
    return make_user("bob")


@pytest.fixture
def auth(alice):
    """Headers for a valid key. Before M4 this was the shared key; now it's alice's."""
    return alice.headers
