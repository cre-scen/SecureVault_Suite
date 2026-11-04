"""Test setup: point every runtime file at a temp dir *before* the app is imported.

app.py and sentinel.py read their paths and keys at import time, so the
environment has to be in place first. Real values in SecureVaultAPI/.env are
never used: python-dotenv does not override variables that are already set.
"""

import os
import sys
import tempfile

import pytest
from cryptography.fernet import Fernet

# Don't write __pycache__ into SecureVaultAPI/ or LogSentinel/
sys.dont_write_bytecode = True

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_DIR = os.path.join(REPO_ROOT, "SecureVaultAPI")
SENTINEL_DIR = os.path.join(REPO_ROOT, "LogSentinel")

TMP_DIR = tempfile.mkdtemp(prefix="securevault-tests-")
TEST_API_KEY = "test-key-" + "x" * 32

os.environ["VALID_API_KEY"] = TEST_API_KEY
os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["VAULT_DB_PATH"] = os.path.join(TMP_DIR, "test_vault.db")
os.environ["VAULT_LOG_PATH"] = os.path.join(TMP_DIR, "app.log")
os.environ["VAULT_BLOCKLIST_PATH"] = os.path.join(TMP_DIR, "blocklist.txt")
os.environ["VAULT_REPORT_PATH"] = os.path.join(TMP_DIR, "Daily_Security_Report.csv")

sys.path.insert(0, API_DIR)
sys.path.insert(0, SENTINEL_DIR)

import app as vault_app  # noqa: E402
import db_test  # noqa: E402


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
    vault_app.app.config["TESTING"] = True
    with vault_app.app.test_client() as c:
        yield c


@pytest.fixture
def auth():
    return {"X-API-Key": TEST_API_KEY}
