"""Shared test setup.

The app reads its key and file paths when it is imported, so everything here
runs before any test module imports it. All runtime files (database, log,
blocklist) go to a temporary directory, never into the repo.
"""

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parent.parent
API_DIR = REPO_ROOT / "SecureVaultAPI"
SENTINEL_DIR = REPO_ROOT / "LogSentinel"

TEST_API_KEY = "test-api-key"
TMP_DIR = Path(tempfile.mkdtemp(prefix="securevault-tests-"))

# Explicit values win over anything in a developer's real .env, because
# load_dotenv() never overrides variables that are already set.
os.environ["VALID_API_KEY"] = TEST_API_KEY
os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["VAULT_DB_PATH"] = str(TMP_DIR / "test_vault.db")
os.environ["VAULT_LOG_PATH"] = str(TMP_DIR / "app.log")
os.environ["VAULT_BLOCKLIST_PATH"] = str(TMP_DIR / "blocklist.txt")

sys.path[:0] = [str(API_DIR), str(SENTINEL_DIR)]
sys.dont_write_bytecode = True  # keep __pycache__ out of the source folders

import app as vault_app  # noqa: E402
import db_test  # noqa: E402


@pytest.fixture
def client():
    """A test client with a fresh database (built by db_test.main) and an empty blocklist."""
    db_path = Path(os.environ["VAULT_DB_PATH"])
    db_path.unlink(missing_ok=True)
    Path(os.environ["VAULT_BLOCKLIST_PATH"]).unlink(missing_ok=True)
    db_test.main()
    vault_app.app.config["TESTING"] = True
    with vault_app.app.test_client() as test_client:
        yield test_client


@pytest.fixture
def auth():
    return {"X-API-Key": TEST_API_KEY}


@pytest.fixture
def db():
    """Direct access to the test database, to check what is really stored."""
    conn = sqlite3.connect(os.environ["VAULT_DB_PATH"])
    yield conn
    conn.close()


@pytest.fixture
def blocklist_path():
    return Path(os.environ["VAULT_BLOCKLIST_PATH"])
