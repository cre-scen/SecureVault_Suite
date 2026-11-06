import os
import sqlite3
from contextlib import closing

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

import schema

# Same database file and .env that app.py use, resolved relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("VAULT_DB_PATH") or os.path.join(BASE_DIR, "test_vault.db")
load_dotenv(os.path.join(BASE_DIR, ".env"))

ENCRYPTION_KEY = os.getenv("VAULT_ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise SystemExit("[-] VAULT_ENCRYPTION_KEY is not set. See .env.example")
fernet = Fernet(ENCRYPTION_KEY.encode())


def migrate_plaintext_rows(cursor):
    """Encrypt any rows stored before encryption was added. Safe to re-run."""
    migrated = 0
    for row_id, data in cursor.execute("SELECT id, secret_data FROM secrets").fetchall():
        try:
            fernet.decrypt(data.encode())  # already encrypted with this key
        except InvalidToken:
            cursor.execute("UPDATE secrets SET secret_data = ? WHERE id = ?",
                           (fernet.encrypt(data.encode()).decode(), row_id))
            migrated += 1
    return migrated


def main():
    """Create the schema on a new database (or check an existing one) and encrypt
    any plaintext rows left from before encryption was added."""
    with closing(sqlite3.connect(DB_PATH)) as conn:
        try:
            schema.init_db(conn)
        except schema.NeedsMigration as e:
            raise SystemExit(f"[-] {e}") from None
        cursor = conn.cursor()
        migrated = migrate_plaintext_rows(cursor)
        conn.commit()
        print(f"[*] Schema v{schema.get_version(conn)}; encrypted {migrated} existing plaintext row(s)")
        # Plain-ASCII markers: emoji can crash print() on a default Windows console
        print("[+] Ready. Create a user and key with: python vault_cli.py user create NAME")


if __name__ == "__main__":
    main()
