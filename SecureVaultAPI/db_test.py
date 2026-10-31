import os
import sqlite3
from contextlib import closing

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

# Same database file and .env that app.py use, resolved relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "test_vault.db")
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
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                secret_data TEXT NOT NULL
            )
        ''')
        # Tables created before UNIQUE was added don't have it, so enforce it here too
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name)")

        migrated = migrate_plaintext_rows(cursor)
        print(f"[*] Encrypted {migrated} existing plaintext row(s)")

        cursor.execute("INSERT OR IGNORE INTO secrets (name, secret_data) VALUES (?, ?)",
                       ("Drill3_Start", fernet.encrypt(b"Database_Is_Live").decode()))
        conn.commit()

        # Show what is actually stored on disk: ciphertext, not the secret
        cursor.execute("SELECT name, secret_data FROM secrets WHERE name = ?", ("Drill3_Start",))
        name, stored = cursor.fetchone()
        print(f"[*] Stored in database: {stored[:40]}...")

        # Plain-ASCII markers: emoji can crash print() on a default Windows console
        print(f"[+] Decrypted with key: {fernet.decrypt(stored.encode()).decode()}")


if __name__ == "__main__":
    main()
