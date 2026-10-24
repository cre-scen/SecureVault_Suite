import os
import sqlite3
from contextlib import closing

# Same database file app.py uses, resolved relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "test_vault.db")


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

        cursor.execute("INSERT OR IGNORE INTO secrets (name, secret_data) VALUES (?, ?)",
                       ("Drill3_Start", "Database_Is_Live"))
        conn.commit()

        cursor.execute("SELECT * FROM secrets")
        print(cursor.fetchall())

        #cursor.execute("DELETE FROM secrets")
        #conn.commit()
        #print("[*] Database cleared of all duplicates.")

        search_name = 'Drill3_Start'
        cursor.execute("SELECT secret_data FROM secrets WHERE name = ?", (search_name,))
        result = cursor.fetchone()

        # Plain-ASCII markers: emoji can crash print() on a default Windows console
        if result:
            print(f"[+] Found it! The secret is: {result[0]}")
        else:
            print("[-] Nothing found with that name.")


if __name__ == "__main__":
    main()
