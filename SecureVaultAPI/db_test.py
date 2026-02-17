import sqlite3

conn = sqlite3.connect('test_vault.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        secret_data TEXT NOT NULL
    )
''')

cursor.execute("INSERT OR IGNORE INTO secrets (name, secret_data) VALUES ('Drill3_Start', 'Database_Is_Live')")
conn.commit()

cursor.execute("SELECT * FROM secrets")
print(cursor.fetchall())

#cursor.execute("DELETE FROM secrets")
#conn.commit()
#print("🧹 Database cleared of all duplicates.")

search_name = 'Drill3_Start'
cursor.execute("SELECT secret_data FROM secrets WHERE name = ?", (search_name,))
result = cursor.fetchone()

if result:
    print(f"🔒Found it! The secret is: {result[0]}")
else:
    print("❌ Nothing found with that name.")

conn.close()