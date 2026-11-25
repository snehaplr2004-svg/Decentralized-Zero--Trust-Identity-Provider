import sqlite3

conn = sqlite3.connect("zero_trust.db")

tables = conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()

print("Database tables:", tables)

conn.close()