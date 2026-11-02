import sqlite3
from contextlib import contextmanager
from .config import DATABASE_PATH


@contextmanager
def connection():
    db = sqlite3.connect(DATABASE_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            did TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            username TEXT,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)


def audit(event, username, details):
    from datetime import datetime, timezone
    import json

    with connection() as db:
        db.execute(
            """INSERT INTO audit_logs
               (event, username, details, created_at)
               VALUES (?, ?, ?, ?)""",
            (
                event,
                username,
                json.dumps(details),
                datetime.now(timezone.utc).isoformat()
            )
        )


def get_logs(limit=100):
    with connection() as db:
        rows = db.execute(
            """SELECT event, username, details, created_at
               FROM audit_logs ORDER BY id DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_users():
    with connection() as db:
        rows = db.execute(
            """SELECT id, username, email, did, role, created_at
               FROM users ORDER BY id DESC"""
        ).fetchall()
        return [dict(row) for row in rows]