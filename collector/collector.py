
import hashlib
import json
import sqlite3
from pathlib import Path

BASE_DIR = Path.home() / "capstone"
LOG_FILE = BASE_DIR / "cowrie" / "log" / "cowrie.json"
DB_FILE = BASE_DIR / "data" / "events.db"


def initialize_database(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_hash TEXT NOT NULL UNIQUE,
            timestamp TEXT,
            eventid TEXT,
            session TEXT,
            src_ip TEXT,
            src_port INTEGER,
            username TEXT,
            message TEXT,
            raw_json TEXT NOT NULL
        )
    """)
    connection.commit()


def collect_events():
    if not LOG_FILE.is_file():
        raise FileNotFoundError(f"Cowrie log not found: {LOG_FILE}")

    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    inserted = 0
    skipped = 0

    with sqlite3.connect(DB_FILE) as connection:
        initialize_database(connection)

        with LOG_FILE.open("r", encoding="utf-8") as logfile:
            for line in logfile:
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue

                event_hash = hashlib.sha256(
                    line.encode("utf-8")
                ).hexdigest()

                cursor = connection.execute("""
                    INSERT OR IGNORE INTO events (
                        event_hash, timestamp, eventid, session,
                        src_ip, src_port, username, message, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_hash,
                    event.get("timestamp"),
                    event.get("eventid"),
                    event.get("session"),
                    event.get("src_ip"),
                    event.get("src_port"),
                    event.get("username"),
                    event.get("message"),
                    line,
                ))

                if cursor.rowcount == 1:
                    inserted += 1
                else:
                    skipped += 1

    print(f"New events: {inserted}")
    print(f"Duplicates or malformed lines skipped: {skipped}")
    print(f"Database: {DB_FILE}")


if __name__ == "__main__":
    collect_events()
