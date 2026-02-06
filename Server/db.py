import sqlite3
import hashlib
import secrets
from typing import Optional
import os
class DB:
    def __init__(self, db_name: str = "db.db"):
            base_dir = os.path.dirname(__file__)
            self.db_path = os.path.join(base_dir, db_name)
            self.create_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=10,
            check_same_thread=False
        )
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    @staticmethod
    def _calc_password_hash(plain_password: str, salt: str) -> str:
        return hashlib.sha256((plain_password + salt).encode()).hexdigest()

    @staticmethod
    def _simple_hash(data: str):
        if data is None:
            return None
        return hashlib.sha256(data.encode()).hexdigest()

    def create_tables(self):
        with self._get_conn() as conn:
            cur = conn.cursor()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    request_id TEXT NOT NULL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    patient_id TEXT,
                    patient_id_hash TEXT,
                    file_hash TEXT,
                    status TEXT DEFAULT 'PENDING',
                    prediction_label TEXT,
                    prediction_confidence REAL,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)

            cur.execute("CREATE INDEX IF NOT EXISTS idx_patient_hash ON scans(patient_id_hash);")

    def close(self):
        # אין pool לסגור ב-SQLite; נשאר כדי לא לשבור קוד שקורא לזה
        pass

    def signup(self, username: str, password_plain: str) -> bool:
        salt = secrets.token_hex(16)
        password_hash = self._calc_password_hash(password_plain, salt)
        try:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                    (username, password_hash, salt)
                )
            return True
        except sqlite3.IntegrityError:
            print(f"User {username} already exists.")
            return False
        except Exception as e:
            print(f"Error creating user: {e}")
            return False

    def login(self, username, password_plain) -> Optional[int]:
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, password_hash, salt FROM users WHERE username = ?",
                    (username,)
                )
                row = cur.fetchone()
                if not row:
                    return None

                user_id, stored_hash, stored_salt = row
                calculated_hash = self._calc_password_hash(password_plain, stored_salt)
                return user_id if calculated_hash == stored_hash else None
        except Exception as e:
            print(f"Login error: {e}")
            return None

    def save_new_scan(self, request_id: str, user_id: int, file_hash: str, patient_id: str) -> bool:
        p_hash = self._simple_hash(patient_id)
        try:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scans (request_id, user_id, file_hash, patient_id, patient_id_hash, status)
                    VALUES (?, ?, ?, ?, ?, 'PENDING')
                    """,
                    (request_id, user_id, file_hash, patient_id, p_hash)
                )
            return True
        except Exception as e:
            print(f"Error saving scan: {e}")
            return False

    def update_scan(self, request_id: str, prediction_label: str, prediction_confidence: float) -> bool:
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE scans
                    SET status = 'COMPLETED',
                        prediction_label = ?,
                        prediction_confidence = ?
                    WHERE request_id = ?
                    """,
                    (prediction_label, prediction_confidence, request_id)
                )
                return cur.rowcount > 0
        except Exception as e:
            print(f"Error updating scan: {e}")
            return False

    def mark_scan_error(self, request_id: str):
        try:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE scans SET status = 'ERROR' WHERE request_id = ?",
                    (request_id,)
                )
        except Exception as e:
            print(f"Error marking error: {e}")

    def get_user_history(self, user_id: int) -> list:
        try:
            with self._get_conn() as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT request_id, patient_id, patient_id_hash, status, prediction_label, uploaded_at
                    FROM scans
                    WHERE user_id = ?
                    ORDER BY uploaded_at DESC
                    """,
                    (user_id,)
                )
                rows = [dict(r) for r in cur.fetchall()]
                for row in rows:
                    if row.get("uploaded_at") is not None:
                        row["uploaded_at"] = str(row["uploaded_at"])
                return rows
        except Exception as e:
            print(f"History error: {e}")
            return []

if __name__ == '__main__':
    db = DB("db.db")
    print("DB READY (SQLite)")
