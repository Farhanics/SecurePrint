import os
import sqlite3
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from config import DB_PATH, STORAGE_DIR, MAX_PIN_ATTEMPTS, JOB_TTL_SECONDS

def get_db_connection(db_path=None):
    """Return a sqlite3 connection with row factory enabled."""
    path = db_path or DB_PATH
    conn = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        pass
    return conn

def init_db(db_path=None):
    """Initialize database tables and indexes."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    pin_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    pin_attempts INTEGER NOT NULL DEFAULT 0,
                    blob_path TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    copies INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('uploaded', 'printed', 'expired', 'deleted', 'locked')),
                    pages_printed INTEGER,
                    printed_at REAL,
                    deleted_at REAL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status_expires ON jobs(status, expires_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);")
    finally:
        conn.close()

def hash_pin(pin: str, salt: str) -> str:
    """Compute SHA-256 hash of pin + salt."""
    return hashlib.sha256((pin + salt).encode("utf-8")).hexdigest()

def secure_delete_file(file_path: Path | str) -> bool:
    """
    Securely delete file by overwriting with random bytes,
    syncing to disk, and removing it.
    """
    p = Path(file_path)
    if not p.is_file():
        return False
    try:
        size = p.stat().st_size
        if size > 0:
            with open(p, "wb") as f:
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
        p.unlink(missing_ok=True)
        return True
    except Exception as e:
        # Fallback to direct unlink if write failed
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
        return False

def create_job(job_id: str, pin: str, blob_path: str, mime_type: str,
               size_bytes: int, copies: int = 1, ttl_seconds: int = None,
               db_path=None) -> dict:
    """Create a new job entry with hashed PIN."""
    salt = secrets.token_hex(16)
    pin_h = hash_pin(pin, salt)
    now = time.time()
    ttl = ttl_seconds if ttl_seconds is not None else JOB_TTL_SECONDS
    expires_at = now + ttl

    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute("""
                INSERT INTO jobs (
                    id, pin_hash, salt, pin_attempts, blob_path, mime_type,
                    size_bytes, copies, created_at, expires_at, status
                ) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, 'uploaded')
            """, (job_id, pin_h, salt, blob_path, mime_type, size_bytes, copies, now, expires_at))
        return {
            "id": job_id,
            "mime_type": mime_type,
            "size_bytes": size_bytes,
            "copies": copies,
            "created_at": now,
            "expires_at": expires_at,
            "status": "uploaded"
        }
    finally:
        conn.close()

def get_job(job_id: str, db_path=None) -> dict | None:
    """Fetch job by ID."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def check_and_update_pin(job_id: str, pin: str, db_path=None) -> tuple[bool, str]:
    """
    Verify 6-digit PIN against salt and stored hash using constant-time compare.
    Tracks failed attempts and locks job if attempts >= MAX_PIN_ATTEMPTS.
    Returns (success: bool, reason: str).
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cur = conn.execute(
                "SELECT pin_hash, salt, pin_attempts, status, expires_at FROM jobs WHERE id = ?",
                (job_id,)
            )
            row = cur.fetchone()
            if not row:
                return False, "Job not found"

            if row["status"] == "locked" or row["pin_attempts"] >= MAX_PIN_ATTEMPTS:
                return False, "Job is locked due to too many failed attempts"

            now = time.time()
            if row["expires_at"] <= now:
                return False, "Job expired"

            expected_hash = hash_pin(pin, row["salt"])
            if hmac.compare_digest(expected_hash, row["pin_hash"]):
                return True, "PIN verified"
            else:
                new_attempts = row["pin_attempts"] + 1
                if new_attempts >= MAX_PIN_ATTEMPTS:
                    conn.execute(
                        "UPDATE jobs SET pin_attempts = ?, status = 'locked' WHERE id = ?",
                        (new_attempts, job_id)
                    )
                    return False, "Incorrect PIN. Job has been locked"
                else:
                    conn.execute(
                        "UPDATE jobs SET pin_attempts = ? WHERE id = ?",
                        (new_attempts, job_id)
                    )
                    remaining = MAX_PIN_ATTEMPTS - new_attempts
                    return False, f"Incorrect PIN ({remaining} attempts remaining)"
    finally:
        conn.close()

def atomic_fetch_and_delete_job(job_id: str, db_path=None) -> tuple[dict | None, str]:
    """
    Atomically retrieve job blob metadata and transition status to 'deleted',
    ensuring one-time fetch even with concurrent requests.
    Returns (job_dict, error_code).
    error_code can be: 'OK', 'NOT_FOUND', 'EXPIRED', 'LOCKED', 'ALREADY_FETCHED' (410 Gone)
    """
    now = time.time()
    conn = get_db_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE;")
        cur = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
        row = cur.fetchone()
        if not row:
            conn.execute("ROLLBACK;")
            return None, "NOT_FOUND"

        status = row["status"]
        if status in ("deleted", "printed"):
            conn.execute("ROLLBACK;")
            return None, "ALREADY_FETCHED"
        if status == "locked":
            conn.execute("ROLLBACK;")
            return None, "LOCKED"
        if status == "expired" or row["expires_at"] <= now:
            conn.execute("UPDATE jobs SET status = 'expired', deleted_at = ? WHERE id = ?", (now, job_id))
            conn.execute("COMMIT;")
            return None, "EXPIRED"

        # Update status to deleted immediately
        conn.execute(
            "UPDATE jobs SET status = 'deleted', deleted_at = ? WHERE id = ?",
            (now, job_id)
        )
        conn.execute("COMMIT;")
        job_data = dict(row)
        job_data["status"] = "deleted"
        job_data["deleted_at"] = now
        return job_data, "OK"
    except Exception as e:
        try:
            conn.execute("ROLLBACK;")
        except Exception:
            pass
        raise e
    finally:
        conn.close()

def mark_job_printed(job_id: str, pages_printed: int, db_path=None) -> bool:
    """Record pages printed and update printed_at timestamp."""
    now = time.time()
    conn = get_db_connection(db_path)
    try:
        with conn:
            cur = conn.execute("""
                UPDATE jobs
                SET pages_printed = ?, printed_at = ?, status = 'printed'
                WHERE id = ?
            """, (pages_printed, now, job_id))
            return cur.rowcount > 0
    finally:
        conn.close()

def get_job_receipt(job_id: str, db_path=None) -> dict | None:
    """
    Return sanitized audit receipt for student verification.
    No file contents, no filenames, no encryption keys.
    """
    job = get_job(job_id, db_path)
    if not job:
        return None
    return {
        "job_id": job["id"],
        "status": job["status"],
        "pages_printed": job["pages_printed"],
        "copies": job["copies"],
        "created_at": job["created_at"],
        "printed_at": job["printed_at"],
        "deleted_at": job["deleted_at"],
        "deleted": job["status"] in ("deleted", "printed", "expired") or job["deleted_at"] is not None
    }

def get_dashboard_stats(db_path=None) -> dict:
    """Fetch dashboard metrics and recent job logs for shop owner."""
    conn = get_db_connection(db_path)
    try:
        now = time.time()
        # Today start in local time
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()

        cur = conn.execute("""
            SELECT
                COUNT(*) as total_jobs,
                SUM(CASE WHEN status = 'printed' THEN 1 ELSE 0 END) as printed_jobs,
                SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as jobs_today,
                COALESCE(SUM(CASE WHEN created_at >= ? THEN pages_printed ELSE 0 END), 0) as pages_today
            FROM jobs
        """, (today_start, today_start))
        stats = dict(cur.fetchone())

        # Recent 50 jobs (no filenames or sensitive content)
        cur = conn.execute("""
            SELECT id, mime_type, copies, created_at, status, pages_printed, printed_at, deleted_at
            FROM jobs
            ORDER BY created_at DESC
            LIMIT 50
        """)
        recent_jobs = [dict(row) for row in cur.fetchall()]

        return {
            "stats": stats,
            "recent_jobs": recent_jobs
        }
    finally:
        conn.close()

def cleanup_expired_jobs(storage_dir=None, db_path=None) -> int:
    """
    Find jobs that have expired and are still holding files.
    Securely overwrite and delete their blobs, mark status='expired'.
    """
    now = time.time()
    s_dir = Path(storage_dir or STORAGE_DIR)
    conn = get_db_connection(db_path)
    deleted_count = 0
    try:
        cur = conn.execute(
            "SELECT id, blob_path FROM jobs WHERE expires_at <= ? AND status = 'uploaded'",
            (now,)
        )
        expired = cur.fetchall()
        for row in expired:
            job_id = row["id"]
            blob_path = Path(row["blob_path"])
            if blob_path.exists():
                secure_delete_file(blob_path)
            conn.execute(
                "UPDATE jobs SET status = 'expired', deleted_at = ? WHERE id = ?",
                (now, job_id)
            )
            deleted_count += 1

        # Also purge any dangling orphan .bin files not actively mapped to an 'uploaded' job
        try:
            cur = conn.execute("SELECT blob_path FROM jobs WHERE status = 'uploaded'")
            active_blobs = {Path(r["blob_path"]).resolve() for r in cur.fetchall()}
            if s_dir.exists():
                for f in s_dir.glob("*.bin"):
                    if f.resolve() not in active_blobs:
                        secure_delete_file(f)
        except Exception:
            pass

        return deleted_count
    finally:
        conn.close()
