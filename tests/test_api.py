import os
import io
import time
import pytest
from pathlib import Path
from flask import session

import config
import db
from app import app, limiter

@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create test client with isolated temp database and storage dir."""
    test_db = tmp_path / "test_secureprint.db"
    test_storage = tmp_path / "test_storage"
    test_storage.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DB_PATH", test_db)
    monkeypatch.setattr(config, "STORAGE_DIR", test_storage)
    monkeypatch.setattr(db, "DB_PATH", test_db)
    monkeypatch.setattr(db, "STORAGE_DIR", test_storage)

    db.init_db(test_db)

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["RATELIMIT_ENABLED"] = False
    limiter.enabled = False

    with app.test_client() as client:
        yield client

def test_upload_success(client):
    """Test successful student file upload with encrypted ciphertext."""
    payload = b"\x01\x02\x03\x04" * 16  # mock IV + ciphertext
    data = {
        "blob": (io.BytesIO(payload), "blob.bin"),
        "mime_type": "application/pdf",
        "size": str(len(payload)),
        "copies": "2"
    }
    res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.data}"
    json_data = res.get_json()
    assert "job_id" in json_data
    assert "pin" in json_data
    assert len(json_data["pin"]) == 6
    assert json_data["copies"] == 2

    # Verify file stored on disk
    job_id = json_data["job_id"]
    blob_path = config.STORAGE_DIR / f"{job_id}.bin"
    assert blob_path.exists()
    assert blob_path.read_bytes() == payload

    # Verify DB record
    job = db.get_job(job_id)
    assert job is not None
    assert job["status"] == "uploaded"
    assert job["mime_type"] == "application/pdf"
    assert job["copies"] == 2

def test_disallowed_mime_type(client):
    """Test rejection of non-whitelisted mime types."""
    data = {
        "blob": (io.BytesIO(b"malicious script"), "script.sh"),
        "mime_type": "application/x-sh",
        "size": "16",
        "copies": "1"
    }
    res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "Disallowed MIME type" in res.get_json()["error"]

def test_oversized_file_rejected(client, monkeypatch):
    """Test rejection when file size exceeds MAX_UPLOAD_BYTES."""
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 100)
    data = {
        "blob": (io.BytesIO(b"A" * 200), "large.bin"),
        "mime_type": "application/pdf",
        "size": "200",
        "copies": "1"
    }
    res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert res.status_code in (400, 413)

def test_invalid_copies_count(client):
    """Test validation of copy counts (1 - 5 allowed)."""
    data_zero = {
        "blob": (io.BytesIO(b"mock-data"), "test.bin"),
        "mime_type": "application/pdf",
        "size": "9",
        "copies": "0"
    }
    res = client.post("/api/upload", data=data_zero, content_type="multipart/form-data")
    assert res.status_code == 400

    data_six = {
        "blob": (io.BytesIO(b"mock-data"), "test.bin"),
        "mime_type": "application/pdf",
        "size": "9",
        "copies": "6"
    }
    res = client.post("/api/upload", data=data_six, content_type="multipart/form-data")
    assert res.status_code == 400

def test_wrong_pin_and_lockout(client):
    """Test incorrect PIN attempts leading to permanent lockout after 5 attempts."""
    data = {
        "blob": (io.BytesIO(b"top-secret"), "doc.bin"),
        "mime_type": "image/png",
        "size": "10",
        "copies": "1"
    }
    upload_res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert upload_res.status_code == 201, f"Upload failed: {upload_res.data}"
    job_info = upload_res.get_json()
    job_id = job_info["job_id"]
    correct_pin = job_info["pin"]

    # Attempts 1 to 4 with incorrect PIN
    for i in range(1, 5):
        res = client.get(f"/api/job/{job_id}/meta?pin=000000")
        assert res.status_code == 403
        assert f"{5 - i} attempts remaining" in res.get_json()["error"]

    # Attempt 5: triggers lockout
    res_lock = client.get(f"/api/job/{job_id}/meta?pin=000000")
    assert res_lock.status_code in (403, 423)
    assert "locked" in res_lock.get_json()["error"].lower()

    # Attempt 6 (even with correct PIN): rejected due to lock
    res_after_lock = client.get(f"/api/job/{job_id}/meta?pin={correct_pin}")
    assert res_after_lock.status_code == 423
    assert "locked" in res_after_lock.get_json()["error"].lower()

def test_atomic_fetch_once_and_blob_deletion(client):
    """
    Test that shop fetch:
    1. Requires shop authentication.
    2. Atomically returns ciphertext.
    3. IMMEDIATELY wipes and deletes the blob from disk.
    4. Second fetch call returns 410 Gone.
    """
    test_blob = b"encrypted_payload_12345"
    data = {
        "blob": (io.BytesIO(test_blob), "doc.bin"),
        "mime_type": "application/pdf",
        "size": str(len(test_blob)),
        "copies": "3"
    }
    up_res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert up_res.status_code == 201, f"Upload failed: {up_res.data}"
    job = up_res.get_json()
    job_id = job["job_id"]
    pin = job["pin"]

    blob_path = config.STORAGE_DIR / f"{job_id}.bin"
    assert blob_path.exists()

    # Unauthenticated fetch should fail
    fetch_unauth = client.post(f"/api/job/{job_id}/fetch", data={"pin": pin})
    assert fetch_unauth.status_code == 401

    # Login as shop operator
    login_res = client.post("/shop/login", data={
        "username": config.SHOP_USER,
        "password": config.DEFAULT_DEV_PASSWORD
    })
    assert login_res.status_code in (200, 302)

    # First fetch: should succeed
    fetch_res = client.post(f"/api/job/{job_id}/fetch", data={"pin": pin})
    assert fetch_res.status_code == 200
    assert fetch_res.data == test_blob
    assert fetch_res.headers.get("X-Job-Copies") == "3"
    assert fetch_res.headers.get("X-Job-Mime") == "application/pdf"

    # Verify blob file is really DELETED from disk
    assert not blob_path.exists()

    # Second fetch call: must return 410 Gone
    second_fetch = client.post(f"/api/job/{job_id}/fetch", data={"pin": pin})
    assert second_fetch.status_code == 410
    assert "410 Gone" in second_fetch.get_json()["error"]

def test_print_confirmation_and_receipt(client):
    """Test recording printed pages and verifying student receipt."""
    data = {
        "blob": (io.BytesIO(b"mock-pages"), "doc.bin"),
        "mime_type": "application/pdf",
        "size": "10",
        "copies": "1"
    }
    up_res = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert up_res.status_code == 201, f"Upload failed: {up_res.data}"
    up = up_res.get_json()
    job_id = up["job_id"]

    # Student checks receipt before print
    r1 = client.get(f"/api/receipt/{job_id}").get_json()
    assert r1["job_id"] == job_id
    assert r1["status"] == "uploaded"
    assert r1["deleted"] is False

    # Shop logs in & records printed
    client.post("/shop/login", data={
        "username": config.SHOP_USER,
        "password": config.DEFAULT_DEV_PASSWORD
    })
    print_res = client.post(f"/api/job/{job_id}/printed", json={"pages": 4})
    assert print_res.status_code == 200

    # Student checks receipt after print
    r2 = client.get(f"/api/receipt/{job_id}").get_json()
    assert r2["status"] == "printed"
    assert r2["pages_printed"] == 4
    assert r2["printed_at"] is not None

def test_expiry_cleanup_deletes_disk_blobs(client):
    """Test that background cleanup purges expired jobs and overwrites blobs."""
    # Create an expired job directly
    job_id = "test_expired_job"
    blob_path = config.STORAGE_DIR / f"{job_id}.bin"
    blob_path.write_bytes(b"expired_content_to_overwrite")

    db.create_job(
        job_id=job_id,
        pin="123456",
        blob_path=str(blob_path),
        mime_type="application/pdf",
        size_bytes=28,
        copies=1,
        ttl_seconds=-60  # expired 60 seconds ago
    )

    assert blob_path.exists()

    # Run cleanup
    purged = db.cleanup_expired_jobs()
    assert purged >= 1

    # File must be deleted from storage
    assert not blob_path.exists()

    # Status must be expired
    job = db.get_job(job_id)
    assert job["status"] == "expired"
    assert job["deleted_at"] is not None

def test_db_stores_zero_sensitive_data():
    """Verify schema and database rows contain no filename or secret key columns."""
    conn = db.get_db_connection()
    cur = conn.execute("PRAGMA table_info(jobs);")
    columns = [row["name"].lower() for row in cur.fetchall()]
    conn.close()

    forbidden_columns = ["filename", "file_name", "key", "secret", "file_content", "plain_pin"]
    for col in forbidden_columns:
        assert col not in columns, f"Forbidden column '{col}' found in jobs table!"
