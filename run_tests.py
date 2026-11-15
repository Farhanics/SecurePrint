import sys
import tempfile
import shutil
from pathlib import Path

# Setup test environment
test_dir = Path(tempfile.mkdtemp(prefix="test_sp_"))
test_db = test_dir / "test.db"
test_storage = test_dir / "storage"
test_storage.mkdir(parents=True, exist_ok=True)

import config
import db
config.DB_PATH = test_db
config.STORAGE_DIR = test_storage
db.DB_PATH = test_db
db.STORAGE_DIR = test_storage

db.init_db(test_db)

from app import app
app.config["TESTING"] = True
app.config["WTF_CSRF_ENABLED"] = False

# Import test functions
import tests.test_api as t

class MockTmpPath:
    def __init__(self, p):
        self.p = p
    def __truediv__(self, other):
        return self.p / other

class MonkeyPatch:
    def setattr(self, target, name, value):
        setattr(target, name, value)

mp = MonkeyPatch()
tmp = MockTmpPath(test_dir)

print("[*] Running SecurePrint Test Suite...")

tests = [
    ("test_db_stores_zero_sensitive_data", lambda: t.test_db_stores_zero_sensitive_data()),
    ("test_upload_success", lambda: t.test_upload_success(app.test_client())),
    ("test_disallowed_mime_type", lambda: t.test_disallowed_mime_type(app.test_client())),
    ("test_oversized_file_rejected", lambda: t.test_oversized_file_rejected(app.test_client(), mp)),
    ("test_invalid_copies_count", lambda: t.test_invalid_copies_count(app.test_client())),
    ("test_wrong_pin_and_lockout", lambda: t.test_wrong_pin_and_lockout(app.test_client())),
    ("test_atomic_fetch_once_and_blob_deletion", lambda: t.test_atomic_fetch_once_and_blob_deletion(app.test_client())),
    ("test_print_confirmation_and_receipt", lambda: t.test_print_confirmation_and_receipt(app.test_client())),
    ("test_expiry_cleanup_deletes_disk_blobs", lambda: t.test_expiry_cleanup_deletes_disk_blobs(app.test_client())),
]

passed = 0
failed = 0

for name, fn in tests:
    try:
        fn()
        print(f"  [PASS] {name}")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] {name}: {e}")
        import traceback
        traceback.print_exc()
        failed += 1

print(f"\n[*] Results: {passed} passed, {failed} failed.")

# Cleanup temp dir
try:
    shutil.rmtree(test_dir, ignore_errors=True)
except Exception:
    pass

if failed > 0:
    sys.exit(1)
