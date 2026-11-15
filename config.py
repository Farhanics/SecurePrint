import os
import secrets
from pathlib import Path
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Base directories
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
STORAGE_DIR = BASE_DIR / "storage"
DB_PATH = BASE_DIR / "secureprint.db"

# Ensure storage directory exists
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

def _safe_int_env(key: str, default: int) -> int:
    val = str(os.environ.get(key, "")).strip()
    digits = "".join(c for c in val if c.isdigit())
    return int(digits) if digits else default

# Application constants
JOB_TTL_SECONDS = _safe_int_env("JOB_TTL_SECONDS", 600)  # 10 minutes default
MAX_UPLOAD_BYTES = _safe_int_env("MAX_UPLOAD_MB", 10) * 1024 * 1024  # 10 MB limit
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/png"
}
MAX_COPIES = 5
MIN_COPIES = 1
MAX_PIN_ATTEMPTS = 5

# Rate limit rules
RATE_LIMIT_UPLOAD = "10 per minute"
RATE_LIMIT_META_FETCH = "20 per minute"

# Shop credentials
SHOP_USER = os.environ.get("SHOP_USER", "shopadmin")
# Default password fallback if no hash provided in env
DEFAULT_DEV_PASSWORD = os.environ.get("SHOP_PASS", "shop123_ChangeMe!")
SHOP_PASS_HASH = os.environ.get("SHOP_PASS_HASH")
if not SHOP_PASS_HASH:
    # Generate hash for dev default password
    SHOP_PASS_HASH = generate_password_hash(DEFAULT_DEV_PASSWORD)

# Flask secret key
SECRET_KEY = os.environ.get("SECRET_KEY", "secureprint-dev-key-" + secrets.token_hex(16))

# Session security
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1")
