import os
import secrets
import time
import threading
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, jsonify, render_template, session, redirect,
    url_for, send_file, Response, make_response, abort
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

import config
import db

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES + (1024 * 1024)  # small overhead allowance
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE

# Setup Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

# Authentication Decorator
def shop_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("shop_authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized. Shop authentication required."}), 401
            return redirect(url_for("shop_login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Security Headers & Cache-Control
@app.after_request
def apply_security_headers(response: Response):
    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Prevent referrer leakage (protect fragments & keys)
    response.headers["Referrer-Policy"] = "no-referrer"
    # Strict Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "media-src 'self' blob:; "
        "worker-src 'self' blob:;"
    )
    # Never cache sensitive or dynamic responses
    if request.path.startswith("/api/") or request.path.startswith("/shop"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response

# Error Handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": f"File exceeds maximum allowed size ({config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB)"}), 413

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": f"Rate limit exceeded: {e.description}"}), 429

@app.errorhandler(500)
@app.errorhandler(Exception)
def handle_internal_server_error(e):
    import traceback
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    app.logger.error(f"Internal Server Error: {e}\n{traceback.format_exc()}")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
    return f"""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>500 Internal Server Error</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 2rem; line-height: 1.6; }}
            .container {{ max-width: 800px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 2rem; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
            h1 {{ color: #ef4444; margin-top: 0; }}
            pre {{ background: #0f172a; border: 1px solid #475569; border-radius: 6px; padding: 1rem; overflow-x: auto; color: #fca5a5; font-size: 0.9rem; }}
            .btn {{ display: inline-block; background: #3b82f6; color: #fff; text-decoration: none; padding: 0.6rem 1.2rem; border-radius: 6px; margin-top: 1rem; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>500 Internal Server Error</h1>
            <p>The application encountered an unexpected error:</p>
            <p><strong>{type(e).__name__}:</strong> {str(e)}</p>
            <h3>Traceback:</h3>
            <pre>{traceback.format_exc()}</pre>
            <a href="/" class="btn">← Back to Home</a>
        </div>
    </body>
    </html>
    """, 500

# Frontend View Routes
@app.route("/")
def index():
    """Student file upload and encryption page."""
    return render_template("index.html", max_mb=config.MAX_UPLOAD_BYTES // (1024 * 1024))

@app.route("/shop/login", methods=["GET", "POST"])
def shop_login():
    """Shop login view."""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == config.SHOP_USER and check_password_hash(config.SHOP_PASS_HASH, password):
            session.clear()
            session["shop_authenticated"] = True
            session["shop_user"] = username
            next_url = request.args.get("next") or url_for("shop_page")
            return redirect(next_url)
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)

@app.route("/shop/logout")
def shop_logout():
    """Shop logout."""
    session.clear()
    return redirect(url_for("shop_login"))

@app.route("/shop")
@app.route("/print")
def shop_page():
    """Shop QR scan and print interface (Public access - secured by client key & PIN)."""
    return render_template("shop.html")

@app.route("/shop/dashboard")
@app.route("/dashboard")
@app.route("/shop/dash")
@app.route("/dash")
@shop_login_required
def shop_dashboard():
    """Shop audit history and statistics dashboard."""
    return render_template("dashboard.html", shop_user=session.get("shop_user"))

@app.route("/receipt/<job_id>")
def view_receipt(job_id):
    """Student receipt status verification page."""
    return render_template("receipt.html", job_id=job_id)

# API Endpoints
@app.route("/api/upload", methods=["POST"])
@limiter.limit(config.RATE_LIMIT_UPLOAD)
def api_upload():
    """
    Store student ciphertext blob.
    Accepts:
      - 'blob': encrypted binary payload [iv || ciphertext+tag]
      - 'mime_type': original mime type
      - 'copies': requested copy count (1-5)
      - 'size': original plaintext size in bytes
    Returns:
      - job_id, pin, expires_at
    """
    if "blob" not in request.files:
        return jsonify({"error": "Missing encrypted blob file"}), 400

    blob_file = request.files["blob"]
    mime_type = request.form.get("mime_type", "").strip()
    size_str = request.form.get("size", "0").strip()
    copies_str = request.form.get("copies", "1").strip()

    if mime_type not in config.ALLOWED_MIME_TYPES:
        return jsonify({"error": f"Disallowed MIME type '{mime_type}'. Only PDF, JPEG, and PNG allowed."}), 400

    try:
        copies = int(copies_str)
        if not (config.MIN_COPIES <= copies <= config.MAX_COPIES):
            return jsonify({"error": f"Copies must be between {config.MIN_COPIES} and {config.MAX_COPIES}."}), 400
    except ValueError:
        return jsonify({"error": "Invalid copies parameter"}), 400

    try:
        size_bytes = int(size_str)
    except ValueError:
        size_bytes = 0

    # Read binary blob data
    blob_data = blob_file.read()
    blob_size = len(blob_data)

    if blob_size == 0:
        return jsonify({"error": "Uploaded blob cannot be empty"}), 400

    if blob_size > config.MAX_UPLOAD_BYTES:
        return jsonify({"error": "Encrypted blob exceeds maximum allowed size"}), 413

    # Generate random 16-byte URL-safe job ID and 6-digit numeric PIN
    job_id = secrets.token_urlsafe(16)
    pin = f"{secrets.randbelow(900000) + 100000}"

    blob_path = config.STORAGE_DIR / f"{job_id}.bin"
    with open(blob_path, "wb") as f:
        f.write(blob_data)

    # Custom TTL countdown (max 5 hours = 300 minutes)
    ttl_str = request.form.get("ttl_minutes", str(config.DEFAULT_TTL_MINUTES)).strip()
    try:
        ttl_minutes = int(ttl_str)
        if ttl_minutes < config.MIN_TTL_MINUTES:
            ttl_minutes = config.MIN_TTL_MINUTES
        elif ttl_minutes > config.MAX_TTL_MINUTES:
            ttl_minutes = config.MAX_TTL_MINUTES
    except (ValueError, TypeError):
        ttl_minutes = config.DEFAULT_TTL_MINUTES
    ttl_seconds = ttl_minutes * 60

    job_entry = db.create_job(
        job_id=job_id,
        pin=pin,
        blob_path=str(blob_path),
        mime_type=mime_type,
        size_bytes=size_bytes or blob_size,
        copies=copies,
        ttl_seconds=ttl_seconds
    )

    return jsonify({
        "success": True,
        "job_id": job_id,
        "pin": pin,
        "expires_at": job_entry["expires_at"],
        "ttl_seconds": ttl_seconds,
        "copies": job_entry["copies"]
    }), 201

@app.route("/api/job/<job_id>/meta", methods=["GET"])
@limiter.limit(config.RATE_LIMIT_META_FETCH)
def api_job_meta(job_id):
    """
    Validate PIN and return job metadata (mime_type, copies, expires_at)
    without downloading or deleting the blob yet.
    """
    pin = request.args.get("pin", "").strip()
    if not pin:
        return jsonify({"error": "Missing PIN parameter"}), 400

    verified, reason = db.check_and_update_pin(job_id, pin)
    if not verified:
        status_code = 423 if "locked" in reason.lower() else (410 if "expired" in reason.lower() else 403)
        return jsonify({"error": reason}), status_code

    job = db.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job["status"] in ("deleted", "printed"):
        return jsonify({"error": "Job has already been fetched or printed"}), 410

    return jsonify({
        "job_id": job["id"],
        "mime_type": job["mime_type"],
        "copies": job["copies"],
        "expires_at": job["expires_at"],
        "status": job["status"]
    })

@app.route("/api/job/<job_id>/fetch", methods=["POST"])
@limiter.limit(config.RATE_LIMIT_META_FETCH)
def api_job_fetch(job_id):
    """
    Atomically retrieve the ciphertext blob and IMMEDIATELY wipe/delete the file from disk.
    Any second attempt returns 410 Gone.
    """
    pin = request.form.get("pin", "") or (request.get_json(silent=True) or {}).get("pin", "")
    pin = str(pin).strip()

    if not pin:
        return jsonify({"error": "PIN is required to fetch the job"}), 400

    verified, reason = db.check_and_update_pin(job_id, pin)
    if not verified:
        status_code = 423 if "locked" in reason.lower() else (410 if "expired" in reason.lower() else 403)
        return jsonify({"error": reason}), status_code

    job, error_code = db.atomic_fetch_and_delete_job(job_id)
    if error_code == "ALREADY_FETCHED":
        return jsonify({"error": "410 Gone: Job has already been downloaded and purged from the server."}), 410
    if error_code == "EXPIRED":
        return jsonify({"error": "Job has expired"}), 410
    if error_code == "LOCKED":
        return jsonify({"error": "Job is locked"}), 423
    if error_code == "NOT_FOUND":
        return jsonify({"error": "Job not found"}), 404

    blob_path = Path(job["blob_path"])
    if not blob_path.exists():
        return jsonify({"error": "Encrypted blob not found or already destroyed"}), 410

    try:
        with open(blob_path, "rb") as f:
            blob_bytes = f.read()
    finally:
        # Securely overwrite and unlink blob immediately upon read
        db.secure_delete_file(blob_path)

    response = make_response(blob_bytes)
    response.headers["Content-Type"] = "application/octet-stream"
    response.headers["X-Job-Mime"] = job["mime_type"]
    response.headers["X-Job-Copies"] = str(job["copies"])
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

@app.route("/api/job/<job_id>/printed", methods=["POST"])
def api_job_printed(job_id):
    """Record pages printed after shop operator confirms browser printing."""
    data = request.get_json(silent=True) or request.form
    try:
        pages = int(data.get("pages", 1))
    except (ValueError, TypeError):
        pages = 1

    success = db.mark_job_printed(job_id, pages)
    if not success:
        return jsonify({"error": "Failed to update print status"}), 400

    return jsonify({
        "success": True,
        "message": "Print confirmed and receipt updated.",
        "pages_printed": pages
    })

@app.route("/api/receipt/<job_id>", methods=["GET"])
def api_receipt(job_id):
    """Return deletion audit receipt for the student."""
    receipt = db.get_job_receipt(job_id)
    if not receipt:
        return jsonify({"error": "Receipt not found"}), 404
    return jsonify(receipt)

@app.route("/api/dashboard/stats", methods=["GET"])
@shop_login_required
def api_dashboard_stats():
    """Shop dashboard statistics and audit log."""
    data = db.get_dashboard_stats()
    return jsonify(data)

# Background Cleanup Thread
def run_periodic_cleanup():
    while True:
        try:
            db.cleanup_expired_jobs()
        except Exception:
            pass
        time.sleep(60)

# Initialize Database and Start Cleanup Worker
with app.app_context():
    db.init_db()
    # Initial cleanup of any orphan or expired files
    db.cleanup_expired_jobs()

cleanup_thread = threading.Thread(target=run_periodic_cleanup, daemon=True)
cleanup_thread.start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] SecurePrint running on http://{host}:{port}")
    print(f"[*] Default Shop User: {config.SHOP_USER}")
    app.run(host=host, port=port, debug=False)
