# SecurePrint — Privacy-First Printing for Photocopy Shops 🖨️🔒

> **University Cybersecurity Final Year Project**  
> Zero-Knowledge Client-Side Encryption & Ephemeral In-Memory Printing System

---

## 📌 The Problem
When students need to print sensitive documents (CNIC/identity cards, university transcripts, salary slips, affidavits) at commercial photocopy shops, they typically send files via **WhatsApp Web** or **USB drives**.

**The Vulnerability:**
- Documents permanently reside in the shop PC's `Downloads` directory, WhatsApp media cache, or Windows temp files.
- Subsequent customers or operators can view, copy, or distribute these confidential files.
- Dishonest shopkeepers can harvest sensitive personal data at scale.

---

## 💡 The Solution: SecurePrint
SecurePrint is an end-to-end encrypted, zero-knowledge print workflow:
1. **Client-Side Encryption**: The student picks a file on their phone. A 256-bit AES-GCM key is generated directly in their browser using the **Web Crypto API**. The file is encrypted *before* it leaves the phone.
2. **Key Stays in URL Fragment**: The decryption key is encoded exclusively in the URL fragment (`#j=<job_id>&k=<key>`). Per RFC 3986, URL fragments are processed purely on the client and are **never transmitted to the server**.
3. **QR Code Handshake**: The student presents a QR code encoding this link plus a 6-digit PIN.
4. **In-Memory Decryption & Canvas Render**: The shop terminal scans the QR, reads the key, removes the fragment from the address bar, fetches the ciphertext, decrypts it **in RAM only**, and renders it onto an HTML5 `<canvas>` using PDF.js.
5. **Immediate Server Destruction**: The server atomically deletes the encrypted blob from disk on the very first fetch. Any subsequent attempt returns **410 Gone**.
6. **Wipe & Proof of Deletion**: When printing is finished, all memory buffers are wiped (`Uint8Array.fill(0)`), and the student receives a cryptographically verifiable audit receipt.

---

## 📁 Repository Structure
```
cybersecurity/
├── app.py                 # Flask server, security headers, cleanup worker, endpoints
├── db.py                  # SQLite schema, atomic transactions, secure file overwrite
├── config.py              # Security parameters, TTL, file limits, shop credentials
├── requirements.txt       # Dependencies (Flask, Flask-Limiter, cryptography, pytest)
├── .env.example           # Environment template with pre-hashed credentials
├── .gitignore             # Ensures .db, .env, and storage/*.bin are never committed
├── THREAT_MODEL.md        # Comprehensive threat analysis and honest limitations
├── README.md              # Setup guide, demo walkthrough, viva defense points
├── storage/               # Encrypted blobs (.bin) only (ephemeral)
├── templates/
│   ├── index.html         # Student upload and browser encryption page
│   ├── login.html         # Shop operator authentication
│   ├── shop.html          # Shop print station with webcam scanner & canvas render
│   ├── dashboard.html     # Shop audit logs (timestamps & page billing only)
│   └── receipt.html       # Student deletion verification receipt
├── static/
│   ├── css/style.css      # Responsive styles & print watermark
│   ├── js/crypto.js       # Web Crypto API AES-256-GCM helpers & self-test
│   ├── js/upload.js       # Student upload flow, key generation, QR display
│   ├── js/shop.js         # Shop QR scanning, in-memory decrypt, canvas print
│   └── js/lib/            # qrcode.min.js, jsQR.js, pdf.min.js, pdf.worker.min.js
└── tests/
    └── test_api.py        # Automated test suite (pytest)
```

---

## 🚀 Quickstart & Setup

### 1. Requirements
- Python 3.10+
- Modern Web Browser (Chrome, Firefox, Safari, Edge) with Web Crypto support

### 2. Installation
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python app.py
```
By default, the server runs on `http://127.0.0.1:5000`.

### 4. Default Shop Credentials
- **Username**: `shopadmin`
- **Password**: `shop123_ChangeMe!`

---

## 📱 Mobile Phone Demo with HTTPS (Cloudflare / Ngrok)
> [!NOTE]  
> The browser **Web Crypto API** requires a **Secure Context** (`HTTPS` or `http://localhost`). To test from a physical mobile phone camera on the local network, use a tunnel:

### Option A: Cloudflare Tunnel (Recommended, No signup required)
```bash
cloudflared tunnel --url http://localhost:5000
```
Open the generated `https://xxxx.trycloudflare.com` on your mobile phone.

### Option B: Ngrok
```bash
ngrok http 5000
```
Open the provided HTTPS forwarding URL on your phone.

---

## 🎬 Viva Demonstration Script

### Step 1: The "Normal Way" (The Problem)
1. Explain to the examiner: *"Normally, a student sends their CNIC or transcript via WhatsApp Web to the shop computer."*
2. Open Windows Explorer on the shop PC and show the `Downloads` folder containing previously downloaded sensitive customer documents.

### Step 2: The SecurePrint Way
1. On your phone (or a browser tab at `/`), choose a sample PDF or image.
2. Select **2 Copies** and click **"Encrypt & Generate Print Code"**.
3. Note to the examiner:
   - The browser generated a 256-bit AES key locally.
   - The document was encrypted into ciphertext in RAM.
   - The server received only the ciphertext. The key was embedded into the URL fragment `#` of the QR code.
4. On the shop terminal (`/shop`), log in with `shopadmin` / `shop123_ChangeMe!`.
5. Point the shop webcam at the student's phone QR code (or paste the link).
6. Enter the 6-digit student PIN.
7. Click **"Fetch, Decrypt & Render In-Memory"**.
8. Notice:
   - The document renders directly onto an HTML5 `<canvas>`.
   - No file is ever created in the shop PC's `Downloads` folder!
9. Click **"Print Now"** (`Ctrl+P` dialog opens). Point out the **"FOR OFFICIAL USE ONLY — SecurePrint"** diagonal watermark across the printed page.
10. Confirm print. Notice the notification: *"File deleted from server & wiped from memory ✔"*.

### Step 3: Proving Security to the Examiner
1. **Proof 1: Server Disk is Clean**
   Inspect the server's `storage/` directory:
   ```bash
   ls storage/
   ```
   *Result: The directory is completely empty.*
2. **Proof 2: Second Attempt is Blocked (410 Gone)**
   Scan the same QR code again or re-enter the link.
   *Result: Server returns `410 Gone: Job has already been downloaded and purged`.*
3. **Proof 3: Database Privacy**
   Open the SQLite database `secureprint.db`:
   ```sql
   SELECT * FROM jobs;
   ```
   *Result: Only random job IDs, SHA-256 PIN hashes, and timestamps exist. There are NO filenames, plaintext keys, or document contents.*
4. **Proof 4: Brute-Force PIN Lockout**
   Attempt to access a job with 5 incorrect PINs.
   *Result: The job enters a `locked` state, and even the correct PIN will now be rejected with HTTP 423.*
5. **Proof 5: Student Verification Receipt**
   On the student device, click **"Verify File Deletion Proof"** (`/receipt/<job_id>`).
   *Result: Displays green confirmation that the ciphertext was wiped from server storage.*

---

## 🧪 Running Automated Tests

Run the full pytest suite:
```bash
python -m pytest tests/ -v
```

Tests verify:
- Valid upload with encryption metadata
- Rejection of disallowed MIME types (`.sh`, `.exe`, `.zip`)
- Rejection of oversized payloads (> 10 MB)
- Copy count boundary validation (1–5)
- PIN verification with constant-time compare (`hmac.compare_digest`)
- Hard lockout after 5 consecutive failed PIN attempts (HTTP 423)
- Atomic single-fetch enforcement (subsequent requests return HTTP 410)
- Verification that blob files are securely overwritten and unlinked from physical storage
- Periodic cleanup worker purging expired jobs
- Database schema inspection proving zero storage of filenames, keys, or plaintext PINs

---

## 🛡️ Viva & Defense Questions

<details>
<summary><strong>Q: Why use the URL fragment (<code>#</code>) instead of a query parameter (<code>?</code>)?</strong></summary>
Per RFC 3986 Section 3.5, the URI fragment is processed exclusively by user agents (browsers) and is <em>never sent in HTTP request headers</em>. Consequently, neither the web server, reverse proxies, nor intermediate firewalls ever receive the decryption key.
</details>

<details>
<summary><strong>Q: What happens if two shop terminals try to fetch the job simultaneously?</strong></summary>
The backend executes <code>db.atomic_fetch_and_delete_job</code> within an immediate SQLite transaction (<code>BEGIN IMMEDIATE</code>). The first terminal changes the status to <code>deleted</code>; the second transaction fails the atomic conditional check and receives <code>410 Gone</code>.
</details>

<details>
<summary><strong>Q: How does SecurePrint prevent saving files from the browser?</strong></summary>
SecurePrint renders PDF pages and images directly onto HTML5 <code>&lt;canvas&gt;</code> elements rather than using <code>&lt;iframe&gt;</code> or <code>&lt;a download&gt;</code> tags. Right-click context menus are disabled, and all typed array buffers in memory are zeroed out after printing.
</details>
