# SecurePrint — Threat Model & Security Architecture

## 1. System Overview & Problem Statement
In university photocopy and print shops, students frequently hand over sensitive personal documents (CNIC/identity cards, academic transcripts, bank statements, affidavits) via USB flash drives or WhatsApp Web. In current practice:
- Files remain indefinitely in the shop computer's `Downloads` folder, WhatsApp desktop cache, or Windows temporary directories.
- Subsequent customers using the shop PC can easily browse recent files.
- Dishonest shopkeepers can copy, aggregate, or sell personal student documents.

**SecurePrint** addresses this privacy vulnerability through client-side encryption, zero-knowledge key distribution, one-time retrieval, and in-memory canvas printing.

---

## 2. Cryptographic Architecture
- **Algorithm**: AES-256-GCM (Authenticated Encryption with Associated Data).
- **Execution Environment**: Client-side Web Crypto API (`window.crypto.subtle`) executed on the student's mobile device.
- **Key Generation**: 256-bit cryptographically secure pseudorandom key per document (`crypto.subtle.generateKey`).
- **Initialization Vector (IV)**: 12-byte unique cryptographic nonce generated per encryption (`crypto.getRandomValues`).
- **Ciphertext Storage**: Only `[12-byte IV || Ciphertext || 16-byte GCM Tag]` is stored on the server.
- **Key Distribution (Zero-Knowledge)**: The 256-bit AES key is encoded as URL-safe Base64 (`base64url`) and passed **only in the URL fragment** (`https://HOST/shop#j=<job_id>&k=<key_b64url>`). According to RFC 3986 Section 3.5, fragments are evaluated strictly on the client agent and are **never transmitted to the web server**.

```
[Student Device] 
   │  AES-256-GCM Key (256-bit) generated locally
   │  File encrypted in browser memory
   ├──► POST /api/upload (Only [IV + Ciphertext] sent to Server)
   │
   └──► Decryption Key placed ONLY in URL fragment (#k=...)
        Encoded into QR Code displayed on student screen
                               │
                               ▼ (Scanned via Webcam)
[Photocopy Shop PC]
   │  Reads Key from fragment #k=...
   │  Immediately strips fragment (history.replaceState)
   │  POST /api/job/<id>/fetch with Student PIN
   │  Server deletes blob immediately (One-time use)
   │  File decrypted IN-MEMORY ONLY
   │  Rendered directly to HTML5 Canvas (No disk/file download)
   │  Printed via browser (window.print()) with diagonal watermark
   ▼  Memory buffers zeroed out & canvases cleared
```

---

## 3. Threat Actors & Mitigations

### 3.1. Curious or Malicious Photocopy Shop Owner
- **Threat**: The shop operator attempts to save copies of student transcripts or CNICs to disk or keep files in a folder for later misuse.
- **Mitigation**:
  - The shop interface never provides a `<a download>` link or saves files to disk.
  - The file is fetched into JavaScript memory as a raw `Uint8Array`, decrypted in memory, and rendered directly to an HTML5 `<canvas>` using PDF.js or `createImageBitmap`.
  - Right-click context menu is disabled.
  - Upon print completion, all typed array memory buffers are zero-filled (`wipeMemory()`) and canvas elements are cleared from the DOM.

### 3.2. Next Customer Using the Shop PC
- **Threat**: A student uses the shop computer after another customer and looks in the browser history, address bar, or Downloads folder for sensitive files.
- **Mitigation**:
  - **No File on Disk**: Nothing is ever saved to the `Downloads/` directory or file system.
  - **URL Sanitization**: Immediately after the shop page extracts the decryption key from the URL fragment, it invokes `history.replaceState(null, "", window.location.pathname)`. If someone clicks "Back" or inspects browser history, the key is gone.
  - **HTTP Cache Control**: All shop and API routes emit `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache`.

### 3.3. Network Sniffer / Man-in-the-Middle (MitM)
- **Threat**: An eavesdropper on the shop's Wi-Fi network inspects HTTP packets or intercepts requests.
- **Mitigation**:
  - Even if traffic were intercepted, the uploaded blob is ciphertext encrypted with AES-256-GCM.
  - The decryption key is never transmitted across the wire in the HTTP payload or query string—it exists only inside the student's browser and QR code.
  - Web Crypto API enforces a Secure Context (HTTPS or localhost).

### 3.4. Compromised or Malicious Server Administrator
- **Threat**: The server administrator inspects the database or reads the files stored in `storage/`.
- **Mitigation**:
  - The server only holds ciphertext blobs. It does not have access to the key.
  - The database records only random job IDs, SHA-256 PIN hashes with per-job salts, MIME types, copy counts, and timestamps.
  - The database **never contains filenames, plaintext keys, or document contents**.
  - Even with full root database access, the administrator cannot decrypt a single document.

### 3.5. Brute-Force PIN Guessing
- **Threat**: An attacker attempts to guess the 6-digit PIN to download someone else's document.
- **Mitigation**:
  - **Hard Lockout**: After 5 failed PIN attempts, the job is permanently marked `locked`, and access is irrevocably revoked.
  - **Constant-Time Verification**: PIN validation uses `hmac.compare_digest` to prevent timing side-channel attacks.
  - **Rate Limiting**: `flask-limiter` enforces a limit of 20 requests per minute on metadata and fetch endpoints.
  - **Job ID Entropy**: 16-byte cryptographically secure random token (128 bits of entropy) prevents enumerating job IDs.

### 3.6. Double-Fetch / Replay Attacks
- **Threat**: A shop operator attempts to download the file twice or share the link with an accomplice.
- **Mitigation**:
  - `POST /api/job/<id>/fetch` is atomic using SQLite immediate transactions (`BEGIN IMMEDIATE`).
  - Upon the first successful read, the file on disk is immediately overwritten with cryptographic random bytes, synced to physical storage (`os.fsync`), unlinked (`os.remove`), and marked `status = 'deleted'`.
  - Any subsequent fetch returns **HTTP 410 Gone**.

---

## 4. Honest Security Limitations & Residual Risks

While SecurePrint provides a high standard of confidentiality against server-side breaches, network eavesdropping, and casual shop theft, the following limitations must be acknowledged:

1. **Physical Printout**:
   - Once a document is physically printed onto paper, the physical sheet is in the custody of the shop operator. SecurePrint cannot control what happens to paper printouts. A diagonal watermark (`"FOR OFFICIAL USE ONLY — SecurePrint"`) is stamped on every page to deter unauthorized photocopies.
2. **Compromised Shop Hardware (OS-Level Keyloggers / Malware)**:
   - If the shop PC is infected with kernel-level malware, screen recording software, or a malicious browser extension with permissions to read Canvas data, the rendered document could be captured.
3. **Smartphone Camera / Physical Screen Recording**:
   - SecurePrint cannot prevent a shop operator from pointing a physical smartphone camera at their monitor screen while the canvas is rendered.
4. **Browser DevTools / Memory Dumps**:
   - While buffers are zeroed out after printing, a sophisticated attacker with local administrator access to the shop PC could run a memory dump during the few seconds between rendering and printing.

---

## 5. Future Work
- **Native Print Agent**: A dedicated signed desktop service that pipes decrypted PostScript/PCL data directly into the OS print spooler without opening a browser window.
- **IPP-Over-TLS / Hardware Integration**: Sending encrypted jobs directly to enterprise printers equipped with internal cryptographic chips, bypassing the shop PC entirely.
