/**
 * SecurePrint - Student Upload & Client-Side Encryption Workflow
 */

document.addEventListener("DOMContentLoaded", () => {
    const fileInput = document.getElementById("file-input");
    const dropzone = document.getElementById("dropzone");
    const uploadForm = document.getElementById("upload-form");
    const previewArea = document.getElementById("preview-area");
    const filePreview = document.getElementById("file-preview");
    const fileNameSpan = document.getElementById("file-name");
    const fileSizeSpan = document.getElementById("file-size");
    const copiesSelect = document.getElementById("copies-select");
    const ttlSelect = document.getElementById("ttl-select");
    const encryptBtn = document.getElementById("encrypt-btn");
    const statusBox = document.getElementById("status-box");
    const statusMessage = document.getElementById("status-message");

    // Result elements
    const resultCard = document.getElementById("result-card");
    const pinDisplay = document.getElementById("pin-display");
    const timerDisplay = document.getElementById("timer-display");
    const qrTarget = document.getElementById("qrcode-target");
    const shareLinkInput = document.getElementById("share-link-input");
    const copyLinkBtn = document.getElementById("copy-link-btn");
    const copyAllBtn = document.getElementById("copy-all-btn");
    const whatsappBtn = document.getElementById("whatsapp-btn");
    const openPrintBtn = document.getElementById("open-print-btn");
    const checkReceiptBtn = document.getElementById("check-receipt-btn");

    let selectedFile = null;
    let countdownInterval = null;

    // Supported types
    const ALLOWED_TYPES = ["application/pdf", "image/jpeg", "image/png"];
    const MAX_SIZE = 10 * 1024 * 1024; // 10MB

    // Drag and drop handlers
    dropzone.addEventListener("click", () => fileInput.click());

    ["dragenter", "dragover"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.remove("dragover");
        }, false);
    });

    dropzone.addEventListener("drop", (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelection(files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            handleFileSelection(e.target.files[0]);
        }
    });

    function handleFileSelection(file) {
        if (!ALLOWED_TYPES.includes(file.type)) {
            alert("Disallowed file type. Please upload a PDF, JPEG, or PNG document.");
            return;
        }
        if (file.size > MAX_SIZE) {
            alert("File is too large. Maximum size is 10 MB.");
            return;
        }

        selectedFile = file;
        fileNameSpan.textContent = file.name;
        fileSizeSpan.textContent = `(${(file.size / (1024 * 1024)).toFixed(2)} MB)`;

        // Image preview if image
        if (file.type.startsWith("image/")) {
            const reader = new FileReader();
            reader.onload = (e) => {
                filePreview.innerHTML = `<img src="${e.target.result}" style="max-height: 80px; border-radius: 6px;">`;
            };
            reader.readAsDataURL(file);
        } else {
            filePreview.innerHTML = `<div style="font-size: 2rem;">📄</div>`;
        }

        previewArea.style.display = "block";
        encryptBtn.disabled = false;
    }

    // Encrypt & Upload
    uploadForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!selectedFile) return;

        encryptBtn.disabled = true;
        statusBox.style.display = "block";
        statusMessage.textContent = "Generating 256-bit AES key on your device...";

        try {
            // 1. Read file as ArrayBuffer
            const arrayBuffer = await selectedFile.arrayBuffer();
            const fileBytes = new Uint8Array(arrayBuffer);

            // 2. Generate random 256-bit key
            statusMessage.textContent = "Encrypting file in browser (AES-256-GCM)...";
            const key = await SecureCrypto.generateKey();
            const keyBase64Url = await SecureCrypto.exportKeyToBase64Url(key);

            // 3. Encrypt data
            const encryptedBytes = await SecureCrypto.encryptData(fileBytes, key);

            // Overwrite original plaintext buffer
            SecureCrypto.wipeMemory(fileBytes);

            statusMessage.textContent = "Uploading encrypted ciphertext to server...";

            // 4. Send encrypted payload
            const formData = new FormData();
            const blob = new Blob([encryptedBytes], { type: "application/octet-stream" });
            formData.append("blob", blob, "ciphertext.bin");
            formData.append("mime_type", selectedFile.type);
            formData.append("size", selectedFile.size.toString());
            formData.append("copies", copiesSelect.value);
            formData.append("ttl_minutes", ttlSelect ? ttlSelect.value : "10");

            const response = await fetch("/api/upload", {
                method: "POST",
                body: formData
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || "Upload failed");
            }

            // Zero out encrypted buffer
            SecureCrypto.wipeMemory(encryptedBytes);

            // 5. Display success, QR, Shareable Link, and PIN
            showSuccess(data, keyBase64Url);

        } catch (err) {
            console.error("Encryption/Upload error:", err);
            statusBox.style.display = "none";
            alert("Error: " + err.message);
            encryptBtn.disabled = false;
        }
    });

    function showSuccess(jobData, keyBase64Url) {
        document.getElementById("upload-card").style.display = "none";
        statusBox.style.display = "none";
        resultCard.style.display = "block";

        pinDisplay.textContent = jobData.pin;

        // Build shop link with key in URL fragment (#)
        const shopUrl = `${window.location.origin}/shop#j=${encodeURIComponent(jobData.job_id)}&k=${encodeURIComponent(keyBase64Url)}`;
        
        // Populate share link input
        if (shareLinkInput) {
            shareLinkInput.value = shopUrl;
        }

        // WhatsApp Share Message
        if (whatsappBtn) {
            const shareText = `Assalam-o-Alaikum! Please print my secure document:\n\n🔗 Link: ${shopUrl}\n🔑 PIN: ${jobData.pin}\n\n(Auto-destructs after printing. No files stay on your PC).`;
            whatsappBtn.href = `https://api.whatsapp.com/send?text=${encodeURIComponent(shareText)}`;
        }

        // Copy Link Button
        if (copyLinkBtn) {
            copyLinkBtn.onclick = () => {
                navigator.clipboard.writeText(shopUrl).then(() => {
                    const original = copyLinkBtn.textContent;
                    copyLinkBtn.textContent = "Copied! ✔";
                    setTimeout(() => copyLinkBtn.textContent = original, 2000);
                }).catch(() => {
                    prompt("Copy this link:", shopUrl);
                });
            };
        }

        // Copy Both Link & PIN Button
        if (copyAllBtn) {
            copyAllBtn.onclick = () => {
                const combined = `Print Link: ${shopUrl}\nPIN: ${jobData.pin}\n(Expires in ${ttlSelect ? ttlSelect.value : 10} minutes)`;
                navigator.clipboard.writeText(combined).then(() => {
                    const original = copyAllBtn.textContent;
                    copyAllBtn.textContent = "Link & PIN Copied! ✔";
                    setTimeout(() => copyAllBtn.textContent = original, 2500);
                }).catch(() => {
                    prompt("Copy details:", combined);
                });
            };
        }

        // Direct Open in Print Page Button
        if (openPrintBtn) {
            openPrintBtn.href = shopUrl;
        }

        // Render QR Code
        qrTarget.innerHTML = "";
        new QRCode(qrTarget, {
            text: shopUrl,
            width: 200,
            height: 200,
            colorDark: "#0f172a",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.M
        });

        // Receipt button
        if (checkReceiptBtn) {
            checkReceiptBtn.onclick = () => {
                window.location.href = `/receipt/${jobData.job_id}`;
            };
        }

        // Start countdown timer with exact expires_at timestamp
        startCountdown(jobData.expires_at);

        // Smooth scroll to result
        resultCard.scrollIntoView({ behavior: "smooth" });
    }

    function startCountdown(expiresAtSeconds) {
        clearInterval(countdownInterval);

        function update() {
            const now = Math.floor(Date.now() / 1000);
            const remaining = Math.max(0, Math.floor(expiresAtSeconds - now));

            const hours = Math.floor(remaining / 3600);
            const mins = Math.floor((remaining % 3600) / 60);
            const secs = remaining % 60;

            if (hours > 0) {
                timerDisplay.textContent = `${hours}h ${String(mins).padStart(2, "0")}m ${String(secs).padStart(2, "0")}s`;
            } else {
                timerDisplay.textContent = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
            }

            if (remaining <= 60) {
                timerDisplay.parentElement.classList.add("urgent");
            } else {
                timerDisplay.parentElement.classList.remove("urgent");
            }

            if (remaining <= 0) {
                clearInterval(countdownInterval);
                timerDisplay.textContent = "EXPIRED";
                alert("This print job has expired. The encrypted file was securely purged from the server.");
            }
        }

        update();
        countdownInterval = setInterval(update, 1000);
    }
});
