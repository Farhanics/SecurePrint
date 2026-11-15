/**
 * SecurePrint - Shop Interface: QR Scanning (Webcam + Image Upload), In-Memory Decryption, Canvas Rendering, & Memory Wiping
 */

document.addEventListener("DOMContentLoaded", () => {
    // UI elements
    const linkInput = document.getElementById("link-input");
    const pinInput = document.getElementById("pin-input");
    const loadBtn = document.getElementById("load-btn");
    const toggleScannerBtn = document.getElementById("toggle-scanner-btn");
    const scannerWrapper = document.getElementById("scanner-wrapper");
    const scannerVideo = document.getElementById("scanner-video");

    const uploadQrBtn = document.getElementById("upload-qr-btn");
    const qrFileInput = document.getElementById("qr-file-input");

    const statusBanner = document.getElementById("status-banner");
    const statusText = document.getElementById("status-text");

    const printControls = document.getElementById("print-controls");
    const jobInfoText = document.getElementById("job-info-text");
    const printBtn = document.getElementById("print-btn");
    const wipeBtn = document.getElementById("wipe-btn");
    const renderContainer = document.getElementById("render-container");

    let currentJobId = null;
    let currentKeyBase64 = null;
    let totalPagesRendered = 0;
    let currentCopies = 1;
    let rawDecryptedBytes = null;
    let videoStream = null;
    let scanningActive = false;

    // Set up PDF.js worker
    if (window.pdfjsLib) {
        pdfjsLib.GlobalWorkerOptions.workerSrc = "/static/js/lib/pdf.worker.min.js";
    }

    // Disable right-click context menu on shop page
    document.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        showStatus("Right-click disabled to protect student privacy.", "warning");
    });

    // Check if URL has fragment on load (#j=...&k=...)
    parseUrlFragment();

    /**
     * Robust URL Fragment Parser
     * Handles full URLs, relative URLs, raw fragments, or direct param strings.
     */
    function parseUrlFragment(rawInput = null) {
        let text = rawInput ? String(rawInput).trim() : window.location.hash;
        if (!text) return false;

        let queryString = "";
        const hashIdx = text.indexOf("#");
        if (hashIdx !== -1) {
            queryString = text.substring(hashIdx + 1);
        } else if (text.includes("j=") && text.includes("k=")) {
            const qIdx = text.indexOf("?");
            queryString = (qIdx !== -1) ? text.substring(qIdx + 1) : text;
        }

        if (!queryString) return false;

        const params = new URLSearchParams(queryString);
        const j = params.get("j");
        const k = params.get("k");

        if (j && k) {
            currentJobId = j;
            currentKeyBase64 = k;
            linkInput.value = `Job: ${j}`;

            // Clean address bar fragment
            if (!rawInput) {
                history.replaceState(null, "", window.location.pathname);
            }

            showStatus(`Job [${j.substring(0, 8)}...] detected! Enter the 6-digit PIN to decrypt.`, "info");
            pinInput.focus();
            return true;
        }
        return false;
    }

    // ==========================================
    // QR Code Image Upload & File Decoding
    // ==========================================
    if (uploadQrBtn && qrFileInput) {
        uploadQrBtn.addEventListener("click", () => {
            qrFileInput.click();
        });

        qrFileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                decodeQrFromImageFile(e.target.files[0]);
                qrFileInput.value = ""; // reset so same file can be re-selected if needed
            }
        });
    }

    // Drag and drop QR image onto the scan section
    const scanSection = document.getElementById("scan-section");
    if (scanSection) {
        ["dragenter", "dragover"].forEach(eventName => {
            scanSection.addEventListener(eventName, (e) => {
                e.preventDefault();
                scanSection.style.borderColor = "var(--accent-emerald)";
            }, false);
        });

        ["dragleave", "drop"].forEach(eventName => {
            scanSection.addEventListener(eventName, (e) => {
                e.preventDefault();
                scanSection.style.borderColor = "var(--border)";
            }, false);
        });

        scanSection.addEventListener("drop", (e) => {
            const files = e.dataTransfer?.files;
            if (files && files.length > 0 && files[0].type.startsWith("image/")) {
                decodeQrFromImageFile(files[0]);
            }
        });
    }

    // Support Ctrl+V paste of QR screenshot anywhere on page
    document.addEventListener("paste", (e) => {
        const items = e.clipboardData?.items;
        if (!items) return;

        for (let i = 0; i < items.length; i++) {
            if (items[i].type.startsWith("image/")) {
                const blob = items[i].getAsFile();
                if (blob) {
                    showStatus("Pasted image detected. Scanning for QR code...", "info");
                    decodeQrFromImageFile(blob);
                    break;
                }
            }
        }
    });

    /**
     * Decode QR code from an image file/blob using jsQR
     */
    function decodeQrFromImageFile(file) {
        showStatus("Analyzing QR image...", "info");
        const reader = new FileReader();
        reader.onload = function(evt) {
            const img = new Image();
            img.onload = function() {
                const canvas = document.createElement("canvas");
                const ctx = canvas.getContext("2d", { willReadFrequently: true });
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);

                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

                // Attempt standard detection
                let code = jsQR(imageData.data, imageData.width, imageData.height, {
                    inversionAttempts: "dontInvert"
                });

                // If not found, try with color inversion
                if (!code || !code.data) {
                    code = jsQR(imageData.data, imageData.width, imageData.height, {
                        inversionAttempts: "attemptBoth"
                    });
                }

                if (code && code.data) {
                    console.log("[Shop] QR Code detected from image:", code.data);
                    const parsed = parseUrlFragment(code.data);
                    if (parsed) {
                        showStatus("QR code verified from uploaded image! ✔ Enter 6-digit PIN.", "success");
                    } else {
                        showStatus("QR detected, but missing SecurePrint job parameters.", "warning");
                    }
                } else {
                    showStatus("Could not find a readable QR code in this image. Please ensure the QR is sharp and centered.", "danger");
                }
            };
            img.onerror = function() {
                showStatus("Failed to load image file.", "danger");
            };
            img.src = evt.target.result;
        };
        reader.readAsDataURL(file);
    }

    // ==========================================
    // Webcam QR Scanner logic
    // ==========================================
    toggleScannerBtn.addEventListener("click", () => {
        if (scanningActive) {
            stopScanner();
        } else {
            startScanner();
        }
    });

    async function startScanner() {
        try {
            videoStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: "environment" }
            });
            scannerVideo.srcObject = videoStream;
            scannerVideo.setAttribute("playsinline", true);
            await scannerVideo.play();

            scannerWrapper.style.display = "block";
            toggleScannerBtn.textContent = "🛑 Stop Camera Scanner";
            scanningActive = true;
            requestAnimationFrame(tickScanner);
        } catch (err) {
            console.error("Camera access error:", err);
            showStatus("Camera not available: " + err.message + ". Use 'Upload QR Image' or paste the link instead.", "warning");
        }
    }

    function stopScanner() {
        if (videoStream) {
            videoStream.getTracks().forEach(track => track.stop());
            videoStream = null;
        }
        scannerWrapper.style.display = "none";
        toggleScannerBtn.textContent = "📷 Open Webcam Scanner";
        scanningActive = false;
    }

    const scanCanvas = document.createElement("canvas");
    const scanCtx = scanCanvas.getContext("2d", { willReadFrequently: true });

    function tickScanner() {
        if (!scanningActive) return;

        if (scannerVideo.readyState === scannerVideo.HAVE_ENOUGH_DATA) {
            scanCanvas.width = scannerVideo.videoWidth;
            scanCanvas.height = scannerVideo.videoHeight;
            scanCtx.drawImage(scannerVideo, 0, 0, scanCanvas.width, scanCanvas.height);

            const imageData = scanCtx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: "dontInvert"
            });

            if (code && code.data) {
                console.log("[Shop] QR Code detected from webcam:", code.data);
                stopScanner();
                parseUrlFragment(code.data);
                return;
            }
        }
        requestAnimationFrame(tickScanner);
    }

    // Manual paste / input handler for link input box
    ["input", "change", "paste"].forEach(evtName => {
        linkInput.addEventListener(evtName, (e) => {
            setTimeout(() => {
                const val = linkInput.value.trim();
                if (val.includes("j=") || val.includes("#")) {
                    parseUrlFragment(val);
                }
            }, 50);
        });
    });

    // ==========================================
    // Load & Decrypt Button
    // ==========================================
    loadBtn.addEventListener("click", async () => {
        const pin = pinInput.value.trim();
        if (!pin) {
            showStatus("Please enter the 6-digit PIN provided by the student.", "warning");
            pinInput.focus();
            return;
        }

        if (!currentJobId || !currentKeyBase64) {
            const manual = linkInput.value.trim();
            parseUrlFragment(manual);
        }

        if (!currentJobId || !currentKeyBase64) {
            showStatus("Missing Job ID or Decryption Key. Please upload the QR image or paste the full link.", "danger");
            return;
        }

        loadBtn.disabled = true;
        showStatus("Fetching ciphertext from server & verifying one-time token...", "info");

        try {
            // 1. Fetch ciphertext atomically (server deletes blob immediately)
            const fetchRes = await fetch(`/api/job/${encodeURIComponent(currentJobId)}/fetch`, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({ pin: pin })
            });

            if (fetchRes.status === 410) {
                throw new Error("Job is GONE (410). File has already been downloaded, printed, or expired.");
            }
            if (fetchRes.status === 423) {
                throw new Error("Job is LOCKED (423). Too many incorrect PIN attempts.");
            }
            if (fetchRes.status === 401) {
                throw new Error("Unauthorized (401). Please sign in to the shop station.");
            }
            if (!fetchRes.ok) {
                const errJson = await fetchRes.json().catch(() => ({}));
                throw new Error(errJson.error || `Fetch error (Status ${fetchRes.status})`);
            }

            const mimeType = fetchRes.headers.get("X-Job-Mime") || "application/pdf";
            currentCopies = parseInt(fetchRes.headers.get("X-Job-Copies") || "1", 10);

            showStatus("Decrypting file in memory (AES-256-GCM)...", "info");

            const encryptedBuffer = await fetchRes.arrayBuffer();
            const encryptedBytes = new Uint8Array(encryptedBuffer);

            // 2. Import key and decrypt in memory
            const cryptoKey = await SecureCrypto.importKeyFromBase64Url(currentKeyBase64);
            rawDecryptedBytes = await SecureCrypto.decryptData(encryptedBytes, cryptoKey);

            // Clear encrypted bytes from memory
            SecureCrypto.wipeMemory(encryptedBytes);

            showStatus("Rendering preview onto secure canvas...", "info");

            // 3. Render directly onto canvas (zero download / zero disk footprint)
            renderContainer.innerHTML = "";
            totalPagesRendered = 0;

            if (mimeType === "application/pdf") {
                await renderPdfToCanvas(rawDecryptedBytes);
            } else if (mimeType.startsWith("image/")) {
                await renderImageToCanvas(rawDecryptedBytes, mimeType);
            } else {
                throw new Error("Unsupported document type: " + mimeType);
            }

            // 4. Update UI for printing
            jobInfoText.textContent = `Job Verified ✔ | Copies: ${currentCopies} | Total Pages: ${totalPagesRendered}`;
            printControls.style.display = "block";
            showStatus("Decrypted in memory ✔ File purged from server disk.", "success");

        } catch (err) {
            console.error("Fetch/Decrypt Error:", err);
            showStatus(err.message, "danger");
        } finally {
            loadBtn.disabled = false;
        }
    });

    // Render PDF onto Canvas with Print Watermark
    async function renderPdfToCanvas(pdfBytes) {
        const loadingTask = pdfjsLib.getDocument({ data: pdfBytes });
        const pdf = await loadingTask.promise;
        totalPagesRendered = pdf.numPages;

        for (let pageNum = 1; pageNum <= totalPagesRendered; pageNum++) {
            const page = await pdf.getPage(pageNum);
            const viewport = page.getViewport({ scale: 1.5 });

            const wrapper = document.createElement("div");
            wrapper.className = "page-canvas-wrapper";

            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");
            canvas.width = viewport.width;
            canvas.height = viewport.height;

            const renderContext = {
                canvasContext: ctx,
                viewport: viewport
            };
            await page.render(renderContext).promise;

            // Add diagonal watermark on every page
            const watermark = document.createElement("div");
            watermark.className = "print-watermark";
            watermark.textContent = "FOR OFFICIAL USE ONLY — SecurePrint";

            wrapper.appendChild(canvas);
            wrapper.appendChild(watermark);
            renderContainer.appendChild(wrapper);
        }
    }

    // Render Image onto Canvas with Print Watermark
    async function renderImageToCanvas(imageBytes, mimeType) {
        totalPagesRendered = 1;
        const blob = new Blob([imageBytes], { type: mimeType });
        const imgBitmap = await createImageBitmap(blob);

        const wrapper = document.createElement("div");
        wrapper.className = "page-canvas-wrapper";

        const canvas = document.createElement("canvas");
        const ctx = canvas.getContext("2d");
        canvas.width = imgBitmap.width;
        canvas.height = imgBitmap.height;

        ctx.drawImage(imgBitmap, 0, 0);

        const watermark = document.createElement("div");
        watermark.className = "print-watermark";
        watermark.textContent = "FOR OFFICIAL USE ONLY — SecurePrint";

        wrapper.appendChild(canvas);
        wrapper.appendChild(watermark);
        renderContainer.appendChild(wrapper);
    }

    // Print Button
    printBtn.addEventListener("click", async () => {
        window.print();

        // After print dialog, confirm and record pages printed
        try {
            const billablePages = totalPagesRendered * currentCopies;
            await fetch(`/api/job/${encodeURIComponent(currentJobId)}/printed`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ pages: billablePages })
            });

            showStatus(`Printed successfully (${billablePages} total pages recorded). Wiping memory...`, "success");
            setTimeout(wipeMemoryAndReset, 1500);
        } catch (e) {
            console.error("Print record update error:", e);
        }
    });

    // Wipe Memory and Reset
    wipeBtn.addEventListener("click", () => {
        wipeMemoryAndReset();
    });

    function wipeMemoryAndReset() {
        if (rawDecryptedBytes) {
            SecureCrypto.wipeMemory(rawDecryptedBytes);
            rawDecryptedBytes = null;
        }

        // Clear canvas elements
        const canvases = renderContainer.querySelectorAll("canvas");
        canvases.forEach(c => {
            const ctx = c.getContext("2d");
            ctx.clearRect(0, 0, c.width, c.height);
        });
        renderContainer.innerHTML = "";

        // Reset variables
        currentJobId = null;
        currentKeyBase64 = null;
        totalPagesRendered = 0;
        linkInput.value = "";
        pinInput.value = "";
        printControls.style.display = "none";
        loadBtn.disabled = false;

        showStatus("Session sanitized. File removed from memory ✔", "success");
    }

    function showStatus(msg, type = "info") {
        statusBanner.style.display = "block";
        statusBanner.className = `notice-box badge-${type}`;
        statusText.textContent = msg;
    }
});
