/**
 * SecurePrint - Browser-Side Web Crypto API helpers
 * AES-256-GCM Client-Side Encryption & Decryption
 * Zero-Knowledge Server Design: Keys live only in the URL Fragment (#)
 */

const SecureCrypto = {
    /**
     * Generate a cryptographic random 256-bit AES-GCM key
     */
    async generateKey() {
        return await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true, // extractable so we can export to URL fragment
            ["encrypt", "decrypt"]
        );
    },

    /**
     * Export raw CryptoKey to Base64URL string (URL fragment safe)
     */
    async exportKeyToBase64Url(key) {
        const raw = await window.crypto.subtle.exportKey("raw", key);
        return this.bytesToBase64Url(new Uint8Array(raw));
    },

    /**
     * Import a CryptoKey from a Base64URL string
     */
    async importKeyFromBase64Url(base64urlStr) {
        const rawBytes = this.base64UrlToBytes(base64urlStr);
        const key = await window.crypto.subtle.importKey(
            "raw",
            rawBytes,
            {
                name: "AES-GCM"
            },
            false, // non-extractable once loaded in shop
            ["decrypt"]
        );
        // Overwrite temporary buffer
        this.wipeMemory(rawBytes);
        return key;
    },

    /**
     * Encrypt ArrayBuffer or Uint8Array using AES-256-GCM.
     * Generates a 12-byte IV.
     * Concatenates: [12-byte IV] + [Ciphertext + 16-byte Auth Tag]
     * Returns: Uint8Array ready for server storage.
     */
    async encryptData(plainBytes, key) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const cipherBuffer = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128
            },
            key,
            plainBytes
        );

        const cipherBytes = new Uint8Array(cipherBuffer);
        const combined = new Uint8Array(iv.byteLength + cipherBytes.byteLength);
        combined.set(iv, 0);
        combined.set(cipherBytes, iv.byteLength);

        return combined;
    },

    /**
     * Decrypt concatenated [12-byte IV || Ciphertext + Tag] using AES-256-GCM.
     * Returns decrypted Uint8Array.
     */
    async decryptData(encryptedBytes, key) {
        if (encryptedBytes.byteLength < 28) {
            // 12 bytes IV + 16 bytes minimum auth tag
            throw new Error("Encrypted payload is corrupted or too short");
        }

        const iv = encryptedBytes.slice(0, 12);
        const cipherWithTag = encryptedBytes.slice(12);

        const plainBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128
            },
            key,
            cipherWithTag
        );

        return new Uint8Array(plainBuffer);
    },

    /**
     * Convert Uint8Array to URL-safe Base64 (base64url)
     */
    bytesToBase64Url(bytes) {
        let binary = "";
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
    },

    /**
     * Convert URL-safe Base64 (base64url) to Uint8Array
     */
    base64UrlToBytes(base64url) {
        let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
        while (base64.length % 4) {
            base64 += "=";
        }
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },

    /**
     * Wipe sensitive buffer contents in-memory
     */
    wipeMemory(typedArray) {
        if (typedArray && typedArray.fill) {
            typedArray.fill(0);
        }
    },

    /**
     * Built-in browser cryptographic self-test.
     * Runs in console on demand or test pages.
     */
    async runSelfTest() {
        console.log("[SecureCrypto] Running self-test...");
        try {
            const testMessage = "SecurePrint Self-Test: " + new Date().toISOString();
            const enc = new TextEncoder();
            const dec = new TextDecoder();
            const originalBytes = enc.encode(testMessage);

            const key = await this.generateKey();
            const exportedKey = await this.exportKeyToBase64Url(key);
            const cipherCombined = await this.encryptData(originalBytes, key);

            const importedKey = await this.importKeyFromBase64Url(exportedKey);
            const decryptedBytes = await this.decryptData(cipherCombined, importedKey);
            const resultText = dec.decode(decryptedBytes);

            const passed = (resultText === testMessage);
            console.log(passed ? "[SecureCrypto] Self-Test Passed ✔" : "[SecureCrypto] Self-Test Failed ❌");
            return passed;
        } catch (err) {
            console.error("[SecureCrypto] Self-Test Exception:", err);
            return false;
        }
    }
};

window.SecureCrypto = SecureCrypto;
