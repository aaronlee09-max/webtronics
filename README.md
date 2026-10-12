# Local TOTP Authenticator

A dependency-free, static browser app for generating time-based one-time passwords (TOTP).

## Features

- RFC 6238 TOTP codes with SHA-1, SHA-256, or SHA-512; six or eight digits; and configurable time period.
- Manual Base32 secret entry, `otpauth://totp/…` URI import, and camera QR scanning where the browser supports `BarcodeDetector`.
- AES-GCM encrypted local vault. A passphrase-derived key is made with PBKDF2/SHA-256; the key and decrypted entries stay in memory only while the vault is unlocked.
- Five-minute inactivity lock and encrypted JSON backup/restore.
- No analytics, external JavaScript, account login, backend, or secret synchronization.

## Run locally

Use HTTPS for the browser Web Crypto API and camera access. For a quick local preview, run a static server such as `python3 -m http.server 8000` and open `http://localhost:8000`; localhost is treated as a secure context by modern browsers. Run tests with `npm test` (Node.js, no installed dependencies required).

On GitHub Pages, the app is static. Account secrets are not uploaded by the application, but the host delivers the JavaScript that handles them.

## Security limits

This is a prototype, not an independently audited authenticator. Encryption at rest helps protect a copied browser-storage file, but it does not protect secrets while the vault is unlocked. Anyone who can change the hosted JavaScript could change it to capture the passphrase or TOTP seeds. Do not use this site for high-value accounts unless you have reviewed and trust the code and hosting; a reputable native authenticator is safer for those accounts. Keep an encrypted backup in a secure location. If the vault passphrase is lost, this app cannot recover it.

For the requested test, a shared ChatGPT OTP seed is included in this deployment's public JavaScript source. Anyone can generate its codes. Do not rely on it as account protection; after testing, re-enroll the authenticator with a fresh seed.

The app supports TOTP provisioning URIs; it does not parse Google Authenticator's multi-account migration export or HOTP provisioning. Camera QR scanning depends on browser support; the setup URI can also be pasted manually.

## References

- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238.html) — algorithm, time-step calculation, and test vectors.
- [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) — `otpauth://` provisioning URI structure.
- [MDN: SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) — browser cryptography API and security caveats.
