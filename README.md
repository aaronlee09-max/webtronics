# Authenticator

A small, dependency-free web page that shows time-based one-time codes (TOTP, RFC 6238) in a Google Authenticator style.

- Large grouped code per account, countdown pie, tap a row to copy.
- Built-in accounts are unlocked with the site password; none are stored in plain text any more.
- "+" adds more accounts from an `otpauth://` link or a Base32 key; those are stored only in the visitor's browser (localStorage).
- Run tests with `npm test`; preview with `python3 -m http.server 8000`.

## Security note

The built-in accounts are stored only as AES-GCM ciphertext in `seeds.enc.json` (PBKDF2-SHA256, 600k iterations) and are decrypted in the browser after the site password is entered. A weak password can be guessed offline because the ciphertext is public, so use a long random one. Seeds that were committed in plain text earlier remain in git history; re-enroll those authenticators.
