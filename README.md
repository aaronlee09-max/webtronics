# Authenticator

A small, dependency-free web page that shows time-based one-time codes (TOTP, RFC 6238) in a Google Authenticator style.

- Large grouped code per account, countdown pie, tap a row to copy.
- Two built-in ChatGPT accounts ("chatgpt 1", "chatgpt 2").
- "+" adds more accounts from an `otpauth://` link or a Base32 key; those are stored only in the visitor's browser (localStorage).
- Run tests with `npm test`; preview with `python3 -m http.server 8000`.

## Security note

There is no site lock yet. The built-in seeds are plain text in `app.js` of a public repository, so anyone can generate those codes. A password-locked version (encrypted seeds, single password screen) exists in git history at commit `9b74a7d` and can be restored when the lock is added.
