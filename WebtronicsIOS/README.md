# Webtronics for iOS and iPadOS

Native SwiftUI companion app for the existing Webtronics TOTP authenticator.

## Open in Xcode

1. Download or clone this repository on a Mac with Xcode installed.
2. Open `WebtronicsIOS/Webtronics.xcodeproj`.
3. Select the **Webtronics** target and choose an iPhone or iPad simulator.
4. To install on a physical device, select your Apple Developer team under **Signing & Capabilities**. Xcode will manage the development provisioning profile.
5. Press **Run**.

The project targets iOS/iPadOS 16.0 or later and uses only Apple frameworks (SwiftUI, CryptoKit, CommonCrypto, and UIKit).

## Features

- Password gate matching the current web app.
- Reads the existing encrypted `seeds.enc.json` format.
- PBKDF2-HMAC-SHA256 key derivation with the iteration count and salt from the encrypted record, followed by AES-256-GCM decryption.
- TOTP codes using SHA-1, SHA-256, or SHA-512; 6- or 8-digit codes and configurable periods.
- One-second refresh, countdown ring, warning color during the final five seconds, and tap-to-copy.
- Manual lock button; decrypted accounts are cleared from app state when locked.
- iPhone and iPad adaptive layout.

## Security notes

- The bundled seed file is ciphertext, not plaintext account secrets. The password is not saved by the app.
- Because the encrypted record is included in the app bundle, a weak password could be guessed offline. Use a long, unique password.
- This project does not upload account data or call a network service.
- TOTP secrets necessarily exist in memory while the vault is unlocked. Lock the app when finished.
- Review the existing repository history before distributing: previously committed plaintext secrets, if any, cannot be erased just by encrypting the current file.

## Notes

This repository contains the Xcode project source, not a signed IPA. Building and installing on an iPhone/iPad requires Xcode on macOS and appropriate Apple signing. App Store distribution additionally requires an Apple Developer account and App Store Connect submission.
