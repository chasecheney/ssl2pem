# ssl2pem

A small drag-and-drop macOS app that combines a private key, a certificate and a CA bundle into a single `.pem` file, and shows you what's in the certificate before you do.

Built with SwiftUI and the Security framework — no OpenSSL, no dependencies, sandboxed.

## What it does

Drop `private.key`, `certificate.crt` and `ca_bundle.crt` anywhere in the window (or one at a time into their slots) and the app will:

- Sort the files by content (private key, server certificate, chain). Several chain files dropped together are merged into one CA bundle.
- Parse the certificate and show the domain, the other names it covers (SANs), the issuer, validity dates with a days-remaining badge, key type/size, signature algorithm, serial and SHA-256 fingerprint, plus a "Show full details" view of every field the certificate carries.
- Check that the private key actually matches the certificate (RSA and ECDSA; PKCS#1, PKCS#8 and SEC1 formats; PEM or DER).
- Accept passphrase-protected keys: enter the passphrase to verify the key. Decryption happens in-process (PBES2/PBKDF2 with AES or 3DES, and the legacy `DEK-Info` format) and the key is exported still encrypted.
- Verify that the certificate chains to a root through the CA bundle, distinguishing a root macOS trusts from a private/internal CA.
- Suggest a file name from the certificate's common name (e.g. `example.com.pem`), which you can change.
- Save the combined `.pem` (⌘S) or copy it to the clipboard (⇧⌘C).

## Export safeguards

The app refuses to write a file that wouldn't work, and says why next to the Save button:

- Formats that include the key require a key that loads, is unlocked, and matches the certificate. A mismatched key blocks export rather than warning.
- A certificate that fails to parse blocks export.
- "Certificate only" exports exactly the leaf, even if the certificate slot holds a full-chain file.
- Duplicate certificates in the chain are removed; the leaf is never repeated.
- Output is written to a temporary file created with `0600` permissions (`0644` when it holds no key) and atomically swapped into place, so a failed save never leaves a half-written file and a symlink at the destination is replaced, not followed.
- Input files are limited to 5 MB and validated on import; a file that mixes a key and certificates must be dropped into a specific slot.

## PEM block order

The default order is **Key → Certificate → CA bundle**. Other orders are available from the *Format* menu with a compatibility note for each:

| Order | Typical use |
|---|---|
| Key → Certificate → CA bundle (default) | General-purpose combined file: nginx (both `ssl_certificate` and `ssl_certificate_key` pointing at it), Apache 2.4.8+, Postfix, Dovecot, Lighttpd, Exim, `curl --cert`. Most OpenSSL-based servers locate blocks by type, so this works almost everywhere. |
| Certificate → CA bundle → Key | HAProxy `crt` convention; stunnel; most OpenSSL tooling. |
| Certificate → Key → CA bundle | Some appliances and load balancers (older F5 / Citrix imports, Synology). |
| Certificate → CA bundle (no key) | Equivalent to Let's Encrypt `fullchain.pem`. For servers that take the key separately (nginx `ssl_certificate`, Apache `SSLCertificateFile`, Traefik, Caddy). Safe to share. |
| Certificate only | Just the leaf, re-armored as PEM. |

## Project layout

```
PEMCore/                       Swift package with everything that isn't UI
  Sources/PEMCore/
    PEM.swift                  PEM block extraction / armoring, PEMError
    Import.swift               File reading, size limits, role classification
    CertificateInfo.swift      X.509 parsing via SecCertificateCopyValues
    KeyAndChain.swift          Key matching, chain verification, formats, exporter, atomic writer
    KeyDecryption.swift        ASN.1 reader and in-process private-key decryption
  Tests/PEMCoreTests/          25 integration tests (fixtures generated with the system openssl)
ssl2pem/                       The app
  ssl2pemApp.swift             Entry point and menu commands
  ContentView.swift            Drop slots, passphrase field, certificate summary, output controls
  BundleModel.swift            Loads files off the main actor, runs the checks, drives export
icon/icon.svg                  Editable icon master (rendered into Assets.xcassets)
```

## Building and testing

Open `ssl2pem.xcodeproj` in Xcode 15 or newer and press Run, or from a terminal:

```sh
./build.sh          # runs `swift test` in PEMCore, then builds build/ssl2pem.app
open build/ssl2pem.app
```

`build.command` does the same when double-clicked in Finder and logs to `build/build.log`. To run only the tests:

```sh
cd PEMCore && swift test
```

The tests generate throwaway CAs, server certificates and encrypted keys with `/usr/bin/openssl` and verify the app's output with it, so the in-process parser, key matcher and exporter are checked against an independent implementation.

The app is sandboxed (user-selected file read/write) and ad-hoc signed, so it runs locally without a developer team. Minimum macOS 14.
