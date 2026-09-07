# ssl2pem

A small drag-and-drop macOS app that combines a private key, a certificate and a CA bundle into a single `.pem` file, and shows you what's in the certificate before you do.

Built with SwiftUI and the Security framework — no OpenSSL, no dependencies.

## Download

[Download ssl2pem 1.0 for macOS](https://github.com/chasecheney/ssl2pem/releases/download/v1.0.0/ssl2pem-1.0-macos-universal.zip) · [Release notes and checksum](https://github.com/chasecheney/ssl2pem/releases/tag/v1.0.0)

Requires macOS 14 or newer. Unzip the download and move `ssl2pem.app` to Applications. The universal app supports Intel and Apple Silicon and is Developer ID signed.

## What it does

Drop `private.key`, `certificate.crt` and `ca_bundle.crt` anywhere in the window (or one at a time into their slots) and the app will:

- Parse the certificate and show the domain, the other names it covers (SANs), the issuer, validity dates with a days-remaining badge, key type/size, signature algorithm, serial and SHA-256 fingerprint.
- Check that the private key actually matches the certificate (RSA and ECDSA, PKCS#1, PKCS#8 and SEC1 formats).
- Verify that the certificate chains to a trusted root through the CA bundle.
- Let you expand a full details view with every field the certificate carries (extensions, key usage, policies, OCSP/CRL URLs, fingerprints, and so on).
- Suggest a file name from the certificate's common name (e.g. `example.com.pem`, `wildcard.example.com.pem`), which you can change.
- Save the combined `.pem` (⌘S) or copy it to the clipboard (⇧⌘C). Files that include the private key are written with `0600` permissions.

Inputs can be PEM or DER, and stray text around the PEM blocks (such as `openssl x509 -text` output) is stripped. A duplicate of the leaf certificate inside the CA bundle is removed automatically.

## PEM block order

The default order is **Key → Certificate → CA bundle**. Other orders are available from the *Order* menu with a compatibility note for each:

| Order | Typical use |
|---|---|
| Key → Certificate → CA bundle (default) | General-purpose combined file: nginx (both `ssl_certificate` and `ssl_certificate_key` pointing at it), Apache 2.4.8+, Postfix, Dovecot, Lighttpd, Exim, `curl --cert`. Most OpenSSL-based servers locate blocks by type, so this works almost everywhere. |
| Certificate → CA bundle → Key | HAProxy `crt` convention; stunnel; most OpenSSL tooling. |
| Certificate → Key → CA bundle | Some appliances and load balancers (older F5 / Citrix imports, Synology). |
| Certificate → CA bundle (no key) | Equivalent to Let's Encrypt `fullchain.pem`. For servers that take the key separately (nginx `ssl_certificate`, Apache `SSLCertificateFile`, Traefik, Caddy). Safe to share. |
| Certificate only | Just the leaf, re-armored as PEM. |

## Building

Open `ssl2pem.xcodeproj` in Xcode 15 or newer and press Run, or from a terminal:

```sh
./build.sh          # produces build/ssl2pem.app
open build/ssl2pem.app
```

The app is sandboxed (user-selected file read/write) and ad-hoc signed, so it runs locally without a developer team. Minimum macOS 14.

## Project layout

```
ssl2pem/
  ssl2pemApp.swift      App entry point and menu commands
  ContentView.swift     Drop slots, certificate summary, output controls
  BundleModel.swift     Loads files, classifies them, runs the checks, saves output
  CertificateInfo.swift X.509 parsing via SecCertificateCopyValues
  KeyAndChain.swift     Private-key matching, chain verification, PEM assembly
  PEM.swift             PEM block extraction / armoring
```
