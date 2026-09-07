import Foundation
import Security

// MARK: - Private key inspection

public struct PrivateKeyInfo: @unchecked Sendable {
    public enum Match: Sendable { case matches, mismatch, unknown }

    public let typeDescription: String
    public let isEncrypted: Bool
    public let match: Match
    public let note: String
    /// Loaded key, when it could be parsed (and decrypted).
    public let key: SecKey?
    /// Error that prevented loading the key (bad passphrase, unsupported format…).
    public let loadError: PEMError?

    public var needsPassphrase: Bool { isEncrypted && key == nil && loadError == nil }
}

public enum PrivateKeyInspector {
    static let rsaOID = "1.2.840.113549.1.1.1"
    static let ecOID  = "1.2.840.10045.2.1"

    /// Inspect the first private key block in `blocks`, optionally decrypting it, and compare
    /// its public key with `certificate`. Never throws: every outcome is described in the result.
    public static func inspect(blocks: [PEM.Block], passphrase: String = "", certificate: SecCertificate?) -> PrivateKeyInfo {
        guard let block = blocks.first(where: \.isPrivateKey) else {
            return PrivateKeyInfo(typeDescription: "No private key found", isEncrypted: false, match: .unknown,
                                  note: "The file does not contain a PRIVATE KEY block.", key: nil,
                                  loadError: PEMError("The file does not contain a private key."))
        }

        var type = block.type
        var der = block.der
        let encrypted = block.isEncryptedPrivateKey
        if encrypted {
            if passphrase.isEmpty {
                return PrivateKeyInfo(typeDescription: "Encrypted private key", isEncrypted: true, match: .unknown,
                                      note: "Enter the passphrase to verify this key against the certificate.",
                                      key: nil, loadError: nil)
            }
            do {
                let plain = try KeyDecryption.decrypt(block, passphrase: passphrase)
                type = plain.type
                der = plain.der
            } catch let e as PEMError {
                return PrivateKeyInfo(typeDescription: "Encrypted private key", isEncrypted: true, match: .unknown,
                                      note: e.message, key: nil, loadError: e)
            } catch {
                let e = PEMError(error.localizedDescription)
                return PrivateKeyInfo(typeDescription: "Encrypted private key", isEncrypted: true, match: .unknown,
                                      note: e.message, key: nil, loadError: e)
            }
        }

        let loaded = load(type: type, der: der)
        guard let key = loaded.key else {
            let err = PEMError(loaded.error ?? "The private key is invalid or uses an unsupported format.")
            return PrivateKeyInfo(typeDescription: loaded.description, isEncrypted: encrypted, match: .unknown,
                                  note: err.message, key: nil, loadError: err)
        }

        var description = loaded.description
        if let attrs = SecKeyCopyAttributes(key) as? [String: Any],
           let bits = attrs[kSecAttrKeySizeInBits as String] as? Int {
            description += " \(bits)-bit"
        }
        if encrypted { description += " (encrypted)" }

        guard let certificate else {
            return PrivateKeyInfo(typeDescription: description, isEncrypted: encrypted, match: .unknown,
                                  note: "Drop a certificate to verify that the key matches it.", key: key, loadError: nil)
        }
        guard let certKey = SecCertificateCopyKey(certificate),
              let certPub = SecKeyCopyExternalRepresentation(certKey, nil) as Data?,
              let pub = SecKeyCopyPublicKey(key),
              let keyPub = SecKeyCopyExternalRepresentation(pub, nil) as Data? else {
            return PrivateKeyInfo(typeDescription: description, isEncrypted: encrypted, match: .unknown,
                                  note: "The certificate's public key could not be read, so the key can't be verified.",
                                  key: key, loadError: nil)
        }
        if certPub == keyPub {
            return PrivateKeyInfo(typeDescription: description, isEncrypted: encrypted, match: .matches,
                                  note: "Private key matches the certificate's public key.", key: key, loadError: nil)
        }
        return PrivateKeyInfo(typeDescription: description, isEncrypted: encrypted, match: .mismatch,
                              note: "Private key does NOT match the certificate. Choose the key used to request this certificate.",
                              key: key, loadError: nil)
    }

    private struct Loaded {
        var key: SecKey?
        var description: String
        var error: String?
    }

    private static func load(type: String, der: Data) -> Loaded {
        switch type {
        case "RSA PRIVATE KEY":
            return Loaded(key: makeKey(der, type: kSecAttrKeyTypeRSA), description: "RSA")
        case "EC PRIVATE KEY":
            guard let x963 = ecPrivateToX963(der) else {
                return Loaded(key: nil, description: "ECDSA", error: "The EC private key doesn't include its public point, so it can't be verified.")
            }
            return Loaded(key: makeKey(x963, type: kSecAttrKeyTypeECSECPrimeRandom), description: "ECDSA")
        case "PRIVATE KEY":
            // PKCS#8: SEQUENCE { INTEGER, SEQUENCE { OID, params }, OCTET STRING }
            guard let outer = ASN1.elements(in: der).first, outer.tag == 0x30 else {
                return Loaded(key: nil, description: "Private key", error: nil)
            }
            let parts = ASN1.elements(in: outer.content)
            guard parts.count >= 3, parts[1].tag == 0x30, parts[2].tag == 0x04,
                  let oidTLV = ASN1.elements(in: parts[1].content).first, oidTLV.tag == 0x06 else {
                return Loaded(key: nil, description: "Private key", error: nil)
            }
            let oid = ASN1.oidString(oidTLV.content)
            switch oid {
            case rsaOID:
                return Loaded(key: makeKey(parts[2].content, type: kSecAttrKeyTypeRSA), description: "RSA")
            case ecOID:
                guard let x963 = ecPrivateToX963(parts[2].content) else {
                    return Loaded(key: nil, description: "ECDSA", error: "The EC private key doesn't include its public point, so it can't be verified.")
                }
                return Loaded(key: makeKey(x963, type: kSecAttrKeyTypeECSECPrimeRandom), description: "ECDSA")
            default:
                let name = OIDNames.name(for: oid) ?? oid
                return Loaded(key: nil, description: name, error: "\(name) keys can't be verified against the certificate on macOS.")
            }
        default:
            return Loaded(key: nil, description: type.capitalized, error: "Unrecognized private key format.")
        }
    }

    private static func makeKey(_ data: Data, type: CFString) -> SecKey? {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: type,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        return SecKeyCreateWithData(data as CFData, attrs as CFDictionary, nil)
    }

    /// Convert an RFC 5915 ECPrivateKey structure into the X9.63 form (04 || X || Y || d)
    /// that SecKeyCreateWithData expects for EC private keys.
    private static func ecPrivateToX963(_ der: Data) -> Data? {
        guard let outer = ASN1.elements(in: der).first, outer.tag == 0x30 else { return nil }
        let parts = ASN1.elements(in: outer.content)
        guard parts.count >= 2, parts[1].tag == 0x04 else { return nil }
        let d = parts[1].content
        guard let pubWrapper = parts.first(where: { $0.tag == 0xA1 }),
              let bitString = ASN1.elements(in: pubWrapper.content).first, bitString.tag == 0x03,
              bitString.content.count > 1 else { return nil }
        let point = bitString.content.dropFirst()
        guard point.first == 0x04 else { return nil }
        return Data(point) + d
    }
}

// MARK: - Chain verification

public struct ChainInfo: Sendable {
    public enum Status: Sendable { case valid, privateRoot, invalid, unknown }
    public let status: Status
    public let summary: String
    public let chain: [String]        // subject summaries, leaf first
    public let bundleCount: Int
}

public enum ChainVerifier {
    public static func verify(leaf: SecCertificate?, bundle: [SecCertificate]) -> ChainInfo {
        guard let leaf else {
            let names = bundle.compactMap { SecCertificateCopySubjectSummary($0) as String? }
            return ChainInfo(status: .unknown,
                             summary: bundle.isEmpty ? "No CA bundle loaded." : "Drop a certificate to verify the chain.",
                             chain: names, bundleCount: bundle.count)
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let certs = [leaf] + bundle
        guard SecTrustCreateWithCertificates(certs as CFArray, policy, &trust) == errSecSuccess, let trust else {
            return ChainInfo(status: .unknown, summary: "Could not create trust evaluation.", chain: [], bundleCount: bundle.count)
        }
        // Structural check only; expiry is reported separately.
        SecTrustSetOptions(trust, [.allowExpired, .allowExpiredRoot])

        var error: CFError?
        let ok = SecTrustEvaluateWithError(trust, &error)
        var names: [String] = []
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
            names = chain.compactMap { SecCertificateCopySubjectSummary($0) as String? }
        }
        if ok {
            let rootNote = bundle.isEmpty ? " (using system roots only — no intermediates supplied)" : ""
            return ChainInfo(status: .valid,
                             summary: "Chain verified to a root trusted by macOS (\(names.count) certificates)\(rootNote).",
                             chain: names, bundleCount: bundle.count)
        }
        let message = (error as Error?)?.localizedDescription ?? "Chain could not be verified."

        // Second pass: self-signed certificates in the bundle act as anchors. Success means the
        // chain is structurally complete and simply ends in a private / internal CA.
        let selfSigned = bundle.filter { isSelfSigned($0) }
        if !selfSigned.isEmpty {
            var trust2: SecTrust?
            if SecTrustCreateWithCertificates(certs as CFArray, policy, &trust2) == errSecSuccess, let trust2 {
                SecTrustSetAnchorCertificates(trust2, selfSigned as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust2, true)
                SecTrustSetOptions(trust2, [.allowExpired, .allowExpiredRoot])
                if SecTrustEvaluateWithError(trust2, nil) {
                    var names2 = names
                    if let chain = SecTrustCopyCertificateChain(trust2) as? [SecCertificate] {
                        names2 = chain.compactMap { SecCertificateCopySubjectSummary($0) as String? }
                    }
                    let root = names2.last ?? "the bundle's root"
                    return ChainInfo(status: .privateRoot,
                                     summary: "Chain is complete up to “\(root)”, which is not a root macOS trusts (private or internal CA). Fine if your clients trust that root.",
                                     chain: names2, bundleCount: bundle.count)
                }
            }
        }
        return ChainInfo(status: .invalid, summary: message, chain: names, bundleCount: bundle.count)
    }

    public static func isSelfSigned(_ cert: SecCertificate) -> Bool {
        guard let values = SecCertificateCopyValues(cert, [kSecOIDX509V1SubjectName, kSecOIDX509V1IssuerName] as CFArray, nil) as? [String: [String: Any]],
              let subject = values[kSecOIDX509V1SubjectName as String]?[kSecPropertyKeyValue as String] as? [[String: Any]],
              let issuer = values[kSecOIDX509V1IssuerName as String]?[kSecPropertyKeyValue as String] as? [[String: Any]] else {
            return false
        }
        let s = subject.map { "\($0[kSecPropertyKeyLabel as String] ?? "")=\($0[kSecPropertyKeyValue as String] ?? "")" }
        let i = issuer.map { "\($0[kSecPropertyKeyLabel as String] ?? "")=\($0[kSecPropertyKeyValue as String] ?? "")" }
        return s == i
    }
}

// MARK: - Output formats

public enum PEMOrder: String, CaseIterable, Identifiable, Sendable {
    case keyCertCA
    case certCAKey
    case certKeyCA
    case certCA
    case certOnly

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .keyCertCA: return "Key → Certificate → CA bundle"
        case .certCAKey: return "Certificate → CA bundle → Key"
        case .certKeyCA: return "Certificate → Key → CA bundle"
        case .certCA:    return "Certificate → CA bundle (no key)"
        case .certOnly:  return "Certificate only"
        }
    }

    public var includesKey: Bool {
        switch self {
        case .keyCertCA, .certCAKey, .certKeyCA: return true
        case .certCA, .certOnly: return false
        }
    }

    public var includesCA: Bool { self != .certOnly }

    public var compatibility: String {
        switch self {
        case .keyCertCA:
            return "General-purpose combined file. Works with nginx (ssl_certificate and ssl_certificate_key both pointing at this file), Apache 2.4.8+ (SSLCertificateFile), Postfix, Dovecot, Lighttpd, Exim, curl --cert, and most tools that read a single PEM. Servers locate blocks by type, so order rarely matters here."
        case .certCAKey:
            return "HAProxy convention (crt directive): leaf first, then chain, then the key. Also the layout most OpenSSL-based tools and stunnel expect. Works anywhere the key→cert→CA order works."
        case .certKeyCA:
            return "Leaf certificate immediately followed by its key, then the chain. Used by some appliances and load balancers (e.g. older F5 / Citrix imports, Synology). Functionally equivalent for OpenSSL-based servers."
        case .certCA:
            return "Full chain without the private key — the same content as Let's Encrypt's fullchain.pem. Use for nginx ssl_certificate, Apache SSLCertificateFile (2.4.8+), Traefik, Caddy, or any server that takes the key as a separate file. Safe to share."
        case .certOnly:
            return "Just the leaf certificate, re-armored as PEM. Use when the server supplies the chain itself or for inspection and pinning."
        }
    }
}

// MARK: - Export

public struct ExportResult: Sendable {
    public let pem: String
    public let warnings: [String]
    public let containsPrivateKey: Bool
    public var data: Data { Data(pem.utf8) }
}

/// Builds the output PEM. Unlike a plain concatenation this *refuses* to produce a file that
/// wouldn't work: a missing or mismatched key, an unparseable certificate, or a locked key.
public enum PEMExporter {
    public static func export(key: [PEM.Block], certificate: [PEM.Block], ca: [PEM.Block],
                              passphrase: String = "", order: PEMOrder) throws -> ExportResult {
        var warnings: [String] = []

        // Leaf certificate: exactly the first CERTIFICATE block in the certificate slot.
        let certBlocks = certificate.filter(\.isCertificate)
        guard let leaf = certBlocks.first else {
            throw PEMError("Import a server certificate first.")
        }
        guard !leaf.der.isEmpty, SecCertificateCreateWithData(nil, leaf.der as CFData) != nil else {
            throw PEMError("The certificate could not be parsed, so nothing was exported.")
        }
        if certBlocks.count > 1 {
            warnings.append("The certificate file contains \(certBlocks.count) certificates; the first is used as the leaf and the rest are treated as chain.")
        }

        // Chain: everything after the leaf in the certificate file, plus the CA bundle, de-duplicated.
        var chainBlocks: [PEM.Block] = []
        if order.includesCA {
            var seen: Set<Data> = [leaf.der]
            let candidates = Array(certBlocks.dropFirst()) + ca.filter(\.isCertificate)
            for b in candidates where seen.insert(b.der).inserted {
                chainBlocks.append(b)
            }
            let dropped = candidates.count - chainBlocks.count
            if dropped > 0 {
                warnings.append("Removed \(dropped) duplicate certificate\(dropped == 1 ? "" : "s") from the chain.")
            }
            if chainBlocks.isEmpty {
                warnings.append("No CA bundle loaded; the output has no chain.")
            }
        }

        // Key: required, must load, must match.
        var keyBlock: PEM.Block?
        if order.includesKey {
            guard let k = key.first(where: \.isPrivateKey) else {
                throw PEMError("This format requires a private key. Drop the key, or choose a key-free format.")
            }
            let cert = SecCertificateCreateWithData(nil, leaf.der as CFData)
            let info = PrivateKeyInspector.inspect(blocks: [k], passphrase: passphrase, certificate: cert)
            if info.needsPassphrase {
                throw PEMError("The private key is encrypted. Enter its passphrase so it can be verified.")
            }
            if let err = info.loadError { throw err }
            switch info.match {
            case .mismatch:
                throw PEMError("The private key does not match this certificate. Choose the key used to request this certificate.")
            case .unknown:
                throw PEMError(info.note)
            case .matches:
                break
            }
            keyBlock = k     // exported exactly as supplied — an encrypted key stays encrypted
        }

        let keyText = keyBlock.map { [$0.armored] } ?? []
        let certText = [leaf.armored]
        let caText = chainBlocks.map(\.armored)

        let parts: [[String]]
        switch order {
        case .keyCertCA: parts = [keyText, certText, caText]
        case .certCAKey: parts = [certText, caText, keyText]
        case .certKeyCA: parts = [certText, keyText, caText]
        case .certCA:    parts = [certText, caText]
        case .certOnly:  parts = [certText]
        }
        let pem = parts.flatMap { $0 }.joined(separator: "\n") + "\n"
        return ExportResult(pem: pem, warnings: warnings, containsPrivateKey: keyBlock != nil)
    }
}

// MARK: - Atomic, permission-safe file writing

public enum PEMWriter {
    /// Write `data` to `destination` atomically. The file is created with `0600` when it holds a
    /// private key (`0644` otherwise) from the moment it exists, then swapped into place, so a
    /// symlink at the destination is replaced rather than followed and a failed write never leaves
    /// a half-written file behind.
    ///
    /// Works inside the App Sandbox, where a save panel grants access to the chosen URL only:
    /// the staging file lives in the system's item-replacement directory for that volume, not
    /// beside the destination.
    public static func save(_ data: Data, to destination: URL, containsPrivateKey: Bool) throws {
        let mode: mode_t = containsPrivateKey ? 0o600 : 0o644
        let fm = FileManager.default

        let stagingDir: URL
        do {
            stagingDir = try fm.url(for: .itemReplacementDirectory, in: .userDomainMask,
                                    appropriateFor: destination, create: true)
        } catch {
            throw PEMError("Could not prepare a temporary file for saving: \(error.localizedDescription)")
        }
        let staging = stagingDir.appendingPathComponent("ssl2pem-\(UUID().uuidString).pem")
        defer { try? fm.removeItem(at: staging); try? fm.removeItem(at: stagingDir) }

        let fd = Darwin.open(staging.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        guard fd >= 0 else { throw PEMError("Could not create a temporary file for saving.") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            throw PEMError("Could not write the PEM file: \(error.localizedDescription)")
        }
        // The umask may have narrowed the mode; make it exactly what we asked for.
        chmod(staging.path, mode)

        // Never follow a symlink at the destination: replace the link itself.
        if let attrs = try? fm.attributesOfItem(atPath: destination.path),
           attrs[.type] as? FileAttributeType == .typeSymbolicLink {
            try? fm.removeItem(at: destination)
        }

        if fm.fileExists(atPath: destination.path) {
            do {
                _ = try fm.replaceItemAt(destination, withItemAt: staging, backupItemName: nil,
                                         options: .usingNewMetadataOnly)
            } catch {
                throw PEMError("Could not replace the existing file: \(error.localizedDescription)")
            }
        } else {
            do {
                try fm.moveItem(at: staging, to: destination)
            } catch {
                throw PEMError("Could not save the PEM file. Check the folder's permissions.")
            }
        }
        // replaceItemAt keeps the staged file's mode, but be explicit.
        chmod(destination.path, mode)
    }
}
