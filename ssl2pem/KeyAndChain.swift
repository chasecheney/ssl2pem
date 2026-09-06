import Foundation
import Security

// MARK: - Tiny ASN.1 DER reader (just enough to unwrap PKCS#8 / SEC1 keys)

struct ASN1 {
    struct TLV {
        let tag: UInt8
        let content: Data
        let range: Range<Int>   // range of the whole TLV inside the parent buffer
    }

    /// Parse a sequence of TLVs from `data` (the content of a constructed element).
    static func elements(in data: Data) -> [TLV] {
        var out: [TLV] = []
        var idx = 0
        let bytes = [UInt8](data)
        while idx < bytes.count {
            let start = idx
            let tag = bytes[idx]; idx += 1
            guard idx < bytes.count else { break }
            var length = Int(bytes[idx]); idx += 1
            if length & 0x80 != 0 {
                let n = length & 0x7F
                guard n > 0, n <= 4, idx + n <= bytes.count else { break }
                length = 0
                for _ in 0..<n { length = (length << 8) | Int(bytes[idx]); idx += 1 }
            }
            guard idx + length <= bytes.count else { break }
            let content = Data(bytes[idx..<(idx + length)])
            idx += length
            out.append(TLV(tag: tag, content: content, range: start..<idx))
        }
        return out
    }

    static func oidString(_ content: Data) -> String {
        let b = [UInt8](content)
        guard let first = b.first else { return "" }
        var parts = [String(Int(first) / 40), String(Int(first) % 40)]
        var value = 0
        for byte in b.dropFirst() {
            value = (value << 7) | Int(byte & 0x7F)
            if byte & 0x80 == 0 { parts.append(String(value)); value = 0 }
        }
        return parts.joined(separator: ".")
    }
}

// MARK: - Private key inspection

struct PrivateKeyInfo {
    enum Match { case matches, mismatch, unknown }

    let typeDescription: String
    let match: Match
    let note: String
}

enum PrivateKeyInspector {
    private static let rsaOID = "1.2.840.113549.1.1.1"
    private static let ecOID  = "1.2.840.10045.2.1"

    static func inspect(blocks: [PEM.Block], certificate: SecCertificate?) -> PrivateKeyInfo {
        guard let block = blocks.first(where: { PEM.isPrivateKeyType($0.type) }) else {
            return PrivateKeyInfo(typeDescription: "No private key found", match: .unknown,
                                  note: "The file does not contain a PRIVATE KEY block.")
        }
        if block.type == "ENCRYPTED PRIVATE KEY" || block.armored.contains("Proc-Type: 4,ENCRYPTED") {
            return PrivateKeyInfo(typeDescription: "Encrypted private key", match: .unknown,
                                  note: "The key is passphrase-protected; it will be copied as-is and cannot be checked against the certificate.")
        }

        var key: SecKey?
        var typeDescription = block.type.capitalized
        var note = ""

        switch block.type {
        case "RSA PRIVATE KEY":
            key = makeKey(block.der, type: kSecAttrKeyTypeRSA)
            typeDescription = "RSA"
        case "EC PRIVATE KEY":
            if let x963 = ecPrivateToX963(block.der) {
                key = makeKey(x963, type: kSecAttrKeyTypeECSECPrimeRandom)
            }
            typeDescription = "ECDSA"
        case "PRIVATE KEY":
            // PKCS#8: SEQUENCE { INTEGER, SEQUENCE { OID, params }, OCTET STRING }
            if let outer = ASN1.elements(in: block.der).first, outer.tag == 0x30 {
                let parts = ASN1.elements(in: outer.content)
                if parts.count >= 3, parts[1].tag == 0x30, parts[2].tag == 0x04,
                   let oidTLV = ASN1.elements(in: parts[1].content).first, oidTLV.tag == 0x06 {
                    let oid = ASN1.oidString(oidTLV.content)
                    if oid == rsaOID {
                        typeDescription = "RSA"
                        key = makeKey(parts[2].content, type: kSecAttrKeyTypeRSA)
                    } else if oid == ecOID {
                        typeDescription = "ECDSA"
                        if let x963 = ecPrivateToX963(parts[2].content) {
                            key = makeKey(x963, type: kSecAttrKeyTypeECSECPrimeRandom)
                        }
                    } else {
                        typeDescription = OIDNames.name(for: oid) ?? "Private key (\(oid))"
                        note = "Key type not supported for verification."
                    }
                }
            }
        default:
            note = "Unrecognized key format."
        }

        guard let key else {
            return PrivateKeyInfo(typeDescription: typeDescription, match: .unknown,
                                  note: note.isEmpty ? "The key could not be loaded for verification; it will still be included in the output." : note)
        }

        if let attrs = SecKeyCopyAttributes(key) as? [String: Any],
           let bits = attrs[kSecAttrKeySizeInBits as String] as? Int {
            typeDescription += " \(bits)-bit"
        }

        guard let certificate,
              let certKey = SecCertificateCopyKey(certificate),
              let certPub = SecKeyCopyExternalRepresentation(certKey, nil) as Data?,
              let pub = SecKeyCopyPublicKey(key),
              let keyPub = SecKeyCopyExternalRepresentation(pub, nil) as Data? else {
            return PrivateKeyInfo(typeDescription: typeDescription, match: .unknown,
                                  note: "Drop a certificate to verify that the key matches it.")
        }

        if certPub == keyPub {
            return PrivateKeyInfo(typeDescription: typeDescription, match: .matches,
                                  note: "Private key matches the certificate's public key.")
        }
        return PrivateKeyInfo(typeDescription: typeDescription, match: .mismatch,
                              note: "Private key does NOT match the certificate. The resulting .pem will not work.")
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
        // [1] publicKey is context-specific constructed tag 0xA1 containing a BIT STRING
        guard let pubWrapper = parts.first(where: { $0.tag == 0xA1 }),
              let bitString = ASN1.elements(in: pubWrapper.content).first, bitString.tag == 0x03,
              bitString.content.count > 1 else { return nil }
        let point = bitString.content.dropFirst() // drop "unused bits" byte
        guard point.first == 0x04 else { return nil }
        return Data(point) + d
    }
}

// MARK: - Chain verification

struct ChainInfo {
    enum Status { case valid, privateRoot, invalid, unknown }
    let status: Status
    let summary: String
    let chain: [String]        // subject summaries, leaf first
    let bundleCount: Int
}

enum ChainVerifier {
    static func verify(leaf: SecCertificate?, bundle: [SecCertificate]) -> ChainInfo {
        guard let leaf else {
            let names = bundle.compactMap { SecCertificateCopySubjectSummary($0) as String? }
            return ChainInfo(status: .unknown,
                             summary: bundle.isEmpty ? "No CA bundle loaded." : "Drop a certificate to verify the chain.",
                             chain: names, bundleCount: bundle.count)
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let certs = [leaf] + bundle
        let status = SecTrustCreateWithCertificates(certs as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust else {
            return ChainInfo(status: .unknown, summary: "Could not create trust evaluation.", chain: [], bundleCount: bundle.count)
        }
        // Ignore validity dates for the *structural* chain check; expiry is reported separately.
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

        // Second pass: treat self-signed certificates in the bundle as anchors. If that succeeds the
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

    private static func isSelfSigned(_ cert: SecCertificate) -> Bool {
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

// MARK: - PEM assembly

enum PEMOrder: String, CaseIterable, Identifiable {
    case keyCertCA
    case certCAKey
    case certKeyCA
    case certCA
    case certOnly

    var id: String { rawValue }

    var title: String {
        switch self {
        case .keyCertCA: return "Key → Certificate → CA bundle"
        case .certCAKey: return "Certificate → CA bundle → Key"
        case .certKeyCA: return "Certificate → Key → CA bundle"
        case .certCA:    return "Certificate → CA bundle (no key)"
        case .certOnly:  return "Certificate only"
        }
    }

    var includesKey: Bool {
        switch self {
        case .keyCertCA, .certCAKey, .certKeyCA: return true
        case .certCA, .certOnly: return false
        }
    }

    var includesCA: Bool { self != .certOnly }

    var compatibility: String {
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

enum PEMBuilder {
    struct Warning: Identifiable { let id = UUID(); let text: String }

    static func build(key: [PEM.Block], cert: [PEM.Block], ca: [PEM.Block], order: PEMOrder) -> (pem: String, warnings: [Warning]) {
        var warnings: [Warning] = []

        let keyBlocks = key.filter { PEM.isPrivateKeyType($0.type) }
        let certBlocks = cert.filter { $0.type == "CERTIFICATE" }
        let caBlocks = ca.filter { $0.type == "CERTIFICATE" }

        if order.includesKey && keyBlocks.isEmpty {
            warnings.append(Warning(text: "No private key block available; output omits the key."))
        }
        if certBlocks.isEmpty {
            warnings.append(Warning(text: "No certificate block available."))
        }
        if order.includesCA && caBlocks.isEmpty {
            warnings.append(Warning(text: "No CA bundle certificates available; output has no chain."))
        }
        if certBlocks.count > 1 {
            warnings.append(Warning(text: "The certificate file contains \(certBlocks.count) certificates; all are included (leaf should be first)."))
        }
        // De-duplicate: a CA bundle sometimes repeats the leaf.
        let leafDERs = Set(certBlocks.map(\.der))
        let dedupedCA = caBlocks.filter { !leafDERs.contains($0.der) }
        if dedupedCA.count != caBlocks.count {
            warnings.append(Warning(text: "Removed a duplicate of the leaf certificate from the CA bundle."))
        }

        let keyText = keyBlocks.map(\.armored)
        let certText = certBlocks.map(\.armored)
        let caText = dedupedCA.map(\.armored)

        let parts: [[String]]
        switch order {
        case .keyCertCA: parts = [keyText, certText, caText]
        case .certCAKey: parts = [certText, caText, keyText]
        case .certKeyCA: parts = [certText, keyText, caText]
        case .certCA:    parts = [certText, caText]
        case .certOnly:  parts = [certText]
        }

        let pem = parts.flatMap { $0 }.joined(separator: "\n") + "\n"
        return (pem, warnings)
    }
}
