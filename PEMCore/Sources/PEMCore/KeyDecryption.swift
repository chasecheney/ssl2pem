import Foundation
import CommonCrypto

// MARK: - Tiny ASN.1 DER reader (enough to unwrap PKCS#8 / SEC1 / PBES2 structures)

public struct ASN1 {
    public struct TLV {
        public let tag: UInt8
        public let content: Data
    }

    /// Parse a sequence of TLVs from `data` (the content of a constructed element).
    public static func elements(in data: Data) -> [TLV] {
        var out: [TLV] = []
        var idx = 0
        let bytes = [UInt8](data)
        while idx < bytes.count {
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
            out.append(TLV(tag: tag, content: Data(bytes[idx..<(idx + length)])))
            idx += length
        }
        return out
    }

    public static func oidString(_ content: Data) -> String {
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

    static func integer(_ content: Data) -> Int {
        content.reduce(0) { ($0 << 8) | Int($1) }
    }
}

// MARK: - Private key decryption (in-process, no OpenSSL)

/// Decrypts passphrase-protected private keys so they can be checked against a certificate.
/// Supports PKCS#8 `ENCRYPTED PRIVATE KEY` using PBES2 (PBKDF2 with SHA-1/224/256/384/512 and
/// AES-128/192/256-CBC or 3DES-CBC — everything modern OpenSSL/LibreSSL emits) and the legacy
/// OpenSSL `Proc-Type: 4,ENCRYPTED` / `DEK-Info:` format.
public enum KeyDecryption {
    public struct Decrypted {
        /// PEM block type of the plaintext key: "PRIVATE KEY", "RSA PRIVATE KEY" or "EC PRIVATE KEY".
        public let type: String
        public let der: Data
    }

    static let pbes2OID   = "1.2.840.113549.1.5.13"
    static let pbkdf2OID  = "1.2.840.113549.1.5.12"
    static let hmacSHA1   = "1.2.840.113549.2.7"
    static let hmacSHA224 = "1.2.840.113549.2.8"
    static let hmacSHA256 = "1.2.840.113549.2.9"
    static let hmacSHA384 = "1.2.840.113549.2.10"
    static let hmacSHA512 = "1.2.840.113549.2.11"
    static let aes128CBC  = "2.16.840.1.101.3.4.1.2"
    static let aes192CBC  = "2.16.840.1.101.3.4.1.22"
    static let aes256CBC  = "2.16.840.1.101.3.4.1.42"
    static let desEDE3CBC = "1.2.840.113549.3.7"

    public static func decrypt(_ block: PEM.Block, passphrase: String) throws -> Decrypted {
        guard !passphrase.contains("\n"), !passphrase.contains("\r") else {
            throw PEMError("The key passphrase cannot contain a line break.")
        }
        if block.type == "ENCRYPTED PRIVATE KEY" {
            return Decrypted(type: "PRIVATE KEY", der: try decryptPKCS8(block.der, passphrase: passphrase))
        }
        if block.headers["Proc-Type"]?.contains("ENCRYPTED") == true, let dek = block.headers["DEK-Info"] {
            return Decrypted(type: block.type, der: try decryptLegacy(block.der, dekInfo: dek, passphrase: passphrase))
        }
        throw PEMError("This private key is not encrypted.")
    }

    // MARK: PKCS#8 / PBES2

    private static func decryptPKCS8(_ der: Data, passphrase: String) throws -> Data {
        guard let outer = ASN1.elements(in: der).first, outer.tag == 0x30 else { throw badFormat }
        let parts = ASN1.elements(in: outer.content)
        guard parts.count == 2, parts[0].tag == 0x30, parts[1].tag == 0x04 else { throw badFormat }
        let alg = ASN1.elements(in: parts[0].content)
        guard alg.count == 2, alg[0].tag == 0x06, ASN1.oidString(alg[0].content) == pbes2OID, alg[1].tag == 0x30 else {
            throw PEMError("This key uses an encryption scheme that isn't supported (only PBES2 is). Re-encrypt it with `openssl pkcs8 -topk8 -v2 aes-256-cbc`.")
        }
        let pbes2 = ASN1.elements(in: alg[1].content)
        guard pbes2.count == 2, pbes2[0].tag == 0x30, pbes2[1].tag == 0x30 else { throw badFormat }

        // keyDerivationFunc
        let kdf = ASN1.elements(in: pbes2[0].content)
        guard kdf.count == 2, kdf[0].tag == 0x06, ASN1.oidString(kdf[0].content) == pbkdf2OID, kdf[1].tag == 0x30 else {
            throw PEMError("This key uses a key-derivation function that isn't supported (only PBKDF2 is).")
        }
        let kdfParams = ASN1.elements(in: kdf[1].content)
        guard kdfParams.count >= 2, kdfParams[0].tag == 0x04, kdfParams[1].tag == 0x02 else { throw badFormat }
        let salt = kdfParams[0].content
        let iterations = ASN1.integer(kdfParams[1].content)
        var prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        var explicitKeyLength: Int?
        for p in kdfParams.dropFirst(2) {
            if p.tag == 0x02 { explicitKeyLength = ASN1.integer(p.content) }
            if p.tag == 0x30, let oid = ASN1.elements(in: p.content).first, oid.tag == 0x06 {
                switch ASN1.oidString(oid.content) {
                case hmacSHA1:   prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
                case hmacSHA224: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
                case hmacSHA256: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
                case hmacSHA384: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
                case hmacSHA512: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
                default: throw PEMError("This key uses a PBKDF2 hash that isn't supported.")
                }
            }
        }

        // encryptionScheme
        let enc = ASN1.elements(in: pbes2[1].content)
        guard enc.count == 2, enc[0].tag == 0x06, enc[1].tag == 0x04 else { throw badFormat }
        let (algorithm, keyLength) = try cipher(for: ASN1.oidString(enc[0].content))
        let iv = enc[1].content
        let key = try pbkdf2(passphrase: passphrase, salt: salt, iterations: iterations,
                             prf: prf, length: explicitKeyLength ?? keyLength)
        let plaintext = try cbcDecrypt(parts[1].content, key: key, iv: iv, algorithm: algorithm)

        // A wrong passphrase normally fails padding; when it doesn't, the result isn't valid ASN.1.
        guard let inner = ASN1.elements(in: plaintext).first, inner.tag == 0x30,
              ASN1.elements(in: inner.content).first?.tag == 0x02 else {
            throw wrongPassphrase
        }
        return plaintext
    }

    // MARK: Legacy OpenSSL PEM encryption (EVP_BytesToKey with MD5, one iteration)

    private static func decryptLegacy(_ der: Data, dekInfo: String, passphrase: String) throws -> Data {
        let comps = dekInfo.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard comps.count == 2, let iv = Data(hex: comps[1]) else { throw badFormat }
        let (algorithm, keyLength): (CCAlgorithm, Int)
        switch comps[0].uppercased() {
        case "AES-128-CBC": (algorithm, keyLength) = (CCAlgorithm(kCCAlgorithmAES), 16)
        case "AES-192-CBC": (algorithm, keyLength) = (CCAlgorithm(kCCAlgorithmAES), 24)
        case "AES-256-CBC": (algorithm, keyLength) = (CCAlgorithm(kCCAlgorithmAES), 32)
        case "DES-EDE3-CBC": (algorithm, keyLength) = (CCAlgorithm(kCCAlgorithm3DES), 24)
        default: throw PEMError("This key uses the \(comps[0]) cipher, which isn't supported.")
        }
        // EVP_BytesToKey: D_i = MD5(D_{i-1} || password || salt[0..<8])
        let salt = iv.prefix(8)
        var key = Data()
        var previous = Data()
        while key.count < keyLength {
            var ctx = CC_MD5_CTX()
            CC_MD5_Init(&ctx)
            previous.withUnsafeBytes { _ = CC_MD5_Update(&ctx, $0.baseAddress, CC_LONG($0.count)) }
            Array(passphrase.utf8).withUnsafeBytes { _ = CC_MD5_Update(&ctx, $0.baseAddress, CC_LONG($0.count)) }
            salt.withUnsafeBytes { _ = CC_MD5_Update(&ctx, $0.baseAddress, CC_LONG($0.count)) }
            var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
            CC_MD5_Final(&digest, &ctx)
            previous = Data(digest)
            key.append(previous)
        }
        let plaintext = try cbcDecrypt(der, key: key.prefix(keyLength), iv: iv, algorithm: algorithm)
        guard let inner = ASN1.elements(in: plaintext).first, inner.tag == 0x30 else { throw wrongPassphrase }
        return plaintext
    }

    // MARK: CommonCrypto helpers

    private static func cipher(for oid: String) throws -> (CCAlgorithm, Int) {
        switch oid {
        case aes128CBC:  return (CCAlgorithm(kCCAlgorithmAES), 16)
        case aes192CBC:  return (CCAlgorithm(kCCAlgorithmAES), 24)
        case aes256CBC:  return (CCAlgorithm(kCCAlgorithmAES), 32)
        case desEDE3CBC: return (CCAlgorithm(kCCAlgorithm3DES), 24)
        default: throw PEMError("This key uses a cipher that isn't supported (\(oid)).")
        }
    }

    private static func pbkdf2(passphrase: String, salt: Data, iterations: Int,
                               prf: CCPseudoRandomAlgorithm, length: Int) throws -> Data {
        var derived = [UInt8](repeating: 0, count: length)
        let pw = Array(passphrase.utf8)
        let status = salt.withUnsafeBytes { saltPtr in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                 pw.map { CChar(bitPattern: $0) }, pw.count,
                                 saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                                 prf, UInt32(max(iterations, 1)),
                                 &derived, length)
        }
        guard status == kCCSuccess else { throw PEMError("Key derivation failed.") }
        return Data(derived)
    }

    private static func cbcDecrypt(_ ciphertext: Data, key: Data, iv: Data, algorithm: CCAlgorithm) throws -> Data {
        var out = [UInt8](repeating: 0, count: ciphertext.count + kCCBlockSizeAES128)
        var moved = 0
        let status = key.withUnsafeBytes { k in
            iv.withUnsafeBytes { v in
                ciphertext.withUnsafeBytes { c in
                    CCCrypt(CCOperation(kCCDecrypt), algorithm, CCOptions(kCCOptionPKCS7Padding),
                            k.baseAddress, key.count, v.baseAddress,
                            c.baseAddress, ciphertext.count,
                            &out, out.count, &moved)
                }
            }
        }
        guard status == kCCSuccess else { throw wrongPassphrase }
        return Data(out.prefix(moved))
    }

    private static var badFormat: PEMError { PEMError("The encrypted private key could not be parsed.") }
    private static var wrongPassphrase: PEMError { PEMError("Could not unlock the private key. Check its passphrase and try again.") }
}

extension Data {
    init?(hex: String) {
        let chars = Array(hex)
        guard chars.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(chars[i...i+1]), radix: 16) else { return nil }
            bytes.append(b)
            i += 2
        }
        self.init(bytes)
    }
}
