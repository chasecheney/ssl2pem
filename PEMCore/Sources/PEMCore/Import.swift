import Foundation
import Security

/// What a file is used for.
public enum PEMRole: String, CaseIterable, Identifiable, Sendable {
    case key, certificate, chain

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .key:         return "Private Key"
        case .certificate: return "Certificate"
        case .chain:       return "CA Bundle"
        }
    }

    public var hint: String {
        switch self {
        case .key:         return "private.key"
        case .certificate: return "certificate.crt"
        case .chain:       return "ca_bundle.crt"
        }
    }
}

/// A file that has been read, parsed into PEM blocks and assigned a role.
public struct ImportedFile: Sendable, Hashable {
    public let url: URL
    public let role: PEMRole
    public let blocks: [PEM.Block]
    /// Non-fatal observation about the file (e.g. a multi-certificate file dropped in the certificate slot).
    public let warning: String?

    public var name: String { url.lastPathComponent }
    public var certificateCount: Int { blocks.filter(\.isCertificate).count }
    public var privateKeyCount: Int { blocks.filter(\.isPrivateKey).count }
    public var isEncryptedKey: Bool { blocks.contains(where: \.isEncryptedPrivateKey) }

    public init(url: URL, role: PEMRole, blocks: [PEM.Block], warning: String? = nil) {
        self.url = url; self.role = role; self.blocks = blocks; self.warning = warning
    }

    /// Merge another CA-bundle file into this one (used when several chain files are dropped together).
    public func merging(_ other: ImportedFile) -> ImportedFile {
        var seen = Set(blocks.map(\.der))
        let extra = other.blocks.filter { seen.insert($0.der).inserted }
        let mergedURL = url.deletingLastPathComponent().appendingPathComponent("\(name) + \(other.name)")
        return ImportedFile(url: mergedURL, role: role, blocks: blocks + extra, warning: warning ?? other.warning)
    }
}

public enum PEMImporter {
    /// Files larger than this are refused; certificate material is tiny and this bounds memory use.
    public static let maximumInputSize = 5 * 1024 * 1024

    /// Read and classify a file. Pass `role` to force a slot (validated against the contents),
    /// or `nil` to detect it from the contents (and, as a tiebreak, the file name).
    public static func read(_ url: URL, as role: PEMRole? = nil) throws -> ImportedFile {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue else {
            throw PEMError("“\(url.lastPathComponent)” is not a file.")
        }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= maximumInputSize else {
            throw PEMError("“\(url.lastPathComponent)” is larger than \(maximumInputSize / 1024 / 1024) MB, which is far bigger than any certificate file. Check that you picked the right file.")
        }
        let data: Data
        do { data = try Data(contentsOf: url) } catch {
            throw PEMError("Couldn't read “\(url.lastPathComponent)”: \(error.localizedDescription)")
        }
        return try parse(data, name: url.lastPathComponent, url: url, as: role)
    }

    /// Parse in-memory data (exposed for tests).
    public static func parse(_ data: Data, name: String, url: URL, as role: PEMRole? = nil) throws -> ImportedFile {
        var blocks = PEM.blocks(in: data)
        if blocks.isEmpty {
            // Maybe a raw DER certificate (.cer / .der)
            if !data.isEmpty, SecCertificateCreateWithData(nil, data as CFData) != nil {
                blocks = [PEM.Block(type: "CERTIFICATE", armored: PEM.armor(data, type: "CERTIFICATE"), der: data)]
            } else {
                throw PEMError("“\(name)” doesn't contain any PEM blocks or a DER certificate.")
            }
        }
        // Every certificate block must actually parse.
        for b in blocks where b.isCertificate {
            guard !b.der.isEmpty, SecCertificateCreateWithData(nil, b.der as CFData) != nil else {
                throw PEMError("“\(name)” contains a CERTIFICATE block that could not be parsed.")
            }
        }

        let certs = blocks.filter(\.isCertificate).count
        let keys = blocks.filter(\.isPrivateKey).count
        var detected = classify(certificates: certs, keys: keys, name: name)
        if keys == 0, certs == 1, detected == .certificate,
           let only = blocks.first(where: \.isCertificate), isCertificateAuthority(only.der) {
            detected = .chain
        }

        guard let role else {
            if keys > 0 && certs > 0 {
                throw PEMError("“\(name)” contains both a private key and certificates. Drop it into a specific slot to say which part you want.")
            }
            if keys > 1 {
                throw PEMError("“\(name)” contains \(keys) private keys; only one is expected.")
            }
            return ImportedFile(url: url, role: detected, blocks: blocks)
        }

        // Explicit slot: validate the contents fit it.
        var warning: String?
        switch role {
        case .key:
            guard keys > 0 else { throw PEMError("“\(name)” has no private key block. Drop it into the Certificate or CA Bundle slot instead.") }
            if keys > 1 { throw PEMError("“\(name)” contains \(keys) private keys; only one is expected.") }
            if certs > 0 { warning = "Also contains \(certs) certificate\(certs == 1 ? "" : "s"), which will be ignored." }
        case .certificate:
            guard certs > 0 else { throw PEMError("“\(name)” has no certificate. Drop it into the Private Key slot instead.") }
            if keys > 0 { warning = "Also contains a private key, which is ignored here. Drop it into the Private Key slot to use it." }
            else if certs > 1 { warning = "Contains \(certs) certificates; the first is the leaf, the rest are treated as chain." }
        case .chain:
            guard certs > 0 else { throw PEMError("“\(name)” has no certificates. Drop it into the Private Key slot instead.") }
            if keys > 0 { warning = "Also contains a private key, which is ignored here." }
            else if certs == 1 && detected == .certificate {
                warning = "Only one certificate — make sure this is the CA/intermediate, not the server certificate."
            }
        }
        return ImportedFile(url: url, role: role, blocks: blocks, warning: warning)
    }

    /// True when the certificate's Basic Constraints extension says CA:TRUE.
    public static func isCertificateAuthority(_ der: Data) -> Bool {
        guard let cert = SecCertificateCreateWithData(nil, der as CFData),
              let values = SecCertificateCopyValues(cert, [kSecOIDBasicConstraints] as CFArray, nil) as? [String: [String: Any]],
              let items = values[kSecOIDBasicConstraints as String]?[kSecPropertyKeyValue as String] as? [[String: Any]] else {
            return false
        }
        for item in items {
            let label = (item[kSecPropertyKeyLabel as String] as? String ?? "").lowercased()
            if label.contains("certificate authority") {
                if let v = item[kSecPropertyKeyValue as String] as? String {
                    return ["yes", "true", "1"].contains(v.lowercased())
                }
                if let n = item[kSecPropertyKeyValue as String] as? NSNumber { return n.boolValue }
            }
        }
        return false
    }

    static func classify(certificates: Int, keys: Int, name: String) -> PEMRole {
        if keys > 0 { return .key }
        if certificates > 1 { return .chain }
        let lower = name.lowercased()
        if lower.contains("fullchain") { return .certificate }
        let caHints = ["ca_bundle", "ca-bundle", "cabundle", "bundle", "chain", "intermediate", "root", "ca.", "ca_", "ca-"]
        if caHints.contains(where: { lower.contains($0) }) { return .chain }
        return .certificate
    }
}
