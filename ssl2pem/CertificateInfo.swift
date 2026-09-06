import Foundation
import Security
import CryptoKit

struct CertField: Identifiable, Hashable {
    let id = UUID()
    let section: String
    let label: String
    let value: String
}

/// Everything we know about an X.509 certificate, parsed with the Security framework.
struct CertificateInfo {
    let certificate: SecCertificate
    let der: Data

    let commonName: String
    let subject: String
    let subjectAltNames: [String]
    let issuer: String
    let issuerFull: String
    let notBefore: Date?
    let notAfter: Date?
    let serial: String
    let signatureAlgorithm: String
    let keyDescription: String
    let sha256Fingerprint: String
    let sha1Fingerprint: String
    let isSelfSigned: Bool
    let allFields: [CertField]

    var isExpired: Bool {
        guard let notAfter else { return false }
        return notAfter < Date()
    }

    var isNotYetValid: Bool {
        guard let notBefore else { return false }
        return notBefore > Date()
    }

    var daysRemaining: Int? {
        guard let notAfter else { return nil }
        return Calendar.current.dateComponents([.day], from: Date(), to: notAfter).day
    }

    /// Domains covered by this certificate (CN + SANs, de-duplicated, CN first).
    var coveredNames: [String] {
        var seen = Set<String>()
        var out: [String] = []
        for n in [commonName] + subjectAltNames where !n.isEmpty && !seen.contains(n) {
            seen.insert(n)
            out.append(n)
        }
        return out
    }

    /// Suggested output file name, e.g. `example.com.pem`.
    var suggestedFileName: String {
        var base = commonName.isEmpty ? (subjectAltNames.first ?? "certificate") : commonName
        if base.hasPrefix("*.") { base = "wildcard." + base.dropFirst(2) }
        base = base.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: " ", with: "_")
        return base + ".pem"
    }

    // MARK: - Parsing

    enum ParseError: LocalizedError {
        case noCertificate
        case invalidDER
        case noValues

        var errorDescription: String? {
            switch self {
            case .noCertificate: return "No certificate block found in the file."
            case .invalidDER:    return "The certificate data could not be parsed."
            case .noValues:      return "The certificate contents could not be read."
            }
        }
    }

    static func parse(der: Data) throws -> CertificateInfo {
        guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
            throw ParseError.invalidDER
        }
        return try parse(certificate: cert, der: der)
    }

    static func parse(certificate cert: SecCertificate, der: Data) throws -> CertificateInfo {
        guard let raw = SecCertificateCopyValues(cert, nil, nil) as? [String: [String: Any]] else {
            throw ParseError.noValues
        }

        func entry(_ oid: CFString) -> [String: Any]? { raw[oid as String] }

        // Subject / issuer
        let subjectParts = nameComponents(entry(kSecOIDX509V1SubjectName)?[kSecPropertyKeyValue as String])
        let issuerParts  = nameComponents(entry(kSecOIDX509V1IssuerName)?[kSecPropertyKeyValue as String])

        var cn = subjectParts.first(where: { $0.0 == "CN" })?.1 ?? ""
        if cn.isEmpty, let summary = SecCertificateCopySubjectSummary(cert) as String? {
            cn = summary
        }
        let issuerCN = issuerParts.first(where: { $0.0 == "CN" })?.1
        let issuerO  = issuerParts.first(where: { $0.0 == "O" })?.1
        let issuer: String = {
            switch (issuerCN, issuerO) {
            case let (cn?, o?) where cn != o: return "\(cn) (\(o))"
            case let (cn?, _): return cn
            case let (nil, o?): return o
            default: return "Unknown"
            }
        }()

        // SANs
        var sans: [String] = []
        if let sanValue = entry(kSecOIDSubjectAltName)?[kSecPropertyKeyValue as String] as? [[String: Any]] {
            for item in sanValue {
                if let v = item[kSecPropertyKeyValue as String] as? String {
                    sans.append(v)
                }
            }
        }

        // Validity
        let notBefore = dateValue(entry(kSecOIDX509V1ValidityNotBefore))
        let notAfter  = dateValue(entry(kSecOIDX509V1ValidityNotAfter))

        // Serial
        var serial = ""
        if let serialData = entry(kSecOIDX509V1SerialNumber)?[kSecPropertyKeyValue as String] as? Data {
            serial = serialData.colonHexString
        } else if let s = entry(kSecOIDX509V1SerialNumber)?[kSecPropertyKeyValue as String] as? String {
            serial = s
        }

        // Signature algorithm
        var sigAlg = "Unknown"
        if let sig = entry(kSecOIDX509V1SignatureAlgorithm)?[kSecPropertyKeyValue as String] as? [[String: Any]] {
            for item in sig {
                if let v = item[kSecPropertyKeyValue as String] as? String, let name = OIDNames.name(for: v) {
                    sigAlg = name
                    break
                } else if let v = item[kSecPropertyKeyValue as String] as? String, v.contains(".") {
                    sigAlg = v
                }
            }
        } else if let s = entry(kSecOIDX509V1SignatureAlgorithm)?[kSecPropertyKeyValue as String] as? String {
            sigAlg = OIDNames.name(for: s) ?? s
        }

        // Public key
        var keyDescription = "Unknown"
        if let key = SecCertificateCopyKey(cert),
           let attrs = SecKeyCopyAttributes(key) as? [String: Any] {
            let type = attrs[kSecAttrKeyType as String] as? String ?? ""
            let bits = attrs[kSecAttrKeySizeInBits as String] as? Int ?? 0
            let typeName: String
            if type == (kSecAttrKeyTypeRSA as String) {
                typeName = "RSA"
            } else if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
                typeName = "ECDSA"
            } else {
                typeName = type
            }
            keyDescription = bits > 0 ? "\(typeName) \(bits)-bit" : typeName
        }

        // Fingerprints
        let sha256 = Data(SHA256.hash(data: der)).colonHexString
        let sha1   = Data(Insecure.SHA1.hash(data: der)).colonHexString

        let subjectString = subjectParts.map { "\($0.0)=\($0.1)" }.joined(separator: ", ")
        let issuerString  = issuerParts.map { "\($0.0)=\($0.1)" }.joined(separator: ", ")
        let selfSigned = !subjectString.isEmpty && subjectString == issuerString

        // Everything, flattened, for the expanded view.
        var fields: [CertField] = []
        func sectionTitle(_ oid: String, _ dict: [String: Any]) -> String {
            let label = (dict[kSecPropertyKeyLocalizedLabel as String] as? String)
                ?? (dict[kSecPropertyKeyLabel as String] as? String) ?? oid
            return OIDNames.friendly(label)
        }
        let sorted = raw.sorted { a, b in
            let pa = OIDNames.displayPriority(a.key), pb = OIDNames.displayPriority(b.key)
            if pa != pb { return pa < pb }
            return sectionTitle(a.key, a.value).localizedCaseInsensitiveCompare(sectionTitle(b.key, b.value)) == .orderedAscending
        }
        for (oid, dict) in sorted {
            flatten(dict, section: sectionTitle(oid, dict), into: &fields)
        }
        if !fields.contains(where: { $0.section.localizedCaseInsensitiveContains("fingerprint") }) {
            fields.append(CertField(section: "Fingerprints", label: "SHA-256", value: sha256))
            fields.append(CertField(section: "Fingerprints", label: "SHA-1", value: sha1))
        }

        return CertificateInfo(
            certificate: cert,
            der: der,
            commonName: cn,
            subject: subjectString,
            subjectAltNames: sans,
            issuer: issuer,
            issuerFull: issuerString,
            notBefore: notBefore,
            notAfter: notAfter,
            serial: serial,
            signatureAlgorithm: sigAlg,
            keyDescription: keyDescription,
            sha256Fingerprint: sha256,
            sha1Fingerprint: sha1,
            isSelfSigned: selfSigned,
            allFields: fields
        )
    }

    // MARK: - Helpers

    /// Turn a subject/issuer value array into ordered (shortName, value) pairs.
    private static func nameComponents(_ value: Any?) -> [(String, String)] {
        guard let items = value as? [[String: Any]] else { return [] }
        var out: [(String, String)] = []
        for item in items {
            let label = (item[kSecPropertyKeyLabel as String] as? String) ?? ""
            let localized = (item[kSecPropertyKeyLocalizedLabel as String] as? String) ?? label
            let short = OIDNames.shortName(for: label) ?? OIDNames.shortName(for: localized) ?? localized
            let v = stringify(item[kSecPropertyKeyValue as String], type: item[kSecPropertyKeyType as String] as? String)
            out.append((short, v))
        }
        return out
    }

    private static func dateValue(_ dict: [String: Any]?) -> Date? {
        guard let dict else { return nil }
        if let n = dict[kSecPropertyKeyValue as String] as? NSNumber {
            return Date(timeIntervalSinceReferenceDate: n.doubleValue)
        }
        if let d = dict[kSecPropertyKeyValue as String] as? Date { return d }
        return nil
    }

    static func stringify(_ value: Any?, type: String? = nil) -> String {
        guard let value else { return "" }
        if type == (kSecPropertyTypeDate as String), let n = value as? NSNumber {
            return Self.dateFormatter.string(from: Date(timeIntervalSinceReferenceDate: n.doubleValue))
        }
        switch value {
        case let s as String:
            return OIDNames.name(for: s).map { "\($0) (\(s))" } ?? s
        case let d as Data:
            return d.colonHexString
        case let n as NSNumber:
            return n.stringValue
        case let arr as [Any]:
            return arr.map { item -> String in
                if let dict = item as? [String: Any] {
                    let label = (dict[kSecPropertyKeyLocalizedLabel as String] as? String)
                        ?? (dict[kSecPropertyKeyLabel as String] as? String) ?? ""
                    let v = stringify(dict[kSecPropertyKeyValue as String], type: dict[kSecPropertyKeyType as String] as? String)
                    return label.isEmpty ? v : "\(label): \(v)"
                }
                return stringify(item)
            }.joined(separator: "\n")
        case let dict as [String: Any]:
            let v = stringify(dict[kSecPropertyKeyValue as String], type: dict[kSecPropertyKeyType as String] as? String)
            return v
        default:
            return String(describing: value)
        }
    }

    private static func flatten(_ dict: [String: Any], section: String, into fields: inout [CertField]) {
        let type = dict[kSecPropertyKeyType as String] as? String
        let value = dict[kSecPropertyKeyValue as String]
        if let items = value as? [[String: Any]], !items.isEmpty,
           items.allSatisfy({ $0[kSecPropertyKeyValue as String] != nil }) {
            for item in items {
                let label = (item[kSecPropertyKeyLocalizedLabel as String] as? String)
                    ?? (item[kSecPropertyKeyLabel as String] as? String) ?? ""
                let nice = OIDNames.friendly(label)
                let sub = item[kSecPropertyKeyValue as String]
                if let nested = sub as? [[String: Any]], !nested.isEmpty,
                   nested.allSatisfy({ $0[kSecPropertyKeyValue as String] != nil }) {
                    flatten(item, section: section.isEmpty ? nice : "\(section) › \(nice)", into: &fields)
                } else {
                    fields.append(CertField(section: section, label: nice,
                                            value: stringify(sub, type: item[kSecPropertyKeyType as String] as? String)))
                }
            }
        } else {
            fields.append(CertField(section: section, label: "", value: stringify(value, type: type)))
        }
    }

    static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()
}

/// Friendly names for OIDs that Security sometimes reports raw.
enum OIDNames {
    static let shortNames: [String: String] = [
        "2.5.4.3": "CN", "Common Name": "CN",
        "2.5.4.10": "O", "Organization": "O", "Organization Name": "O",
        "2.5.4.11": "OU", "Organizational Unit": "OU", "Organizational Unit Name": "OU",
        "2.5.4.6": "C", "Country": "C", "Country Name": "C",
        "2.5.4.7": "L", "Locality": "L", "Locality Name": "L",
        "2.5.4.8": "ST", "State/Province": "ST", "State or Province Name": "ST",
        "2.5.4.5": "serialNumber", "Serial Number": "serialNumber",
        "1.2.840.113549.1.9.1": "emailAddress", "Email Address": "emailAddress",
        "2.5.4.15": "businessCategory", "Business Category": "businessCategory",
        "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
        "0.9.2342.19200300.100.1.25": "DC", "Domain Component": "DC",
    ]

    static let names: [String: String] = [
        "1.2.840.113549.1.1.1": "RSA",
        "1.2.840.113549.1.1.5": "SHA-1 with RSA",
        "1.2.840.113549.1.1.11": "SHA-256 with RSA",
        "1.2.840.113549.1.1.12": "SHA-384 with RSA",
        "1.2.840.113549.1.1.13": "SHA-512 with RSA",
        "1.2.840.113549.1.1.10": "RSA-PSS",
        "1.2.840.10045.2.1": "Elliptic Curve",
        "1.2.840.10045.3.1.7": "P-256 (prime256v1)",
        "1.3.132.0.34": "P-384 (secp384r1)",
        "1.3.132.0.35": "P-521 (secp521r1)",
        "1.2.840.10045.4.3.2": "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3": "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4": "ECDSA with SHA-512",
        "1.3.101.112": "Ed25519",
        "1.3.101.113": "Ed448",
        "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
        "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
        "1.3.6.1.5.5.7.3.3": "Code Signing",
        "1.3.6.1.5.5.7.3.4": "Email Protection",
        "1.3.6.1.5.5.7.1.1": "Authority Information Access",
        "1.3.6.1.5.5.7.48.1": "OCSP",
        "1.3.6.1.5.5.7.48.2": "CA Issuers",
        "2.5.29.14": "Subject Key Identifier",
        "2.5.29.15": "Key Usage",
        "2.5.29.17": "Subject Alternative Name",
        "2.5.29.19": "Basic Constraints",
        "2.5.29.31": "CRL Distribution Points",
        "2.5.29.32": "Certificate Policies",
        "2.5.29.35": "Authority Key Identifier",
        "2.5.29.37": "Extended Key Usage",
        "2.23.140.1.2.1": "CA/B Forum Domain Validated",
        "2.23.140.1.2.2": "CA/B Forum Organization Validated",
        "2.23.140.1.1": "CA/B Forum Extended Validation",
        "1.3.6.1.4.1.11129.2.4.2": "Signed Certificate Timestamps",
    ]

    static func name(for oid: String) -> String? { names[oid] }
    static func shortName(for label: String) -> String? { shortNames[label] }

    /// Replace a raw dotted OID with its friendly name; leave other labels alone.
    static func friendly(_ label: String) -> String {
        if let n = names[label] { return n }
        if let s = shortNames[label], label.first?.isNumber == true { return s }
        return label
    }

    /// Ordering for the full-details view: core fields first, extensions after, fingerprints last.
    static func displayPriority(_ oid: String) -> Int {
        let order: [CFString] = [
            kSecOIDX509V1SubjectName, kSecOIDX509V1IssuerName, kSecOIDX509V1SerialNumber,
            kSecOIDX509V1Version, kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter,
            kSecOIDSubjectAltName, kSecOIDX509V1SubjectPublicKeyAlgorithm, kSecOIDX509V1SubjectPublicKey,
            kSecOIDX509V1SignatureAlgorithm, kSecOIDX509V1Signature,
            kSecOIDKeyUsage, kSecOIDExtendedKeyUsage, kSecOIDBasicConstraints,
            kSecOIDCertificatePolicies, kSecOIDAuthorityInfoAccess, kSecOIDCrlDistributionPoints,
            kSecOIDSubjectKeyIdentifier, kSecOIDAuthorityKeyIdentifier,
        ]
        if let i = order.firstIndex(where: { ($0 as String) == oid }) { return i }
        if oid.localizedCaseInsensitiveContains("fingerprint") { return 1000 }
        return 500
    }
}
