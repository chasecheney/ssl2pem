import Foundation

/// Error type used throughout PEMCore. Messages are written for display in the UI.
public struct PEMError: LocalizedError, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// Minimal helpers for working with PEM-armored text.
public enum PEM {
    public struct Block: Equatable, Hashable {
        public let type: String      // e.g. "CERTIFICATE", "PRIVATE KEY", "RSA PRIVATE KEY"
        public let armored: String   // full text including BEGIN/END lines, LF line endings, no trailing newline
        public let der: Data         // decoded body
        public let headers: [String: String]   // RFC 1421 headers such as "Proc-Type", "DEK-Info"

        public init(type: String, armored: String, der: Data, headers: [String: String] = [:]) {
            self.type = type
            self.armored = armored
            self.der = der
            self.headers = headers
        }

        public var isCertificate: Bool { type == "CERTIFICATE" }
        public var isPrivateKey: Bool { type.hasSuffix("PRIVATE KEY") }
        public var isEncryptedPrivateKey: Bool {
            type == "ENCRYPTED PRIVATE KEY" || (headers["Proc-Type"]?.contains("ENCRYPTED") ?? false)
        }
    }

    /// Extract every `-----BEGIN X----- ... -----END X-----` block from a string.
    public static func blocks(in text: String) -> [Block] {
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
                             .replacingOccurrences(of: "\r", with: "\n")
        var result: [Block] = []
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }

        var i = 0
        while i < lines.count {
            let line = lines[i]
            if line.hasPrefix("-----BEGIN "), line.hasSuffix("-----"), line.count > 16 {
                let type = String(line.dropFirst("-----BEGIN ".count).dropLast("-----".count))
                let endMarker = "-----END \(type)-----"
                var j = i + 1
                var body: [String] = []
                var found = false
                while j < lines.count {
                    if lines[j] == endMarker { found = true; break }
                    body.append(lines[j])
                    j += 1
                }
                if found {
                    var headers: [String: String] = [:]
                    var base64Lines: [String] = []
                    for l in body where !l.isEmpty {
                        // Base64 never contains ':' so any such line is an RFC 1421 header.
                        if let colon = l.firstIndex(of: ":") {
                            headers[String(l[..<colon]).trimmingCharacters(in: .whitespaces)] =
                                String(l[l.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                        } else {
                            base64Lines.append(l)
                        }
                    }
                    let der = Data(base64Encoded: base64Lines.joined(), options: [.ignoreUnknownCharacters]) ?? Data()
                    // Re-armor: BEGIN, any headers followed by the blank line PEM readers expect, base64, END.
                    let headerLines = body.filter { !$0.isEmpty && $0.contains(":") }
                    let armored = ([line] + headerLines + (headerLines.isEmpty ? [] : [""]) + base64Lines + [endMarker])
                        .joined(separator: "\n")
                    result.append(Block(type: type, armored: armored, der: der, headers: headers))
                    i = j + 1
                    continue
                }
            }
            i += 1
        }
        return result
    }

    public static func blocks(in data: Data) -> [Block] {
        if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN ") {
            return blocks(in: text)
        }
        if let text = String(data: data, encoding: .isoLatin1), text.contains("-----BEGIN ") {
            return blocks(in: text)
        }
        return []
    }

    /// Wrap DER bytes in PEM armor.
    public static func armor(_ der: Data, type: String) -> String {
        let b64 = der.base64EncodedString(options: [.lineLength64Characters])
        return "-----BEGIN \(type)-----\n\(b64)\n-----END \(type)-----"
    }

    public static func isPrivateKeyType(_ type: String) -> Bool {
        type.hasSuffix("PRIVATE KEY")
    }
}

public extension Data {
    var hexString: String {
        map { String(format: "%02X", $0) }.joined()
    }

    var colonHexString: String {
        map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}
