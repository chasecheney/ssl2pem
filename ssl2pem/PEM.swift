import Foundation

/// Minimal helpers for working with PEM-armored text.
enum PEM {
    struct Block: Equatable {
        let type: String      // e.g. "CERTIFICATE", "PRIVATE KEY", "RSA PRIVATE KEY"
        let armored: String   // full text including BEGIN/END lines, LF line endings
        let der: Data         // decoded body
    }

    /// Extract every `-----BEGIN X----- ... -----END X-----` block from a string.
    static func blocks(in text: String) -> [Block] {
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
                             .replacingOccurrences(of: "\r", with: "\n")
        var result: [Block] = []
        var lines = normalized.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        // Trim surrounding whitespace on every line so odd indentation doesn't break parsing.
        lines = lines.map { $0.trimmingCharacters(in: .whitespaces) }

        var i = 0
        while i < lines.count {
            let line = lines[i]
            if line.hasPrefix("-----BEGIN "), line.hasSuffix("-----") {
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
                    // Skip RFC 1421 headers (e.g. "Proc-Type:", "DEK-Info:") when decoding.
                    let base64 = body.filter { !$0.contains(":") && !$0.isEmpty }.joined()
                    let der = Data(base64Encoded: base64, options: [.ignoreUnknownCharacters]) ?? Data()
                    let armored = ([line] + body + [endMarker]).joined(separator: "\n")
                    result.append(Block(type: type, armored: armored, der: der))
                    i = j + 1
                    continue
                }
            }
            i += 1
        }
        return result
    }

    static func blocks(in data: Data) -> [Block] {
        if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN ") {
            return blocks(in: text)
        }
        if let text = String(data: data, encoding: .isoLatin1), text.contains("-----BEGIN ") {
            return blocks(in: text)
        }
        return []
    }

    /// Wrap DER bytes in PEM armor.
    static func armor(_ der: Data, type: String) -> String {
        let b64 = der.base64EncodedString(options: [.lineLength64Characters])
        return "-----BEGIN \(type)-----\n\(b64)\n-----END \(type)-----"
    }

    static func isPrivateKeyType(_ type: String) -> Bool {
        type.hasSuffix("PRIVATE KEY")
    }
}

extension Data {
    var hexString: String {
        map { String(format: "%02X", $0) }.joined()
    }

    var colonHexString: String {
        map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}
