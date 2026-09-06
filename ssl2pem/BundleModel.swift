import Foundation
import AppKit
import SwiftUI
import Security
import UniformTypeIdentifiers

enum Slot: String, CaseIterable, Identifiable {
    case key, cert, ca

    var id: String { rawValue }

    var title: String {
        switch self {
        case .key:  return "Private Key"
        case .cert: return "Certificate"
        case .ca:   return "CA Bundle"
        }
    }

    var hint: String {
        switch self {
        case .key:  return "private.key"
        case .cert: return "certificate.crt"
        case .ca:   return "ca_bundle.crt"
        }
    }

    var systemImage: String {
        switch self {
        case .key:  return "key.fill"
        case .cert: return "doc.badge.ellipsis"
        case .ca:   return "doc.on.doc.fill"
        }
    }
}

struct LoadedFile {
    let url: URL
    let blocks: [PEM.Block]
    var name: String { url.lastPathComponent }
}

@MainActor
final class BundleModel: ObservableObject {
    @Published var files: [Slot: LoadedFile] = [:]
    @Published var certInfo: CertificateInfo?
    @Published var keyInfo: PrivateKeyInfo?
    @Published var chainInfo: ChainInfo?
    @Published var slotWarnings: [Slot: String] = [:]

    @Published var order: PEMOrder = .keyCertCA
    @Published var fileName: String = "certificate.pem"
    @Published var fileNameEdited = false
    @Published var errorMessage: String?
    @Published var statusMessage: String?

    var canSave: Bool { files[.cert] != nil }

    // MARK: Loading

    /// Load a URL into a specific slot, or auto-detect the slot when `slot` is nil.
    func load(url: URL, into slot: Slot?) {
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            errorMessage = "Couldn't read \(url.lastPathComponent): \(error.localizedDescription)"
            return
        }

        var blocks = PEM.blocks(in: data)
        if blocks.isEmpty {
            // Maybe raw DER certificate (.cer / .der)
            if SecCertificateCreateWithData(nil, data as CFData) != nil {
                blocks = [PEM.Block(type: "CERTIFICATE", armored: PEM.armor(data, type: "CERTIFICATE"), der: data)]
            } else {
                errorMessage = "\(url.lastPathComponent) doesn't contain any PEM blocks or a DER certificate."
                return
            }
        }

        let detected = classify(blocks: blocks, name: url.lastPathComponent)
        let target = slot ?? detected

        // Warn if the user dropped a file into a slot that doesn't match its contents.
        var warning: String?
        if let slot, slot != detected {
            switch (slot, detected) {
            case (.key, _):  warning = "This file has no private key block."
            case (.cert, .key): warning = "This looks like a private key, not a certificate."
            case (.ca, .key):   warning = "This looks like a private key, not a CA bundle."
            case (.cert, .ca):  warning = "This file has \(blocks.filter { $0.type == "CERTIFICATE" }.count) certificates; only the first is treated as the leaf."
            case (.ca, .cert):  warning = "This file has a single certificate; expected an intermediate chain."
            default: break
            }
        }

        files[target] = LoadedFile(url: url, blocks: blocks)
        slotWarnings[target] = warning
        errorMessage = nil
        statusMessage = nil
        reanalyze()
    }

    func load(urls: [URL]) {
        // Auto-sort a multi-file drop. If a file is ambiguous it lands in cert.
        for url in urls { load(url: url, into: nil) }
    }

    func clear(_ slot: Slot) {
        files[slot] = nil
        slotWarnings[slot] = nil
        reanalyze()
    }

    func clearAll() {
        files = [:]
        slotWarnings = [:]
        fileNameEdited = false
        fileName = "certificate.pem"
        errorMessage = nil
        statusMessage = nil
        reanalyze()
    }

    private func classify(blocks: [PEM.Block], name: String) -> Slot {
        if blocks.contains(where: { PEM.isPrivateKeyType($0.type) }) { return .key }
        let certCount = blocks.filter { $0.type == "CERTIFICATE" }.count
        if certCount > 1 { return .ca }
        let lower = name.lowercased()
        let caHints = ["ca_bundle", "ca-bundle", "cabundle", "bundle", "chain", "intermediate", "ca.", "ca_", "ca-", "root"]
        if caHints.contains(where: { lower.contains($0) }) && !lower.contains("fullchain") { return .ca }
        return .cert
    }

    // MARK: Analysis

    private func reanalyze() {
        // Certificate
        if let certFile = files[.cert],
           let leaf = certFile.blocks.first(where: { $0.type == "CERTIFICATE" }) {
            do {
                let info = try CertificateInfo.parse(der: leaf.der)
                certInfo = info
                if !fileNameEdited { fileName = info.suggestedFileName }
            } catch {
                certInfo = nil
                errorMessage = error.localizedDescription
            }
        } else {
            certInfo = nil
        }

        // Key
        if let keyFile = files[.key] {
            keyInfo = PrivateKeyInspector.inspect(blocks: keyFile.blocks, certificate: certInfo?.certificate)
        } else {
            keyInfo = nil
        }

        // Chain
        let bundleCerts: [SecCertificate] = (files[.ca]?.blocks ?? [])
            .filter { $0.type == "CERTIFICATE" }
            .compactMap { SecCertificateCreateWithData(nil, $0.der as CFData) }
        // Extra certs bundled inside the certificate file count as chain too.
        let extraFromCert: [SecCertificate] = (files[.cert]?.blocks ?? [])
            .filter { $0.type == "CERTIFICATE" }
            .dropFirst()
            .compactMap { SecCertificateCreateWithData(nil, $0.der as CFData) }

        if certInfo != nil || !bundleCerts.isEmpty {
            chainInfo = ChainVerifier.verify(leaf: certInfo?.certificate, bundle: bundleCerts + extraFromCert)
        } else {
            chainInfo = nil
        }
    }

    // MARK: Output

    var output: (pem: String, warnings: [PEMBuilder.Warning]) {
        PEMBuilder.build(key: files[.key]?.blocks ?? [],
                         cert: files[.cert]?.blocks ?? [],
                         ca: files[.ca]?.blocks ?? [],
                         order: order)
    }

    var normalizedFileName: String {
        var name = fileName.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty { name = certInfo?.suggestedFileName ?? "certificate.pem" }
        if !name.lowercased().hasSuffix(".pem") { name += ".pem" }
        return name
    }

    func save() {
        let panel = NSSavePanel()
        panel.title = "Save PEM"
        panel.nameFieldStringValue = normalizedFileName
        panel.allowedContentTypes = [UTType(filenameExtension: "pem") ?? .data]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        if let dir = files[.cert]?.url.deletingLastPathComponent() {
            panel.directoryURL = dir
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }

        let (pem, _) = output
        do {
            try pem.write(to: url, atomically: true, encoding: .utf8)
            if order.includesKey {
                // A file containing a private key should be owner-readable only.
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            }
            statusMessage = "Saved \(url.lastPathComponent)"
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } catch {
            errorMessage = "Couldn't save: \(error.localizedDescription)"
        }
    }

    func copyToClipboard() {
        let (pem, _) = output
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(pem, forType: .string)
        statusMessage = "Copied PEM to clipboard"
    }

    func chooseFile(for slot: Slot) {
        let panel = NSOpenPanel()
        panel.title = "Choose \(slot.title)"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.data, .text, .x509Certificate, .pkcs12]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        load(url: url, into: slot)
    }
}
