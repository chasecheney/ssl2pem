import Foundation
import AppKit
import SwiftUI
import Security
import UniformTypeIdentifiers
import PEMCore

typealias Slot = PEMRole

extension PEMRole {
    var systemImage: String {
        switch self {
        case .key:         return "key.fill"
        case .certificate: return "doc.badge.ellipsis"
        case .chain:       return "doc.on.doc.fill"
        }
    }
}

/// Result of analysing the current set of files. Computed off the main actor.
struct Analysis: Sendable {
    var certInfo: CertificateInfo?
    var certError: String?
    var keyInfo: PrivateKeyInfo?
    var chainInfo: ChainInfo?
}

@MainActor
final class BundleModel: ObservableObject {
    @Published private(set) var files: [Slot: ImportedFile] = [:]
    @Published private(set) var certInfo: CertificateInfo?
    @Published private(set) var certError: String?
    @Published private(set) var keyInfo: PrivateKeyInfo?
    @Published private(set) var chainInfo: ChainInfo?
    @Published private(set) var isAnalyzing = false

    @Published var order: PEMOrder = .keyCertCA { didSet { refreshExport() } }
    @Published var passphrase: String = "" { didSet { scheduleReanalysis() } }
    @Published var fileName: String = "certificate.pem"
    @Published var fileNameEdited = false
    @Published var errorMessage: String?
    @Published var statusMessage: String?

    /// The export as it would be written right now, or the reason it can't be.
    @Published private(set) var export: ExportResult?
    @Published private(set) var exportBlocker: String?

    private var analysisTask: Task<Void, Never>?
    private var reanalysisDebounce: Task<Void, Never>?
    private var statusTask: Task<Void, Never>?

    var canSave: Bool { export != nil }
    var hasEncryptedKey: Bool { files[.key]?.isEncryptedKey ?? false }

    // MARK: Loading

    /// Load one URL into a specific slot, or auto-detect the slot when `slot` is nil.
    func load(url: URL, into slot: Slot?) {
        load(urls: [url], into: slot)
    }

    /// Load several URLs. Files that classify as chain material are merged into the CA slot.
    func load(urls: [URL], into slot: Slot? = nil) {
        guard !urls.isEmpty else { return }
        isAnalyzing = true
        Task.detached(priority: .userInitiated) { [weak self] in
            var imported: [ImportedFile] = []
            var errors: [String] = []
            for url in urls {
                let accessing = url.startAccessingSecurityScopedResource()
                defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                do {
                    imported.append(try PEMImporter.read(url, as: slot))
                } catch {
                    errors.append(error.localizedDescription)
                }
            }
            await self?.apply(imported: imported, errors: errors)
        }
    }

    private func apply(imported: [ImportedFile], errors: [String]) {
        // Several chain files dropped together are merged into one CA bundle.
        let chains = imported.filter { $0.role == .chain }
        if let first = chains.first {
            files[.chain] = chains.dropFirst().reduce(first) { $0.merging($1) }
        }
        for file in imported where file.role != .chain {
            files[file.role] = file
        }
        if files[.key]?.isEncryptedKey != true { passphrase = "" }
        errorMessage = errors.isEmpty ? nil : errors.joined(separator: "\n\n")
        statusMessage = nil
        reanalyze()
    }

    func clear(_ slot: Slot) {
        files[slot] = nil
        if slot == .key { passphrase = "" }
        reanalyze()
    }

    func clearAll() {
        files = [:]
        passphrase = ""
        fileNameEdited = false
        fileName = "certificate.pem"
        errorMessage = nil
        statusMessage = nil
        reanalyze()
    }

    // MARK: Analysis (off the main actor)

    private func scheduleReanalysis() {
        reanalysisDebounce?.cancel()
        reanalysisDebounce = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else { return }
            self?.reanalyze()
        }
    }

    private func reanalyze() {
        analysisTask?.cancel()
        let snapshot = files
        let pass = passphrase
        isAnalyzing = true
        analysisTask = Task.detached(priority: .userInitiated) { [weak self] in
            let analysis = Self.analyze(files: snapshot, passphrase: pass)
            guard !Task.isCancelled else { return }
            await self?.finish(analysis)
        }
    }

    nonisolated private static func analyze(files: [Slot: ImportedFile], passphrase: String) -> Analysis {
        var result = Analysis()

        if let certFile = files[.certificate], let leaf = certFile.blocks.first(where: \.isCertificate) {
            do {
                result.certInfo = try CertificateInfo.parse(der: leaf.der)
            } catch {
                result.certError = error.localizedDescription
            }
        }

        if let keyFile = files[.key] {
            result.keyInfo = PrivateKeyInspector.inspect(blocks: keyFile.blocks, passphrase: passphrase,
                                                         certificate: result.certInfo?.certificate)
        }

        let bundleCerts: [SecCertificate] = (files[.chain]?.blocks ?? [])
            .filter(\.isCertificate)
            .compactMap { SecCertificateCreateWithData(nil, $0.der as CFData) }
        let extraFromCert: [SecCertificate] = (files[.certificate]?.blocks ?? [])
            .filter(\.isCertificate)
            .dropFirst()
            .compactMap { SecCertificateCreateWithData(nil, $0.der as CFData) }
        if result.certInfo != nil || !bundleCerts.isEmpty {
            result.chainInfo = ChainVerifier.verify(leaf: result.certInfo?.certificate, bundle: bundleCerts + extraFromCert)
        }
        return result
    }

    private func finish(_ analysis: Analysis) {
        certInfo = analysis.certInfo
        certError = analysis.certError
        keyInfo = analysis.keyInfo
        chainInfo = analysis.chainInfo
        if let info = analysis.certInfo, !fileNameEdited {
            fileName = info.suggestedFileName
        }
        isAnalyzing = false
        refreshExport()
    }

    private func refreshExport() {
        guard files[.certificate] != nil else {
            export = nil
            exportBlocker = nil
            return
        }
        do {
            export = try PEMExporter.export(key: files[.key]?.blocks ?? [],
                                            certificate: files[.certificate]?.blocks ?? [],
                                            ca: files[.chain]?.blocks ?? [],
                                            passphrase: passphrase,
                                            order: order)
            exportBlocker = nil
        } catch {
            export = nil
            exportBlocker = error.localizedDescription
        }
    }

    // MARK: Output

    var normalizedFileName: String {
        var name = fileName.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty { name = certInfo?.suggestedFileName ?? "certificate.pem" }
        if !name.lowercased().hasSuffix(".pem") { name += ".pem" }
        return name
    }

    func save() {
        guard let export else { return }
        let panel = NSSavePanel()
        panel.title = "Save PEM"
        panel.nameFieldStringValue = normalizedFileName
        panel.allowedContentTypes = [UTType(filenameExtension: "pem") ?? .data]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        if let dir = files[.certificate]?.url.deletingLastPathComponent() {
            panel.directoryURL = dir
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try PEMWriter.save(export.data, to: url, containsPrivateKey: export.containsPrivateKey)
            showStatus("Saved \(url.lastPathComponent)" + (export.containsPrivateKey ? " (permissions 600)" : ""))
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func copyToClipboard() {
        guard let export else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(export.pem, forType: .string)
        showStatus(export.containsPrivateKey ? "Copied PEM (includes the private key) to the clipboard"
                                             : "Copied PEM to the clipboard")
    }

    private func showStatus(_ text: String) {
        statusMessage = text
        statusTask?.cancel()
        statusTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(6))
            guard !Task.isCancelled else { return }
            self?.statusMessage = nil
        }
    }

    func chooseFile(for slot: Slot) {
        let panel = NSOpenPanel()
        panel.title = "Choose \(slot.title)"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = slot == .chain
        panel.allowedContentTypes = [.data, .text, .x509Certificate]
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        load(urls: panel.urls, into: slot)
    }
}
