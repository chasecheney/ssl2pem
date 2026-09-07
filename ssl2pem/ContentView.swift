import SwiftUI
import UniformTypeIdentifiers
import PEMCore

struct ContentView: View {
    @EnvironmentObject private var model: BundleModel
    @State private var showAllDetails = false
    @State private var windowTargeted = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                slotsSection
                if let error = model.certError {
                    Label(error, systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red)
                } else if let info = model.certInfo {
                    CertificateSummaryView(info: info, keyInfo: model.keyInfo, chainInfo: model.chainInfo,
                                           showAllDetails: $showAllDetails)
                } else if model.files[.key] != nil || model.files[.chain] != nil {
                    Label("Drop the server certificate to see its details and verify the key and chain.",
                          systemImage: "info.circle")
                        .foregroundStyle(.secondary)
                }
                outputSection
            }
            .padding(20)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay {
            if windowTargeted {
                ZStack {
                    Color.accentColor.opacity(0.08)
                    RoundedRectangle(cornerRadius: 12)
                        .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 3, dash: [10, 6]))
                        .padding(8)
                    Text("Drop to add")
                        .font(.title2.weight(.semibold))
                        .padding(.horizontal, 18).padding(.vertical, 10)
                        .background(.regularMaterial, in: Capsule())
                }
                .allowsHitTesting(false)
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $windowTargeted) { providers in
            DropHelper.urls(from: providers) { urls in model.load(urls: urls) }
            return true
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if model.isAnalyzing {
                    ProgressView().controlSize(.small)
                }
                Button {
                    model.clearAll()
                } label: {
                    Label("Clear All", systemImage: "trash")
                }
                .disabled(model.files.isEmpty)
                .help("Remove all files (⇧⌘K)")
            }
        }
        .alert("Couldn't use that file", isPresented: Binding(get: { model.errorMessage != nil },
                                                              set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    // MARK: Slots

    private var slotsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Drop your files")
                .font(.title2.weight(.semibold))
            Text("Drop all three at once anywhere in the window and they'll be sorted by content, or drop each file into its slot.")
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack(spacing: 12) {
                ForEach(Slot.allCases) { slot in
                    FileSlotView(slot: slot)
                }
            }
            if model.hasEncryptedKey {
                PassphraseField()
            }
        }
    }

    // MARK: Output

    private var outputSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Picker("Format", selection: $model.order) {
                    ForEach(PEMOrder.allCases) { order in
                        Text(order.title).tag(order)
                    }
                }
                .pickerStyle(.menu)
                .fixedSize()

                Text(model.order.compatibility)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if let blocker = model.exportBlocker {
                    Label(blocker, systemImage: "hand.raised.fill")
                        .foregroundStyle(.orange)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let export = model.export {
                    ForEach(export.warnings, id: \.self) { w in
                        Label(w, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                HStack {
                    TextField("File name", text: $model.fileName)
                        .textFieldStyle(.roundedBorder)
                        .onChange(of: model.fileName) { _, newValue in
                            let suggested = model.certInfo?.suggestedFileName ?? "certificate.pem"
                            if newValue != suggested { model.fileNameEdited = true }
                        }
                        .onSubmit { if model.canSave { model.save() } }
                    Button {
                        model.copyToClipboard()
                    } label: {
                        Label("Copy", systemImage: "doc.on.clipboard")
                    }
                    .disabled(!model.canSave)
                    .help("Copy the PEM text to the clipboard (⇧⌘C)")
                    Button {
                        model.save()
                    } label: {
                        Label("Save PEM…", systemImage: "square.and.arrow.down")
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.canSave)
                    .help("Save the combined .pem file (⌘S)")
                }

                HStack {
                    if let export = model.export {
                        Text("\(export.data.count.formatted()) bytes · \(PEM.blocks(in: export.pem).count) blocks" +
                             (export.containsPrivateKey ? " · saved with permissions 600" : ""))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if let status = model.statusMessage {
                        Label(status, systemImage: "checkmark.circle.fill")
                            .font(.caption)
                            .foregroundStyle(.green)
                            .transition(.opacity)
                    }
                }
                .animation(.default, value: model.statusMessage)
            }
            .padding(6)
        } label: {
            Label("Output .pem", systemImage: "shippingbox")
                .font(.headline)
        }
    }
}

// MARK: - Passphrase

struct PassphraseField: View {
    @EnvironmentObject private var model: BundleModel
    @State private var reveal = false

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "lock.fill").foregroundStyle(.secondary)
            Group {
                if reveal {
                    TextField("Private key passphrase", text: $model.passphrase)
                } else {
                    SecureField("Private key passphrase", text: $model.passphrase)
                }
            }
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: 360)
            Toggle(isOn: $reveal) { Image(systemName: reveal ? "eye.slash" : "eye") }
                .toggleStyle(.button)
                .help(reveal ? "Hide passphrase" : "Show passphrase")
            Text("The key is encrypted. It's only unlocked to verify it and is exported still encrypted.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 4)
    }
}

// MARK: - File slot

struct FileSlotView: View {
    @EnvironmentObject private var model: BundleModel
    let slot: Slot
    @State private var targeted = false

    private var file: ImportedFile? { model.files[slot] }

    var body: some View {
        VStack(spacing: 8) {
            ZStack {
                Circle()
                    .fill(file == nil ? Color.secondary.opacity(0.12) : Color.green.opacity(0.15))
                    .frame(width: 52, height: 52)
                Image(systemName: file == nil ? slot.systemImage : "checkmark")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(file == nil ? Color.secondary : Color.green)
            }
            Text(slot.title)
                .font(.headline)
            if let file {
                Text(file.name)
                    .font(.callout)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(file.url.path)
                Text(blockSummary(file))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let warning = file.warning {
                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Button("Change…") { model.chooseFile(for: slot) }
                    Button("Remove") { model.clear(slot) }
                }
                .controlSize(.small)
            } else {
                Text(slot.hint)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Button("Choose…") { model.chooseFile(for: slot) }
                    .controlSize(.small)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 160)
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(targeted ? Color.accentColor.opacity(0.15) : Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(style: StrokeStyle(lineWidth: targeted ? 2 : 1, dash: file == nil ? [6, 4] : []))
                .foregroundStyle(targeted ? Color.accentColor : Color.secondary.opacity(0.4))
        )
        .animation(.easeInOut(duration: 0.15), value: targeted)
        .onDrop(of: [.fileURL], isTargeted: $targeted) { providers in
            DropHelper.urls(from: providers) { urls in
                if urls.count == 1 || slot == .chain {
                    model.load(urls: urls, into: slot)
                } else {
                    model.load(urls: urls)
                }
            }
            return true
        }
    }

    private func blockSummary(_ file: ImportedFile) -> String {
        var parts: [String] = []
        let certs = file.certificateCount, keys = file.privateKeyCount
        if certs > 0 { parts.append("\(certs) certificate\(certs == 1 ? "" : "s")") }
        if keys > 0 { parts.append(file.isEncryptedKey ? "encrypted private key" : "private key") }
        let other = file.blocks.count - certs - keys
        if other > 0 { parts.append("\(other) other") }
        return parts.isEmpty ? "no PEM blocks" : parts.joined(separator: ", ")
    }
}

// MARK: - Certificate summary

struct CertificateSummaryView: View {
    let info: CertificateInfo
    let keyInfo: PrivateKeyInfo?
    let chainInfo: ChainInfo?
    @Binding var showAllDetails: Bool

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 8) {
                    row("Domain") {
                        Text(info.commonName.isEmpty ? "—" : info.commonName)
                            .font(.title3.weight(.semibold))
                            .textSelection(.enabled)
                    }
                    let others = info.coveredNames.filter { $0 != info.commonName }
                    if !others.isEmpty {
                        row("Also covers") {
                            Text(others.joined(separator: "  ·  "))
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    row("Issuer") {
                        HStack(spacing: 6) {
                            Text(info.issuer).textSelection(.enabled)
                            if info.isSelfSigned { badge("self-signed", .orange) }
                        }
                    }
                    row("Valid") {
                        HStack(spacing: 8) {
                            Text("\(fmt(info.notBefore))  →  \(fmt(info.notAfter))")
                                .textSelection(.enabled)
                            validityBadge
                        }
                    }
                    row("Key") { Text(info.keyDescription) }
                    row("Signature") { Text(info.signatureAlgorithm) }
                    row("Serial") {
                        Text(info.serial).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    }
                    row("SHA-256") {
                        Text(info.sha256Fingerprint)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let keyInfo {
                        row("Private key") { checkLine(keyInfo) }
                    }
                    if let chainInfo {
                        row("Chain") { chainLine(chainInfo) }
                    }
                }

                Divider()

                Button {
                    withAnimation(.easeInOut(duration: 0.15)) { showAllDetails.toggle() }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .rotationEffect(.degrees(showAllDetails ? 90 : 0))
                        Text(showAllDetails ? "Hide full details" : "Show full details (\(info.allFields.count) fields)")
                            .font(.callout)
                        Spacer()
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                if showAllDetails {
                    AllDetailsView(fields: info.allFields)
                }
            }
            .padding(6)
        } label: {
            Label("Certificate", systemImage: "checkmark.seal")
                .font(.headline)
        }
    }

    private func row<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func fmt(_ date: Date?) -> String {
        guard let date else { return "—" }
        return date.formatted(date: .abbreviated, time: .omitted)
    }

    @ViewBuilder
    private var validityBadge: some View {
        if info.isExpired {
            badge("Expired", .red)
        } else if info.isNotYetValid {
            badge("Not yet valid", .orange)
        } else if let days = info.daysRemaining {
            badge("\(days) days left", days < 30 ? .orange : .green)
        }
    }

    private func badge(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }

    private func checkLine(_ keyInfo: PrivateKeyInfo) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            switch keyInfo.match {
            case .matches:  Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .mismatch: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
            case .unknown:  Image(systemName: keyInfo.needsPassphrase ? "lock.fill" : "questionmark.circle").foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(keyInfo.typeDescription)
                Text(keyInfo.note).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func chainLine(_ chain: ChainInfo) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            switch chain.status {
            case .valid:       Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .privateRoot: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            case .invalid:     Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
            case .unknown:     Image(systemName: "questionmark.circle").foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(chain.summary).fixedSize(horizontal: false, vertical: true)
                if !chain.chain.isEmpty {
                    Text(chain.chain.joined(separator: "  →  "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

// MARK: - Full details

struct AllDetailsView: View {
    let fields: [CertField]

    private var sections: [(String, [CertField])] {
        var order: [String] = []
        var map: [String: [CertField]] = [:]
        for f in fields {
            if map[f.section] == nil { order.append(f.section) }
            map[f.section, default: []].append(f)
        }
        return order.map { ($0, map[$0] ?? []) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(sections, id: \.0) { section, items in
                VStack(alignment: .leading, spacing: 4) {
                    Text(section)
                        .font(.subheadline.weight(.semibold))
                    ForEach(items) { field in
                        HStack(alignment: .top, spacing: 8) {
                            if !field.label.isEmpty {
                                Text(field.label)
                                    .foregroundStyle(.secondary)
                                    .frame(width: 180, alignment: .trailing)
                            }
                            Text(field.value)
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .font(.callout)
                    }
                }
                .padding(8)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}

// MARK: - Drop helper

enum DropHelper {
    static func urls(from providers: [NSItemProvider], completion: @escaping ([URL]) -> Void) {
        let group = DispatchGroup()
        var urls: [URL] = []
        let lock = NSLock()
        for provider in providers where provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            group.enter()
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
                defer { group.leave() }
                var url: URL?
                if let data = item as? Data {
                    url = URL(dataRepresentation: data, relativeTo: nil)
                } else if let u = item as? URL {
                    url = u
                } else if let s = item as? String {
                    url = URL(string: s)
                }
                if let url {
                    lock.lock(); urls.append(url); lock.unlock()
                }
            }
        }
        group.notify(queue: .main) {
            completion(urls.sorted { $0.lastPathComponent < $1.lastPathComponent })
        }
    }
}
