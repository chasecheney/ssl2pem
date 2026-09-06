import SwiftUI

@main
struct ssl2pemApp: App {
    @StateObject private var model = BundleModel()

    var body: some Scene {
        Window("ssl2pem", id: "main") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 720, minHeight: 560)
        }
        .defaultSize(width: 820, height: 900)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandGroup(after: .saveItem) {
                Button("Save PEM…") { model.save() }
                    .keyboardShortcut("s", modifiers: .command)
                    .disabled(!model.canSave)
                Button("Copy PEM to Clipboard") { model.copyToClipboard() }
                    .keyboardShortcut("c", modifiers: [.command, .shift])
                    .disabled(!model.canSave)
                Divider()
                Button("Clear All") { model.clearAll() }
                    .keyboardShortcut("k", modifiers: [.command, .shift])
            }
        }
    }
}
