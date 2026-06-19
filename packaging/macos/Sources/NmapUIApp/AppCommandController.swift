import AppKit
import Foundation

@MainActor
final class AppCommandController {
    private let runtimeURL: URL

    init(runtimeURL: URL) {
        self.runtimeURL = runtimeURL
    }

    func openApp() {
        NSWorkspace.shared.open(runtimeURL)
    }

    func openPreferences() {
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func openDataDirectory() {
        NSWorkspace.shared.activateFileViewerSelecting([ProcessLauncher.currentDataDirectoryURL()])
    }
}
