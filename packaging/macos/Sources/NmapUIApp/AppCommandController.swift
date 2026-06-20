import AppKit
import Foundation

@MainActor
final class AppCommandController {
    private let runtimeURL = RuntimeEndpoints.baseURL

    func openApp() {
        NSApp.sendAction(Selector(("showWindow:")), to: nil, from: nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        NSApp.windows.first?.makeKeyAndOrderFront(nil)
        NSApp.windows.first?.orderFrontRegardless()
    }

    func openBrowser() {
        NSWorkspace.shared.open(runtimeURL)
    }

    func showAbout() {
        NSApplication.shared.orderFrontStandardAboutPanel(options: [
            .credits: NSAttributedString(string: "Menu bar shell for the NmapUI runtime")
        ])
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func openPreferences() {
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func openDataDirectory() {
        NSWorkspace.shared.activateFileViewerSelecting([ProcessLauncher.currentDataDirectoryURL()])
    }
}
