import AppKit
import Foundation

@MainActor
final class AppCommandController {
    func openApp() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        NSApp.windows.first?.makeKeyAndOrderFront(nil)
        NSApp.windows.first?.orderFrontRegardless()
    }

    func openBrowser() {
        openApp()
    }

    func showAbout() {
        NSApplication.shared.orderFrontStandardAboutPanel(options: [
            .credits: NSAttributedString(string: "Menu bar shell for the NmapUI runtime")
        ])
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func openPreferences() {
        NSApp.activate(ignoringOtherApps: true)
    }

    func openDataDirectory() {
        NSWorkspace.shared.activateFileViewerSelecting([RuntimeSettingsStore.currentDataDirectoryURL()])
    }
}
