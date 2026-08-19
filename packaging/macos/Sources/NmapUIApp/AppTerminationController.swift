import AppKit
import Foundation
import ServiceManagement

@MainActor
final class AppTerminationController {
    func uninstallApp() {
        if #available(macOS 13.0, *) {
            try? SMAppService.mainApp.unregister()
        }
        let bundleURL = Bundle.main.bundleURL
        NSWorkspace.shared.recycle([bundleURL]) { _, error in
            if let error {
                NSLog("Failed to recycle app bundle during uninstall: \(error.localizedDescription)")
            }
            DispatchQueue.main.async {
                NSApp.terminate(nil)
            }
        }
    }

    func quitApp() {
        NSApp.terminate(nil)
    }
}
