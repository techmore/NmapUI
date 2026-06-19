import AppKit
import Foundation
import ServiceManagement

@MainActor
final class AppTerminationController {
    private let runtimeLifecycleController: RuntimeLifecycleController

    init(runtimeLifecycleController: RuntimeLifecycleController) {
        self.runtimeLifecycleController = runtimeLifecycleController
    }

    func uninstallApp() {
        runtimeLifecycleController.stopForQuitOrUninstall()
        if #available(macOS 13.0, *) {
            try? SMAppService.mainApp.unregister()
        }
        let bundleURL = Bundle.main.bundleURL
        NSWorkspace.shared.recycle([bundleURL]) { _, _ in
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
    }

    func quitApp() {
        runtimeLifecycleController.stopForQuitOrUninstall()
        NSApp.terminate(nil)
    }
}
