import AppKit
import Foundation
import ServiceManagement

@MainActor
final class LaunchAtLoginController {
    func syncLaunchAtLoginState(_ menuPresenter: RuntimeMenuPresenter) {
        menuPresenter.syncLaunchAtLoginState()
    }

    func toggleLaunchAtLogin() {
        guard #available(macOS 13.0, *) else { return }
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            NSLog("Failed to toggle launch at login: \(error.localizedDescription)")
        }
    }
}
