import AppKit
import Darwin
import Foundation

/// Privilege UX for NmapUI.
///
/// The app process always stays a normal user GUI. When privileged nmap is required,
/// we install/use a root helper daemon once (admin password), then subsequent
/// interactive and scheduled scans run without elevating the whole app.
enum PrivilegeElevationController {
    static var isRunningAsRoot: Bool {
        geteuid() == 0
    }

    /// Legacy whole-app root relaunch is intentionally disabled.
    @MainActor
    @discardableResult
    static func relaunchAsRootIfNeeded() -> Bool {
        if isRunningAsRoot {
            RuntimeDiagnosticsLogger.log("App is running as root; continuing in user-oriented mode is preferred going forward")
        }
        return false
    }

    static var isPrivilegedHelperReady: Bool {
        PrivilegeHelperClient.isHelperReachable
    }

    /// Ensures the privileged nmap helper is installed. Prompts for admin once if needed.
    @MainActor
    static func ensurePrivilegedHelperReady(interactive: Bool) throws {
        if PrivilegeHelperClient.isHelperReachable {
            return
        }
        guard interactive else {
            throw PrivilegeHelperClient.ClientError.notAvailable
        }
        try PrivilegeHelperClient.ensureInstalled()
        RuntimeDiagnosticsLogger.log("Privileged nmap helper is ready")
    }

    @MainActor
    static func presentHelperInstallFailure(_ error: Error) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Administrator helper required"
        alert.informativeText = """
        Full nmap scans (SYN / OS detection) need a one-time administrator approval to install NmapUI's scanner helper.

        After that, interactive and scheduled scans can run with root nmap privileges without restarting the app as root.

        \(error.localizedDescription)
        """
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
