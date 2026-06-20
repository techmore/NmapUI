import AppKit
import Foundation

@MainActor
final class RuntimeAlertPresenter {
    func presentLaunchFailureAlert() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "NmapUI could not start the runtime"
        alert.informativeText = "Check the runtime command and make sure the app can bind the fixed port."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    func presentPreferencesSaveFailureAlert() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Could not save preferences"
        alert.informativeText = "NmapUI could not update the launch at login setting, so the preferences change was not saved."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    func presentStartupTimeoutAlert() {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "NmapUI is still starting"
        alert.informativeText = "The runtime is taking a little longer than usual. The app will keep the native shell open and continue loading the UI in the background."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    func presentRuntimeExitAlert(terminationStatus: Int32, onRestart: @MainActor @escaping () -> Void) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "NmapUI runtime stopped"
        alert.informativeText = "The backend exited with status \(terminationStatus). Restart the runtime from the menu if you want another attempt."
        alert.addButton(withTitle: "Restart Runtime")
        alert.addButton(withTitle: "OK")

        if alert.runModal() == .alertFirstButtonReturn {
            onRestart()
        }
    }
}
