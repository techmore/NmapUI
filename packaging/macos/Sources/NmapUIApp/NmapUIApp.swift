import AppKit
import SwiftUI

@main
struct NmapUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            NativeShellView(
                url: RuntimeEndpoints.baseURL,
                sessionState: appDelegate.sessionState,
                onOpenBrowser: { appDelegate.openBrowser() }
            )
        }
        Settings {
            PreferencesView(
                store: appDelegate.preferencesStore,
                onChooseFolder: { appDelegate.chooseDataDirectory() },
                onRevealFolder: { appDelegate.openDataDirectory() },
                onSave: { appDelegate.savePreferences() },
                onReset: { appDelegate.resetPreferences() }
            )
        }
    }
}
