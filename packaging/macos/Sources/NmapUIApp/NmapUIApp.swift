import AppKit
import SwiftUI

@main
struct NmapUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        Settings {
            PreferencesView(
                store: appDelegate.preferencesStore,
                onChooseFolder: { appDelegate.openDataDirectoryFromSwiftUI() },
                onRevealFolder: { appDelegate.openDataDirectoryFromSwiftUI() },
                onSave: { appDelegate.savePreferencesFromSwiftUI() },
                onReset: { appDelegate.resetPreferencesFromSwiftUI() }
            )
        }
    }
}
