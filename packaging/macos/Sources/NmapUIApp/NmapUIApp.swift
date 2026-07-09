import AppKit
import SwiftUI

@main
struct NmapUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup("TM-NMAPUI") {
            if ScheduledScanRunner.isScheduledScanInvocation {
                Color.clear.frame(width: 1, height: 1)
            } else {
                NativeShellView(
                    url: RuntimeEndpoints.dashboardURL,
                    sessionState: appDelegate.sessionState,
                    onOpenBrowser: { appDelegate.openBrowser() },
                    onQuickScan: { appDelegate.startQuickScanFromNativeShell() },
                    onStartScan: { target, scanKind, vpnHelper in
                        appDelegate.startScanFromNativeShell(target: target, scanKind: scanKind, vpnHelper: vpnHelper)
                    }
                )
            }
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
