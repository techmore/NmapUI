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
                    sessionState: appDelegate.sessionState,
                    onQuickScan: { appDelegate.startQuickScanFromNativeShell() },
                    onStartScan: { target, scanKind, vpnHelper in
                        appDelegate.startScanFromNativeShell(target: target, scanKind: scanKind, vpnHelper: vpnHelper)
                    },
                    onOpenReport: { path in appDelegate.openReportPath(path) },
                    onCreateCustomer: { name in appDelegate.createCustomer(name) },
                    onSelectCustomer: { id in appDelegate.selectCustomer(id) }
                )
            }
        }
        Settings {
            PreferencesView(
                store: appDelegate.preferencesStore,
                sessionState: appDelegate.sessionState,
                onChooseFolder: { appDelegate.chooseDataDirectory() },
                onRevealFolder: { appDelegate.openDataDirectory() },
                onSave: { appDelegate.savePreferences() },
                onReset: { appDelegate.resetPreferences() },
                onConnectGoogleDrive: { appDelegate.connectGoogleDriveFromSettings() },
                onDisconnectGoogleDrive: { appDelegate.disconnectGoogleDriveFromSettings() },
                onSaveGoogleDriveSettings: { enabled, folderID in appDelegate.saveGoogleDriveSettingsFromNative(enabled: enabled, folderID: folderID) },
                onSaveGoogleDriveCredentials: { json in appDelegate.saveGoogleDriveCredentialsFromNative(json) }
            )
        }
    }
}
