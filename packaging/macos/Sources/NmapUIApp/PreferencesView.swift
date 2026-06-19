import ServiceManagement
import SwiftUI

enum PreferencesKeys {
    static let runtimeCommand = "NMAPUI_RUNTIME_COMMAND"
    static let dataDirectory = "NMAPUI_DATA_DIR"
}

@MainActor
final class PreferencesStore: ObservableObject {
    @Published var runtimeCommand: String
    @Published var dataDirectoryPath: String
    @Published var launchAtLoginEnabled: Bool

    init() {
        runtimeCommand = ProcessLauncher.currentRuntimeCommand()
        dataDirectoryPath = ProcessLauncher.currentDataDirectory()
        launchAtLoginEnabled = ProcessLauncher.isLaunchAtLoginEnabled()
    }

    func save() {
        let defaults = UserDefaults.standard
        defaults.set(runtimeCommand, forKey: PreferencesKeys.runtimeCommand)
        defaults.set(dataDirectoryPath, forKey: PreferencesKeys.dataDirectory)

        do {
            if #available(macOS 13.0, *) {
                if launchAtLoginEnabled {
                    try SMAppService.mainApp.register()
                } else {
                    try SMAppService.mainApp.unregister()
                }
            }
        } catch {
            NSLog("Failed to update launch at login from preferences: \(error.localizedDescription)")
        }
    }

    func resetToDefaults() {
        runtimeCommand = ProcessLauncher.currentRuntimeCommand()
        dataDirectoryPath = ProcessLauncher.currentDataDirectory()
        launchAtLoginEnabled = ProcessLauncher.isLaunchAtLoginEnabled()
    }

    func clearPersistedValues() {
        let defaults = UserDefaults.standard
        defaults.removeObject(forKey: PreferencesKeys.runtimeCommand)
        defaults.removeObject(forKey: PreferencesKeys.dataDirectory)
    }
}

struct PreferencesView: View {
    @ObservedObject var store: PreferencesStore
    let onChooseFolder: () -> Void
    let onRevealFolder: () -> Void
    let onSave: () -> Void
    let onReset: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Runtime Command")
                    .font(.headline)
                TextField("node server.js", text: $store.runtimeCommand)
                    .textFieldStyle(.roundedBorder)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Data Directory")
                    .font(.headline)
                HStack(spacing: 10) {
                    TextField("", text: $store.dataDirectoryPath)
                        .textFieldStyle(.roundedBorder)
                    Button("Choose Folder…", action: onChooseFolder)
                    Button("Reveal in Finder", action: onRevealFolder)
                }
            }

            Toggle("Launch at Login", isOn: $store.launchAtLoginEnabled)

            HStack {
                Button("Reset to Defaults") {
                    onReset()
                }
                Spacer()
                Button("Save") {
                    onSave()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 540)
    }
}
