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
    private var persistedRuntimeCommand: String
    private var persistedDataDirectoryPath: String
    private var persistedLaunchAtLoginEnabled: Bool

    init() {
        let runtimeCommand = ProcessLauncher.currentRuntimeCommand()
        let dataDirectoryPath = ProcessLauncher.currentDataDirectory()
        let launchAtLoginEnabled = ProcessLauncher.isLaunchAtLoginEnabled()
        self.runtimeCommand = runtimeCommand
        self.dataDirectoryPath = dataDirectoryPath
        self.launchAtLoginEnabled = launchAtLoginEnabled
        let persistedState = Self.persistedState(
            runtimeCommand: runtimeCommand,
            dataDirectoryPath: dataDirectoryPath,
            launchAtLoginEnabled: launchAtLoginEnabled
        )
        persistedRuntimeCommand = persistedState.runtimeCommand
        persistedDataDirectoryPath = persistedState.dataDirectoryPath
        persistedLaunchAtLoginEnabled = persistedState.launchAtLoginEnabled
    }

    func save() -> Bool {
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
            return false
        }

        let defaults = UserDefaults.standard
        defaults.set(runtimeCommand, forKey: PreferencesKeys.runtimeCommand)
        defaults.set(dataDirectoryPath, forKey: PreferencesKeys.dataDirectory)

        let persistedState = Self.persistedState(
            runtimeCommand: runtimeCommand,
            dataDirectoryPath: dataDirectoryPath,
            launchAtLoginEnabled: launchAtLoginEnabled
        )
        persistedRuntimeCommand = persistedState.runtimeCommand
        persistedDataDirectoryPath = persistedState.dataDirectoryPath
        persistedLaunchAtLoginEnabled = persistedState.launchAtLoginEnabled
        return true
    }

    func resetToDefaults() {
        runtimeCommand = ProcessLauncher.currentRuntimeCommand()
        dataDirectoryPath = ProcessLauncher.currentDataDirectory()
        launchAtLoginEnabled = ProcessLauncher.isLaunchAtLoginEnabled()
        let persistedState = Self.persistedState(
            runtimeCommand: runtimeCommand,
            dataDirectoryPath: dataDirectoryPath,
            launchAtLoginEnabled: launchAtLoginEnabled
        )
        persistedRuntimeCommand = persistedState.runtimeCommand
        persistedDataDirectoryPath = persistedState.dataDirectoryPath
        persistedLaunchAtLoginEnabled = persistedState.launchAtLoginEnabled
    }

    var hasUnsavedChanges: Bool {
        runtimeCommand != persistedRuntimeCommand
            || dataDirectoryPath != persistedDataDirectoryPath
            || launchAtLoginEnabled != persistedLaunchAtLoginEnabled
    }

    private static func persistedState(
        runtimeCommand: String,
        dataDirectoryPath: String,
        launchAtLoginEnabled: Bool
    ) -> (runtimeCommand: String, dataDirectoryPath: String, launchAtLoginEnabled: Bool) {
        (
            runtimeCommand: runtimeCommand,
            dataDirectoryPath: dataDirectoryPath,
            launchAtLoginEnabled: launchAtLoginEnabled
        )
    }
}

struct PreferencesView: View {
    @ObservedObject var store: PreferencesStore
    let onChooseFolder: () -> Void
    let onRevealFolder: () -> Void
    let onSave: () -> Void
    let onReset: () -> Void
    @State private var showingResetConfirmation = false
    @State private var copiedPathConfirmation = false
    @State private var copiedPathHideWorkItem: DispatchWorkItem?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Runtime Command")
                    .font(.headline)
                TextField("node server.js", text: $store.runtimeCommand)
                    .textFieldStyle(.roundedBorder)
                Text("This command runs from the repo root and should start the local backend.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Data Directory")
                    .font(.headline)
                HStack(spacing: 10) {
                    Text(store.dataDirectoryPath)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(store.dataDirectoryPath, forType: .string)
                        copiedPathConfirmation = true
                        copiedPathHideWorkItem?.cancel()
                        let hideWorkItem = DispatchWorkItem {
                            copiedPathConfirmation = false
                        }
                        copiedPathHideWorkItem = hideWorkItem
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5, execute: hideWorkItem)
                    } label: {
                        Label("Copy Path", systemImage: "doc.on.doc")
                    }
                    .labelStyle(.titleAndIcon)
                    Button("Choose Folder…", action: onChooseFolder)
                    Button("Reveal in Finder", action: onRevealFolder)
                    if copiedPathConfirmation {
                        Text("Copied")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Text("Choose a writable folder for reports and app state.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Toggle("Launch at Login", isOn: $store.launchAtLoginEnabled)

            HStack {
                Button("Reset to Defaults") {
                    showingResetConfirmation = true
                }
                Spacer()
                Button("Save") {
                    onSave()
                }
                .disabled(!store.hasUnsavedChanges)
                .keyboardShortcut(.defaultAction)
            }
            if store.hasUnsavedChanges {
                Text("You have unsaved changes.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .confirmationDialog(
            "Reset preferences to defaults?",
            isPresented: $showingResetConfirmation,
            titleVisibility: .visible
        ) {
            Button("Reset to Defaults", role: .destructive) {
                onReset()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will restore the runtime command, data directory, and launch-at-login settings to their default values.")
        }
        .onDisappear {
            copiedPathHideWorkItem?.cancel()
            copiedPathHideWorkItem = nil
        }
        .padding(20)
        .frame(width: 540)
    }
}
