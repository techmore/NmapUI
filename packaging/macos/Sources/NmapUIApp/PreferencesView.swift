import ServiceManagement
import SwiftUI

enum PreferencesKeys {
    static let useDefaultRuntimeCommand = "NMAPUI_USE_DEFAULT_RUNTIME_COMMAND"
    static let runtimeExecutable = "NMAPUI_RUNTIME_EXECUTABLE"
    static let runtimeArguments = "NMAPUI_RUNTIME_ARGUMENTS"
    static let runtimeCommand = "NMAPUI_RUNTIME_COMMAND"
    static let dataDirectory = "NMAPUI_DATA_DIR"
}

@MainActor
final class PreferencesStore: ObservableObject {
    @Published var useDefaultRuntimeCommand: Bool
    @Published var runtimeExecutable: String
    @Published var runtimeArguments: String
    @Published var dataDirectoryPath: String
    @Published var launchAtLoginEnabled: Bool
    private var persistedUseDefaultRuntimeCommand: Bool
    private var persistedRuntimeExecutable: String
    private var persistedRuntimeArguments: String
    private var persistedDataDirectoryPath: String
    private var persistedLaunchAtLoginEnabled: Bool

    init() {
        let loadedSettings = RuntimeSettingsStore.load(from: RuntimeSettingsStore.currentDataDirectoryURL())
        let currentSettings = RuntimeSettingsStore.current()
        let useDefaultRuntimeCommand = loadedSettings?.useDefaultRuntimeCommand ?? currentSettings.useDefaultRuntimeCommand
        let runtimeExecutable = loadedSettings?.runtimeExecutable ?? currentSettings.runtimeExecutable
        let runtimeArguments = loadedSettings?.runtimeArguments ?? currentSettings.runtimeArguments
        let dataDirectoryPath = loadedSettings?.dataDirectoryPath ?? currentSettings.dataDirectoryPath
        let launchAtLoginEnabled = loadedSettings?.launchAtLoginEnabled ?? currentSettings.launchAtLoginEnabled
        self.useDefaultRuntimeCommand = useDefaultRuntimeCommand
        self.runtimeExecutable = runtimeExecutable
        self.runtimeArguments = runtimeArguments
        self.dataDirectoryPath = dataDirectoryPath
        self.launchAtLoginEnabled = launchAtLoginEnabled
        let persistedState = Self.persistedState(
            useDefaultRuntimeCommand: useDefaultRuntimeCommand,
            runtimeExecutable: runtimeExecutable,
            runtimeArguments: runtimeArguments,
            dataDirectoryPath: dataDirectoryPath,
            launchAtLoginEnabled: launchAtLoginEnabled
        )
        persistedUseDefaultRuntimeCommand = persistedState.useDefaultRuntimeCommand
        persistedRuntimeExecutable = persistedState.runtimeExecutable
        persistedRuntimeArguments = persistedState.runtimeArguments
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
        defaults.set(useDefaultRuntimeCommand, forKey: PreferencesKeys.useDefaultRuntimeCommand)
        if useDefaultRuntimeCommand {
            defaults.removeObject(forKey: PreferencesKeys.runtimeExecutable)
            defaults.removeObject(forKey: PreferencesKeys.runtimeArguments)
            defaults.removeObject(forKey: PreferencesKeys.runtimeCommand)
        } else {
            defaults.set(runtimeExecutable, forKey: PreferencesKeys.runtimeExecutable)
            defaults.set(runtimeArguments, forKey: PreferencesKeys.runtimeArguments)
            defaults.removeObject(forKey: PreferencesKeys.runtimeCommand)
        }
        defaults.set(dataDirectoryPath, forKey: PreferencesKeys.dataDirectory)
        RuntimeSettingsStore.persist(
            RuntimeSettings(
                useDefaultRuntimeCommand: useDefaultRuntimeCommand,
                runtimeExecutable: runtimeExecutable,
                runtimeArguments: runtimeArguments,
                dataDirectoryPath: dataDirectoryPath,
                launchAtLoginEnabled: launchAtLoginEnabled
            ),
            to: URL(fileURLWithPath: dataDirectoryPath)
        )

        let persistedState = Self.persistedState(
            useDefaultRuntimeCommand: useDefaultRuntimeCommand,
            runtimeExecutable: runtimeExecutable,
            runtimeArguments: runtimeArguments,
            dataDirectoryPath: dataDirectoryPath,
            launchAtLoginEnabled: launchAtLoginEnabled
        )
        persistedUseDefaultRuntimeCommand = persistedState.useDefaultRuntimeCommand
        persistedRuntimeExecutable = persistedState.runtimeExecutable
        persistedRuntimeArguments = persistedState.runtimeArguments
        persistedDataDirectoryPath = persistedState.dataDirectoryPath
        persistedLaunchAtLoginEnabled = persistedState.launchAtLoginEnabled
        return true
    }

    func resetToDefaults() {
        let currentSettings = RuntimeSettingsStore.current()
        useDefaultRuntimeCommand = currentSettings.useDefaultRuntimeCommand
        runtimeExecutable = currentSettings.runtimeExecutable
        runtimeArguments = currentSettings.runtimeArguments
        dataDirectoryPath = currentSettings.dataDirectoryPath
        launchAtLoginEnabled = currentSettings.launchAtLoginEnabled
        let persistedState = Self.persistedState(
            useDefaultRuntimeCommand: useDefaultRuntimeCommand,
            runtimeExecutable: runtimeExecutable,
            runtimeArguments: runtimeArguments,
            dataDirectoryPath: dataDirectoryPath,
            launchAtLoginEnabled: launchAtLoginEnabled
        )
        persistedUseDefaultRuntimeCommand = persistedState.useDefaultRuntimeCommand
        persistedRuntimeExecutable = persistedState.runtimeExecutable
        persistedRuntimeArguments = persistedState.runtimeArguments
        persistedDataDirectoryPath = persistedState.dataDirectoryPath
        persistedLaunchAtLoginEnabled = persistedState.launchAtLoginEnabled
    }

    var hasUnsavedChanges: Bool {
        useDefaultRuntimeCommand != persistedUseDefaultRuntimeCommand
            || runtimeExecutable != persistedRuntimeExecutable
            || runtimeArguments != persistedRuntimeArguments
            || dataDirectoryPath != persistedDataDirectoryPath
            || launchAtLoginEnabled != persistedLaunchAtLoginEnabled
    }

    var runtimeCommandLaunchPreview: String {
        let executable = runtimeExecutable.trimmingCharacters(in: .whitespacesAndNewlines)
        let arguments = runtimeArguments.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !executable.isEmpty else {
            return "Executable: --"
        }
        return arguments.isEmpty
            ? "Executable: \(executable)"
            : "Executable: \(executable) | Arguments: \(arguments)"
    }

    private static func persistedState(
        useDefaultRuntimeCommand: Bool,
        runtimeExecutable: String,
        runtimeArguments: String,
        dataDirectoryPath: String,
        launchAtLoginEnabled: Bool
    ) -> (useDefaultRuntimeCommand: Bool, runtimeExecutable: String, runtimeArguments: String, dataDirectoryPath: String, launchAtLoginEnabled: Bool) {
        (
            useDefaultRuntimeCommand: useDefaultRuntimeCommand,
            runtimeExecutable: runtimeExecutable,
            runtimeArguments: runtimeArguments,
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
                Picker("Runtime Mode", selection: $store.useDefaultRuntimeCommand) {
                    Text("Default").tag(true)
                    Text("Custom").tag(false)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.bottom, 2)
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Executable")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField("/usr/bin/true", text: $store.runtimeExecutable)
                            .disabled(store.useDefaultRuntimeCommand)
                            .textFieldStyle(.roundedBorder)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Arguments")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField("", text: $store.runtimeArguments)
                            .disabled(store.useDefaultRuntimeCommand)
                            .textFieldStyle(.roundedBorder)
                    }
                }
                if !store.useDefaultRuntimeCommand {
                    Text(store.runtimeCommandLaunchPreview)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Text("The default launch now uses a neutral native placeholder. Turn it off only if you need a custom executable and arguments.")
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
