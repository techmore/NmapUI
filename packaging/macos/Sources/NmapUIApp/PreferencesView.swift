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
    @Published var autoOpenScheduledReports: Bool
    private var persistedUseDefaultRuntimeCommand: Bool
    private var persistedRuntimeExecutable: String
    private var persistedRuntimeArguments: String
    private var persistedDataDirectoryPath: String
    private var persistedLaunchAtLoginEnabled: Bool
    private var persistedAutoOpenScheduledReports: Bool

    init() {
        let loadedSettings = RuntimeSettingsStore.load(from: RuntimeSettingsStore.currentDataDirectoryURL())
        let currentSettings = RuntimeSettingsStore.current()
        let useDefaultRuntimeCommand = loadedSettings?.useDefaultRuntimeCommand ?? currentSettings.useDefaultRuntimeCommand
        let runtimeExecutable = loadedSettings?.runtimeExecutable ?? currentSettings.runtimeExecutable
        let runtimeArguments = loadedSettings?.runtimeArguments ?? currentSettings.runtimeArguments
        let dataDirectoryPath = loadedSettings?.dataDirectoryPath ?? currentSettings.dataDirectoryPath
        let launchAtLoginEnabled = loadedSettings?.launchAtLoginEnabled ?? currentSettings.launchAtLoginEnabled
        let configURL = URL(fileURLWithPath: dataDirectoryPath).appendingPathComponent("config.json")
        let config = (try? Data(contentsOf: configURL)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        let autoOpenScheduledReports = ((config?["reportBehavior"] as? [String: Any])?["autoOpenScheduledReports"] as? Bool) ?? false
        self.useDefaultRuntimeCommand = useDefaultRuntimeCommand
        self.runtimeExecutable = runtimeExecutable
        self.runtimeArguments = runtimeArguments
        self.dataDirectoryPath = dataDirectoryPath
        self.launchAtLoginEnabled = launchAtLoginEnabled
        self.autoOpenScheduledReports = autoOpenScheduledReports
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
        persistedAutoOpenScheduledReports = autoOpenScheduledReports
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
        RuntimeMetadataStore.persistConfigSection(
            "reportBehavior",
            values: ["autoOpenScheduledReports": .bool(autoOpenScheduledReports)],
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
        persistedAutoOpenScheduledReports = autoOpenScheduledReports
        return true
    }

    func resetToDefaults() {
        let currentSettings = RuntimeSettingsStore.current()
        useDefaultRuntimeCommand = currentSettings.useDefaultRuntimeCommand
        runtimeExecutable = currentSettings.runtimeExecutable
        runtimeArguments = currentSettings.runtimeArguments
        dataDirectoryPath = currentSettings.dataDirectoryPath
        launchAtLoginEnabled = currentSettings.launchAtLoginEnabled
        autoOpenScheduledReports = false
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
        persistedAutoOpenScheduledReports = autoOpenScheduledReports
    }

    var hasUnsavedChanges: Bool {
        useDefaultRuntimeCommand != persistedUseDefaultRuntimeCommand
            || runtimeExecutable != persistedRuntimeExecutable
            || runtimeArguments != persistedRuntimeArguments
            || dataDirectoryPath != persistedDataDirectoryPath
            || launchAtLoginEnabled != persistedLaunchAtLoginEnabled
            || autoOpenScheduledReports != persistedAutoOpenScheduledReports
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
    @ObservedObject var sessionState: AppSessionState
    let onChooseFolder: () -> Void
    let onRevealFolder: () -> Void
    let onSave: () -> Void
    let onReset: () -> Void
    let onConnectGoogleDrive: () -> Void
    let onDisconnectGoogleDrive: () -> Void
    let onSaveGoogleDriveSettings: (Bool, String) -> Void
    let onSaveGoogleDriveCredentials: (String) -> Void
    @State private var showingResetConfirmation = false
    @State private var copiedPathConfirmation = false
    @State private var copiedPathHideWorkItem: DispatchWorkItem?
    @State private var googleDriveEnabled = false
    @State private var googleDriveFolderID = ""
    @State private var googleDriveCredentialsJSON = ""
    @State private var googleDriveStatus: GoogleDriveService.Status?
    @State private var showingCredentialEditor = false

    var body: some View {
        ScrollView {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Native execution")
                    .font(.headline)
                Text("The dashboard, scans, reports, and integrations run through the Swift-native implementation. Legacy runtime command settings remain stored only for migration compatibility.")
                    .font(.callout)
                    .foregroundStyle(NativePalette.olive600)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Data Directory")
                    .font(.headline)
                HStack(spacing: 10) {
                    Text(store.dataDirectoryPath)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(NativePalette.olive500)
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
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.olive500, hoverFill: NativePalette.olive600, text: .white))
                    Button("Reveal in Finder", action: onRevealFolder)
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.olive500, hoverFill: NativePalette.olive600, text: .white))
                    if copiedPathConfirmation {
                        Text("Copied")
                            .font(.caption)
                            .foregroundStyle(NativePalette.emerald600)
                    }
                }
                Text("Choose a writable folder for reports and app state.")
                    .font(.caption)
                    .foregroundStyle(NativePalette.olive600)
            }

            Toggle("Open HTML and PDF after scheduled scans", isOn: $store.autoOpenScheduledReports)
                .toggleStyle(OliveToggleStyle())
                .foregroundStyle(NativePalette.olive700)
            Text("Off by default so unattended scans do not interrupt your work.")
                .font(.caption)
                .foregroundStyle(NativePalette.olive600)

            Toggle("Launch at Login", isOn: $store.launchAtLoginEnabled)
                .toggleStyle(OliveToggleStyle())
                .foregroundStyle(NativePalette.olive700)

            Divider()
            googleDriveSection

            HStack {
                Button("Reset to Defaults") {
                    showingResetConfirmation = true
                }
                .buttonStyle(OliveButtonStyle(fill: NativePalette.olive100, hoverFill: NativePalette.red50, text: NativePalette.olive700, hoverText: NativePalette.red600))
                Spacer()
                Button("Save") {
                    onSave()
                }
                .disabled(!store.hasUnsavedChanges)
                .keyboardShortcut(.defaultAction)
                .buttonStyle(OliveButtonStyle(fill: NativePalette.olive600, hoverFill: NativePalette.olive700, text: .white))
            }
            if store.hasUnsavedChanges {
                Text("You have unsaved changes.")
                    .font(.caption)
                    .foregroundStyle(NativePalette.amber700)
            }
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
        .onAppear { refreshGoogleDriveState() }
        .onChange(of: sessionState.runtimeGoogleDriveSnapshot.enabled) { _ in refreshGoogleDriveState() }
        .onChange(of: sessionState.runtimeGoogleDriveSnapshot.folderId) { _ in refreshGoogleDriveState() }
        .padding(20)
        .frame(width: 620, height: 680)
        .foregroundStyle(NativePalette.body)
        .tint(NativePalette.olive600)
        .background(NativePalette.olive50)
        .environment(\.colorScheme, .light)
    }

    private var googleDriveSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Google Drive Sync").font(.headline)
                    Text("Upload completed HTML, PDF, and XML reports to Google Drive.")
                        .font(.caption)
                        .foregroundStyle(NativePalette.olive600)
                }
                Spacer()
                Label(
                    googleDriveStatus?.connected == true ? "Connected" : (googleDriveStatus?.configured == true ? "Configured" : "Not configured"),
                    systemImage: googleDriveStatus?.connected == true ? "checkmark.circle.fill" : "exclamationmark.circle"
                )
                .font(.caption.weight(.bold))
                .foregroundStyle(googleDriveStatus?.connected == true ? NativePalette.emerald600 : NativePalette.amber700)
            }

            Toggle("Sync reports after successful scans", isOn: $googleDriveEnabled)
                .toggleStyle(OliveToggleStyle())
                .onChange(of: googleDriveEnabled) { enabled in
                    onSaveGoogleDriveSettings(enabled, googleDriveFolderID)
                }

            VStack(alignment: .leading, spacing: 5) {
                Text("Destination folder ID (optional)").font(.caption.weight(.semibold))
                TextField("Leave blank to use the integration's default folder", text: $googleDriveFolderID)
                    .oliveField()
                    .onSubmit { onSaveGoogleDriveSettings(googleDriveEnabled, googleDriveFolderID) }
                Text("Use the value after `/folders/` in a Google Drive folder URL.")
                    .font(.caption2)
                    .foregroundStyle(NativePalette.olive600)
            }

            HStack {
                if googleDriveStatus?.connected == true {
                    Button("Disconnect", action: onDisconnectGoogleDrive)
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.red50, hoverFill: NativePalette.olive100, text: NativePalette.red600))
                } else {
                    Button("Connect Google Drive", action: onConnectGoogleDrive)
                        .buttonStyle(OliveButtonStyle(fill: NativePalette.olive600, hoverFill: NativePalette.olive700, text: .white))
                        .disabled(googleDriveStatus?.configured != true)
                }
                Button("Refresh Status") { refreshGoogleDriveState() }
                Spacer()
                Button(showingCredentialEditor ? "Hide OAuth Setup" : "OAuth Setup") {
                    showingCredentialEditor.toggle()
                }
            }

            if let status = googleDriveStatus {
                Text(status.error ?? status.status)
                    .font(.caption)
                    .foregroundStyle(status.success ? NativePalette.olive600 : NativePalette.red600)
            }

            if showingCredentialEditor {
                VStack(alignment: .leading, spacing: 7) {
                    Text("Google OAuth client JSON").font(.caption.weight(.semibold))
                    Text("Paste the downloaded Desktop OAuth client JSON. It is stored owner-readable in the app data directory and is never written to the repository.")
                        .font(.caption2)
                        .foregroundStyle(NativePalette.olive600)
                    TextEditor(text: $googleDriveCredentialsJSON)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 110)
                        .padding(6)
                        .background(NativePalette.white)
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(NativePalette.olive300))
                    Button("Save OAuth Credentials") {
                        onSaveGoogleDriveCredentials(googleDriveCredentialsJSON)
                        googleDriveCredentialsJSON = ""
                        refreshGoogleDriveState()
                    }
                    .disabled(googleDriveCredentialsJSON.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }

    private func refreshGoogleDriveState() {
        googleDriveEnabled = sessionState.runtimeGoogleDriveSnapshot.enabled
        googleDriveFolderID = sessionState.runtimeGoogleDriveSnapshot.folderId
        googleDriveStatus = GoogleDriveService.status(dataDirectory: RuntimeSettingsStore.currentDataDirectoryURL())
    }
}

private extension View {
    func oliveField() -> some View {
        self
            .textFieldStyle(.plain)
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .foregroundStyle(NativePalette.olive900)
            .background(NativePalette.white)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).stroke(NativePalette.olive300, lineWidth: 1))
    }
}
