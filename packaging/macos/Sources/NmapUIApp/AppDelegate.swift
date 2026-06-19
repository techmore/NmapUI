import AppKit
import Foundation
import ServiceManagement
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let runtimeURL = RuntimeEndpoints.baseURL
    private let processLauncher = ProcessLauncher()
    private lazy var startupCoordinator = StartupCoordinator(readinessURL: RuntimeEndpoints.readinessURL, runtimeURL: runtimeURL)
    private lazy var runtimeLifecycleController = RuntimeLifecycleController(
        processLauncher: processLauncher,
        startupCoordinator: startupCoordinator,
        runtimeURL: runtimeURL
    )

    private var statusItem: NSStatusItem?
    private var runtimeStatusMenuItem: NSMenuItem?
    private var openAppMenuItem: NSMenuItem?
    private var openDataDirectoryMenuItem: NSMenuItem?
    private var restartRuntimeMenuItem: NSMenuItem?
    private var launchAtLoginMenuItem: NSMenuItem?

    let preferencesStore = PreferencesStore()

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        syncLaunchAtLoginState()
        startRuntimeLifecycle()
    }

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        guard let button = statusItem?.button else { return }
        updateStatusIcon(isReady: false)
        button.imagePosition = .imageOnly
        button.toolTip = "NmapUI"

        let menu = NSMenu()
        let runtimeStatusItem = NSMenuItem(title: "Runtime: Starting...", action: nil, keyEquivalent: "")
        runtimeStatusItem.isEnabled = false
        menu.addItem(runtimeStatusItem)
        runtimeStatusMenuItem = runtimeStatusItem
        menu.addItem(.separator())

        let openItem = NSMenuItem(title: "Starting NmapUI...", action: #selector(openApp), keyEquivalent: "o")
        openItem.target = self
        openItem.isEnabled = false
        menu.addItem(openItem)
        openAppMenuItem = openItem
        menu.addItem(.separator())

        let preferencesItem = NSMenuItem(title: "Preferences...", action: #selector(openPreferences), keyEquivalent: ",")
        preferencesItem.target = self
        menu.addItem(preferencesItem)
        menu.addItem(.separator())

        let restartItem = NSMenuItem(title: "Restart Runtime", action: #selector(restartRuntime), keyEquivalent: "r")
        restartItem.target = self
        menu.addItem(restartItem)
        restartRuntimeMenuItem = restartItem
        menu.addItem(.separator())

        let dataDirectoryItem = NSMenuItem(title: "Open Data Folder", action: #selector(openDataDirectory), keyEquivalent: "")
        dataDirectoryItem.target = self
        menu.addItem(dataDirectoryItem)
        openDataDirectoryMenuItem = dataDirectoryItem
        menu.addItem(.separator())

        let loginItem = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin), keyEquivalent: "")
        loginItem.target = self
        menu.addItem(loginItem)
        launchAtLoginMenuItem = loginItem
        menu.addItem(.separator())

        let uninstallItem = NSMenuItem(title: "Uninstall NmapUI", action: #selector(uninstallApp), keyEquivalent: "")
        uninstallItem.target = self
        menu.addItem(uninstallItem)

        menu.addItem(withTitle: "Quit", action: #selector(quitApp), keyEquivalent: "q")
        statusItem?.menu = menu
    }

    private func syncLaunchAtLoginState() {
        guard #available(macOS 13.0, *) else {
            launchAtLoginMenuItem?.isEnabled = false
            launchAtLoginMenuItem?.state = .off
            return
        }
        launchAtLoginMenuItem?.state = SMAppService.mainApp.status == .enabled ? .on : .off
    }

    @objc private func openApp() {
        NSWorkspace.shared.open(runtimeURL)
    }

    @objc private func openPreferences() {
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func openDataDirectory() {
        NSWorkspace.shared.activateFileViewerSelecting([ProcessLauncher.currentDataDirectoryURL()])
    }

    func openDataDirectoryFromSwiftUI() {
        openDataDirectory()
    }

    @objc private func restartRuntime() {
        restartRuntimeAfterPreferenceChange()
    }

    func savePreferencesFromSwiftUI() {
        savePreferences()
    }

    func resetPreferencesFromSwiftUI() {
        resetPreferences()
    }

    @objc private func savePreferences() {
        preferencesStore.save()
        restartRuntimeAfterPreferenceChange()
    }

    @objc private func resetPreferences() {
        preferencesStore.clearPersistedValues()
        preferencesStore.resetToDefaults()
        restartRuntimeAfterPreferenceChange()
    }

    @objc private func toggleLaunchAtLogin() {
        guard #available(macOS 13.0, *) else { return }
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
            syncLaunchAtLoginState()
        } catch {
            NSLog("Failed to toggle launch at login: \(error.localizedDescription)")
        }
    }

    @objc private func uninstallApp() {
        runtimeLifecycleController.stopForQuitOrUninstall()
        if #available(macOS 13.0, *) {
            try? SMAppService.mainApp.unregister()
        }
        let bundleURL = Bundle.main.bundleURL
        NSWorkspace.shared.recycle([bundleURL]) { _, _ in
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
    }

    @objc private func quitApp() {
        runtimeLifecycleController.stopForQuitOrUninstall()
        NSApp.terminate(nil)
    }

    private func restartRuntimeAfterPreferenceChange() {
        runtimeLifecycleController.restartAfterPreferenceChange(
            onBrowserOpen: { [weak self] in self?.handleRuntimeBrowserOpen() },
            onLaunchFailure: { [weak self] in self?.handleRuntimeLaunchFailure() },
            onStartupTimeout: { [weak self] in self?.handleRuntimeStartupTimeout() },
            onRuntimeExitFinalFailure: { [weak self] terminationStatus in
                self?.handleRuntimeExitFinalFailure(terminationStatus: terminationStatus)
            },
            onStateChanged: { [weak self] in self?.handleRuntimeStateChanged() }
        )
    }

    private func startRuntimeLifecycle() {
        runtimeLifecycleController.start(
            onBrowserOpen: { [weak self] in self?.handleRuntimeBrowserOpen() },
            onLaunchFailure: { [weak self] in self?.handleRuntimeLaunchFailure() },
            onStartupTimeout: { [weak self] in self?.handleRuntimeStartupTimeout() },
            onRuntimeExitFinalFailure: { [weak self] terminationStatus in
                self?.handleRuntimeExitFinalFailure(terminationStatus: terminationStatus)
            },
            onStateChanged: { [weak self] in self?.handleRuntimeStateChanged() }
        )
    }

    private func handleRuntimeBrowserOpen() {
        syncRuntimeMenuState()
        NSWorkspace.shared.open(runtimeURL)
    }

    private func handleRuntimeLaunchFailure() {
        syncRuntimeMenuState()
        presentRuntimeLaunchFailureAlert()
    }

    private func handleRuntimeStartupTimeout() {
        syncRuntimeMenuState()
        presentRuntimeStartupTimeoutAlert()
    }

    private func handleRuntimeExitFinalFailure(terminationStatus: Int32) {
        presentRuntimeExitAlert(terminationStatus: terminationStatus)
    }

    private func handleRuntimeStateChanged() {
        syncRuntimeMenuState()
    }

    private func presentRuntimeLaunchFailureAlert() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "NmapUI could not start the runtime"
        alert.informativeText = "Check the runtime command and make sure the app can bind the fixed port."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func presentRuntimeStartupTimeoutAlert() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "NmapUI is still starting"
        alert.informativeText = "The runtime did not become ready in time. Keep the app open and use Restart Runtime from the menu if you need another startup attempt."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func presentRuntimeExitAlert(terminationStatus: Int32) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "NmapUI runtime stopped"
        alert.informativeText = "The backend exited with status \(terminationStatus). Restart the runtime from the menu if you want another attempt."
        alert.addButton(withTitle: "Restart Runtime")
        alert.addButton(withTitle: "OK")

        if alert.runModal() == .alertFirstButtonReturn {
            restartRuntimeAfterPreferenceChange()
        }
    }

    private func syncRuntimeMenuState() {
        runtimeStatusMenuItem?.title = "Runtime: \(runtimeLifecycleController.runtimeStatusText)"
        openAppMenuItem?.title = runtimeLifecycleController.runtimeIsReady ? "Open App" : "Starting NmapUI..."
        openAppMenuItem?.isEnabled = runtimeLifecycleController.runtimeIsReady
        restartRuntimeMenuItem?.isEnabled = true
        openDataDirectoryMenuItem?.isEnabled = true
        updateStatusIcon(isReady: runtimeLifecycleController.runtimeIsReady)
    }

    private func updateStatusIcon(isReady: Bool) {
        guard let button = statusItem?.button else { return }
        let symbolName = isReady ? "network" : "hourglass"
        let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: "NmapUI")
        image?.isTemplate = true
        button.image = image
        button.contentTintColor = isReady ? .controlAccentColor : .secondaryLabelColor
    }
}

final class ProcessLauncher {
    private let runtimeCommand: String
    private let runtimeWorkDir: URL
    private let runtimeDataDir: URL

    init() {
        let environment = ProcessInfo.processInfo.environment
        if let persistedCommand = UserDefaults.standard.string(forKey: PreferencesKeys.runtimeCommand), !persistedCommand.isEmpty {
            runtimeCommand = persistedCommand
        } else {
            runtimeCommand = environment["NMAPUI_RUNTIME_COMMAND"] ?? "node server.js"
        }

        if let persistedWorkDir = environment["NMAPUI_RUNTIME_WORKDIR"], !persistedWorkDir.isEmpty {
            runtimeWorkDir = URL(fileURLWithPath: persistedWorkDir)
        } else {
            runtimeWorkDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        }

        if let persistedDataDir = UserDefaults.standard.string(forKey: PreferencesKeys.dataDirectory), !persistedDataDir.isEmpty {
            runtimeDataDir = URL(fileURLWithPath: persistedDataDir)
        } else if let explicitDataDir = environment["NMAPUI_DATA_DIR"], !explicitDataDir.isEmpty {
            runtimeDataDir = URL(fileURLWithPath: explicitDataDir)
        } else {
            runtimeDataDir = Self.defaultDataDirectory()
        }
    }

    func launchRuntimeIfNeeded() -> Process? {
        let process = Process()
        process.currentDirectoryURL = runtimeWorkDir
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-lc", runtimeCommand]
        process.environment = [
            "HOST": RuntimeEndpoints.host,
            "PORT": RuntimeEndpoints.fixedPortString,
            "NMAPUI_PORT": RuntimeEndpoints.fixedPortString,
            "NMAPUI_RUNTIME_WORKDIR": runtimeWorkDir.path,
            "NMAPUI_DATA_DIR": runtimeDataDir.path,
            "PATH": ProcessInfo.processInfo.environment["PATH"] ?? ""
        ]

        do {
            try process.run()
            return process
        } catch {
            NSLog("Failed to launch runtime: \(error.localizedDescription)")
            return nil
        }
    }

    func stop(runtimeProcess: Process?) {
        guard let runtimeProcess else { return }
        if runtimeProcess.isRunning {
            runtimeProcess.terminate()
        }
    }

    static func waitForRuntime(url: URL, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        let session = URLSession(configuration: .ephemeral)
        while Date() < deadline {
            do {
                let (_, response) = try await session.data(from: url)
                if let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) {
                    return true
                }
            } catch {
                // Keep polling until timeout.
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        return false
    }

    private static func defaultDataDirectory() -> URL {
        let fileManager = FileManager.default
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
        let dataDir = appSupport.appendingPathComponent("NmapUI", isDirectory: true)
        try? fileManager.createDirectory(at: dataDir, withIntermediateDirectories: true)
        return dataDir
    }

    static func currentRuntimeCommand() -> String {
        UserDefaults.standard.string(forKey: PreferencesKeys.runtimeCommand) ?? "node server.js"
    }

    static func currentDataDirectory() -> String {
        currentDataDirectoryURL().path
    }

    static func currentDataDirectoryURL() -> URL {
        if let persistedDataDir = UserDefaults.standard.string(forKey: PreferencesKeys.dataDirectory), !persistedDataDir.isEmpty {
            return URL(fileURLWithPath: persistedDataDir)
        }
        return defaultDataDirectory()
    }

    static func isLaunchAtLoginEnabled() -> Bool {
        guard #available(macOS 13.0, *) else { return false }
        return SMAppService.mainApp.status == .enabled
    }
}
