import AppKit
import Foundation
import ServiceManagement
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let runtimeURL = RuntimeEndpoints.baseURL
    private let processLauncher = ProcessLauncher()
    private lazy var startupCoordinator = StartupCoordinator(readinessURL: RuntimeEndpoints.readinessURL, runtimeURL: runtimeURL)

    private var statusItem: NSStatusItem?
    private var runtimeStatusMenuItem: NSMenuItem?
    private var openAppMenuItem: NSMenuItem?
    private var openDataDirectoryMenuItem: NSMenuItem?
    private var restartRuntimeMenuItem: NSMenuItem?
    private var launchAtLoginMenuItem: NSMenuItem?

    private var runtimeProcess: Process?
    private var runtimeStopRequested = false
    private var runtimeAutoRestartAttempted = false
    private var runtimeStatusText = "Starting..."
    private var runtimeIsReady = false
    let preferencesStore = PreferencesStore()

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        syncLaunchAtLoginState()
        runtimeProcess = processLauncher.launchRuntimeIfNeeded()
        if runtimeProcess == nil {
            runtimeStatusText = "Error"
            syncRuntimeMenuState()
            presentRuntimeLaunchFailureAlert()
        } else {
            attachRuntimeTerminationHandler()
        }
        beginRuntimeStartupWatch()
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

    private func beginRuntimeStartupWatch() {
        startupCoordinator.begin()
        Task { [weak self] in
            guard let self else { return }
            let result = await self.startupCoordinator.observeStartup()
            guard let result else { return }
            switch result {
            case .ready:
                self.runtimeIsReady = true
                self.runtimeStatusText = "Ready"
                self.runtimeAutoRestartAttempted = false
                self.syncRuntimeMenuState()
                NSWorkspace.shared.open(self.runtimeURL)
            case .timeout:
                self.runtimeIsReady = false
                self.runtimeStatusText = "Starting..."
                self.syncRuntimeMenuState()
                self.presentRuntimeStartupTimeoutAlert()
            }
        }
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
        runtimeStopRequested = true
        stopRuntimeProcess()
        if #available(macOS 13.0, *) {
            try? SMAppService.mainApp.unregister()
        }
        let bundleURL = Bundle.main.bundleURL
        NSWorkspace.shared.recycle([bundleURL]) { _, _ in
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
    }

    @objc private func quitApp() {
        runtimeStopRequested = true
        stopRuntimeProcess()
        NSApp.terminate(nil)
    }

    private func stopRuntimeProcess() {
        processLauncher.stop(runtimeProcess: runtimeProcess)
        runtimeProcess = nil
    }

    private func restartRuntimeAfterPreferenceChange() {
        runtimeStopRequested = true
        stopRuntimeProcess()
        runtimeIsReady = false
        runtimeAutoRestartAttempted = false
        runtimeStatusText = "Starting..."
        syncRuntimeMenuState()

        runtimeProcess = processLauncher.launchRuntimeIfNeeded()
        if runtimeProcess == nil {
            runtimeStatusText = "Error"
            syncRuntimeMenuState()
            presentRuntimeLaunchFailureAlert()
        } else {
            attachRuntimeTerminationHandler()
        }

        runtimeStopRequested = false
        beginRuntimeStartupWatch()
    }

    private func attachRuntimeTerminationHandler() {
        runtimeProcess?.terminationHandler = { [weak self] process in
            Task { @MainActor in
                self?.handleRuntimeExit(terminationStatus: process.terminationStatus)
            }
        }
    }

    private func handleRuntimeExit(terminationStatus: Int32) {
        runtimeProcess = nil
        runtimeIsReady = false
        runtimeStatusText = "Error"
        syncRuntimeMenuState()

        guard !runtimeStopRequested else { return }

        if !runtimeAutoRestartAttempted {
            runtimeAutoRestartAttempted = true
            runtimeStatusText = "Restarting..."
            syncRuntimeMenuState()
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                self?.restartRuntimeAfterPreferenceChange()
            }
            return
        }

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

    private func syncRuntimeMenuState() {
        runtimeStatusMenuItem?.title = "Runtime: \(runtimeStatusText)"
        openAppMenuItem?.title = runtimeIsReady ? "Open App" : "Starting NmapUI..."
        openAppMenuItem?.isEnabled = runtimeIsReady
        restartRuntimeMenuItem?.isEnabled = true
        openDataDirectoryMenuItem?.isEnabled = true
        updateStatusIcon(isReady: runtimeIsReady)
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
