import AppKit
import Foundation
import ServiceManagement
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let processLauncher = ProcessLauncher()
    private lazy var startupCoordinator = StartupCoordinator(readinessURL: RuntimeEndpoints.readinessURL)
    private let runtimeMenuPresenter = RuntimeMenuPresenter()
    private let runtimeAlertPresenter = RuntimeAlertPresenter()
    private let appCommandController = AppCommandController()
    private let appMenuBuilder = AppMenuBuilder()
    private let launchAtLoginController = LaunchAtLoginController()
    let sessionState = AppSessionState()
    let preferencesStore = PreferencesStore()
    private lazy var runtimeLifecycleController = RuntimeLifecycleController(
        processLauncher: processLauncher,
        startupCoordinator: startupCoordinator
    )
    private lazy var appTerminationController = AppTerminationController(
        runtimeLifecycleController: runtimeLifecycleController
    )

    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Starting..."
        sessionState.startupHint = "Preparing native shell..."
        sessionState.preloadMessage = "Loading dashboard..."
        sessionState.showLoadingStrip = true
        setupStatusItem()
        syncLaunchAtLoginState()
        Task { @MainActor in
            await Task.yield()
            self.startRuntimeLifecycle()
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first?.makeKeyAndOrderFront(nil)
        }
        return true
    }

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        guard let button = statusItem?.button else { return }
        button.imagePosition = .imageOnly
        button.toolTip = "NmapUI"

        let runtimeStatusItem = NSMenuItem(title: "Runtime: Starting...", action: nil, keyEquivalent: "")
        runtimeStatusItem.isEnabled = false

        let openItem = NSMenuItem(title: "Starting NmapUI...", action: #selector(openApp), keyEquivalent: "o")
        openItem.isEnabled = false

        let aboutItem = NSMenuItem(title: "About NmapUI", action: #selector(showAbout), keyEquivalent: "")

        let preferencesItem = NSMenuItem(title: "Preferences...", action: #selector(openPreferences), keyEquivalent: ",")

        let restartItem = NSMenuItem(title: "Restart Runtime", action: #selector(restartRuntime), keyEquivalent: "r")

        let dataDirectoryItem = NSMenuItem(title: "Open Data Folder", action: #selector(openDataDirectory), keyEquivalent: "")

        let loginItem = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin), keyEquivalent: "")

        let uninstallItem = NSMenuItem(title: "Uninstall NmapUI", action: #selector(uninstallApp), keyEquivalent: "")

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: "q")

        let menu = appMenuBuilder.buildMenu(
            target: self,
            onRuntimeStatusItem: runtimeStatusItem,
            onOpenItem: openItem,
            onAboutItem: aboutItem,
            onPreferencesItem: preferencesItem,
            onRestartItem: restartItem,
            onDataDirectoryItem: dataDirectoryItem,
            onLaunchAtLoginItem: loginItem,
            onUninstallItem: uninstallItem,
            onQuitItem: quitItem
        )
        statusItem?.menu = menu
        runtimeMenuPresenter.configureStatusItem(
            statusItem,
            runtimeStatusMenuItem: runtimeStatusItem,
            openAppMenuItem: openItem,
            openDataDirectoryMenuItem: dataDirectoryItem,
            restartRuntimeMenuItem: restartItem,
            launchAtLoginMenuItem: loginItem
        )
    }

    private func syncLaunchAtLoginState() {
        launchAtLoginController.syncLaunchAtLoginState(runtimeMenuPresenter)
    }

    @objc private func openApp() {
        appCommandController.openApp()
    }

    @objc private func openPreferences() {
        appCommandController.openPreferences()
    }

    @objc private func showAbout() {
        appCommandController.showAbout()
    }

    @objc func openBrowser() {
        appCommandController.openBrowser()
    }

    @objc func openDataDirectory() {
        appCommandController.openDataDirectory()
    }

    @objc private func restartRuntime() {
        restartRuntimeAfterPreferenceChange()
    }

    @objc func savePreferences() {
        savePreferencesAndRestartRuntimeIfNeeded()
    }

    @objc func resetPreferences() {
        preferencesStore.resetToDefaults()
        restartRuntimeAfterPreferenceChange()
    }

    @objc private func toggleLaunchAtLogin() {
        launchAtLoginController.toggleLaunchAtLogin()
        syncLaunchAtLoginState()
    }

    @objc private func uninstallApp() {
        appTerminationController.uninstallApp()
    }

    @objc private func quitApp() {
        appTerminationController.quitApp()
    }

    @objc func chooseDataDirectory() {
        chooseDataDirectoryForSwiftUI()
    }

    private func savePreferencesAndRestartRuntimeIfNeeded() {
        if preferencesStore.save() {
            restartRuntimeAfterPreferenceChange()
        } else {
            runtimeAlertPresenter.presentPreferencesSaveFailureAlert()
        }
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
        sessionState.runtimeIsReady = true
        sessionState.runtimeStatusText = "Ready"
        sessionState.startupHint = "Ready to scan"
        sessionState.preloadMessage = "Dashboard ready"
        sessionState.showLoadingStrip = false
        syncRuntimeMenuState()
        NSWorkspace.shared.open(RuntimeEndpoints.baseURL)
    }

    private func handleRuntimeLaunchFailure() {
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Error"
        sessionState.startupHint = "Runtime failed to start"
        sessionState.preloadMessage = "Runtime failed to start"
        sessionState.showLoadingStrip = false
        syncRuntimeMenuState()
        runtimeAlertPresenter.presentLaunchFailureAlert()
    }

    private func handleRuntimeStartupTimeout() {
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Waiting"
        sessionState.startupHint = "Backend is still booting"
        sessionState.preloadMessage = "Keeping the shell open"
        sessionState.showLoadingStrip = true
        syncRuntimeMenuState()
        handleRuntimeBrowserOpen()
    }

    private func handleRuntimeExitFinalFailure(terminationStatus: Int32) {
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Error"
        sessionState.startupHint = "Runtime stopped unexpectedly"
        sessionState.preloadMessage = "Runtime stopped unexpectedly"
        sessionState.showLoadingStrip = false
        runtimeAlertPresenter.presentRuntimeExitAlert(terminationStatus: terminationStatus) { [weak self] in
            self?.restartRuntimeAfterPreferenceChange()
        }
    }

    private func handleRuntimeStateChanged() {
        sessionState.runtimeIsReady = runtimeLifecycleController.runtimeIsReady
        sessionState.runtimeStatusText = runtimeLifecycleController.runtimeStatusText
        syncRuntimeMenuState()
    }

    private func syncRuntimeMenuState() {
        runtimeMenuPresenter.syncRuntimeMenuState(
            isReady: runtimeLifecycleController.runtimeIsReady,
            statusText: runtimeLifecycleController.runtimeStatusText
        )
    }

    private func chooseDataDirectoryForSwiftUI() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: preferencesStore.dataDirectoryPath)

        panel.begin { [weak self] response in
            guard response == .OK, let self, let url = panel.url else { return }
            self.preferencesStore.dataDirectoryPath = url.path
        }
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
