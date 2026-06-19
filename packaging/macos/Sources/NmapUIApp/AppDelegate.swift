import AppKit
import Foundation
import ServiceManagement
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let runtimeURL = RuntimeEndpoints.baseURL
    private let processLauncher = ProcessLauncher()
    private lazy var startupCoordinator = StartupCoordinator(readinessURL: RuntimeEndpoints.readinessURL, runtimeURL: runtimeURL)
    private let runtimeMenuPresenter = RuntimeMenuPresenter()
    private let runtimeAlertPresenter = RuntimeAlertPresenter()
    private let appCommandController = AppCommandController(runtimeURL: RuntimeEndpoints.baseURL)
    private let launchAtLoginController = LaunchAtLoginController()
    let preferencesStore = PreferencesStore()
    private lazy var preferencesController = PreferencesController(preferencesStore: preferencesStore)
    private lazy var runtimeLifecycleController = RuntimeLifecycleController(
        processLauncher: processLauncher,
        startupCoordinator: startupCoordinator,
        runtimeURL: runtimeURL
    )

    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        syncLaunchAtLoginState()
        startRuntimeLifecycle()
    }

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        guard let button = statusItem?.button else { return }
        button.imagePosition = .imageOnly
        button.toolTip = "NmapUI"

        let menu = NSMenu()
        let runtimeStatusItem = NSMenuItem(title: "Runtime: Starting...", action: nil, keyEquivalent: "")
        runtimeStatusItem.isEnabled = false
        menu.addItem(runtimeStatusItem)
        menu.addItem(.separator())

        let openItem = NSMenuItem(title: "Starting NmapUI...", action: #selector(openApp), keyEquivalent: "o")
        openItem.target = self
        openItem.isEnabled = false
        menu.addItem(openItem)
        menu.addItem(.separator())

        let preferencesItem = NSMenuItem(title: "Preferences...", action: #selector(openPreferences), keyEquivalent: ",")
        preferencesItem.target = self
        menu.addItem(preferencesItem)
        menu.addItem(.separator())

        let restartItem = NSMenuItem(title: "Restart Runtime", action: #selector(restartRuntime), keyEquivalent: "r")
        restartItem.target = self
        menu.addItem(restartItem)
        menu.addItem(.separator())

        let dataDirectoryItem = NSMenuItem(title: "Open Data Folder", action: #selector(openDataDirectory), keyEquivalent: "")
        dataDirectoryItem.target = self
        menu.addItem(dataDirectoryItem)
        menu.addItem(.separator())

        let loginItem = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin), keyEquivalent: "")
        loginItem.target = self
        menu.addItem(loginItem)
        menu.addItem(.separator())

        let uninstallItem = NSMenuItem(title: "Uninstall NmapUI", action: #selector(uninstallApp), keyEquivalent: "")
        uninstallItem.target = self
        menu.addItem(uninstallItem)

        menu.addItem(withTitle: "Quit", action: #selector(quitApp), keyEquivalent: "q")
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

    @objc private func openDataDirectory() {
        appCommandController.openDataDirectory()
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
        preferencesController.savePreferences()
        restartRuntimeAfterPreferenceChange()
    }

    @objc private func resetPreferences() {
        preferencesController.resetPreferences()
        restartRuntimeAfterPreferenceChange()
    }

    @objc private func toggleLaunchAtLogin() {
        launchAtLoginController.toggleLaunchAtLogin()
        syncLaunchAtLoginState()
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
        runtimeAlertPresenter.presentLaunchFailureAlert()
    }

    private func handleRuntimeStartupTimeout() {
        syncRuntimeMenuState()
        runtimeAlertPresenter.presentStartupTimeoutAlert()
    }

    private func handleRuntimeExitFinalFailure(terminationStatus: Int32) {
        runtimeAlertPresenter.presentRuntimeExitAlert(terminationStatus: terminationStatus) { [weak self] in
            self?.restartRuntimeAfterPreferenceChange()
        }
    }

    private func handleRuntimeStateChanged() {
        syncRuntimeMenuState()
    }

    private func syncRuntimeMenuState() {
        runtimeMenuPresenter.syncRuntimeMenuState(
            isReady: runtimeLifecycleController.runtimeIsReady,
            statusText: runtimeLifecycleController.runtimeStatusText
        )
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
