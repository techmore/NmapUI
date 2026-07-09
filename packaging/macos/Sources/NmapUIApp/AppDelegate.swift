import AppKit
import Foundation
import ServiceManagement
import SwiftUI
import RuntimeContracts

private extension String {
    var nilIfEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let processLauncher = ProcessLauncher()
    private lazy var scanCoordinator = ScanCoordinator()
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
    private let reportRefreshMonitor = RuntimeReportRefreshMonitor()
    private lazy var appTerminationController = AppTerminationController(
        runtimeLifecycleController: runtimeLifecycleController
    )

    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        if ScheduledScanRunner.isScheduledScanInvocation {
            NSApp.setActivationPolicy(.prohibited)
            Task {
                await ScheduledScanRunner.runAndExit()
            }
            return
        }

        NSApp.setActivationPolicy(.regular)
        // App stays a normal user process. Privileged nmap runs via helper when needed.
        _ = PrivilegeElevationController.relaunchAsRootIfNeeded()
        RuntimeDiagnosticsLogger.log(
            "Application did finish launching as user euid=\(geteuid()) helperReady=\(PrivilegeHelperClient.isHelperReachable)"
        )
        let fallbackIdentity = RuntimeIdentity.localFallback(version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown")
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        RuntimeDiagnosticsLogger.configure(dataDirectory: dataDirectory)
        try? FileManager.default.createDirectory(
            at: RuntimeSettingsStore.currentRuntimeWorkDirectoryURL(),
            withIntermediateDirectories: true
        )
        Self.copyBundledStylesheetIfNeeded()
        RuntimeDiagnosticsLogger.log("Application did finish launching")
        let startupIdentity = RuntimeMetadataStore.loadIdentity(from: dataDirectory) ?? fallbackIdentity
        let capabilities = RuntimeMetadataStore.loadCapabilities(from: dataDirectory) ?? RuntimeCapabilities.current()
        let toolchain = RuntimeMetadataStore.loadToolchain(from: dataDirectory) ?? RuntimeToolchain.current()
        let networkState = RuntimeMetadataStore.loadNetworkState(from: dataDirectory)
        sessionState.updateBootstrapSnapshot(
            runtimeIdentity: startupIdentity,
            runtimeCapabilities: capabilities,
            runtimeToolchain: toolchain,
            runtimeNetworkState: networkState,
            runtimeCustomerProfile: RuntimeMetadataStore.loadCustomerProfile(from: dataDirectory)
                ?? RuntimeCustomerProfile.current(
                    prefix: RuntimeMetadataStore.loadCustomerProfilePrefix(from: dataDirectory),
                    networkState: networkState
                )
        )
        sessionState.refreshDataSnapshot(from: dataDirectory)
        sessionState.refreshAutoScanSnapshot(from: dataDirectory, fallbackTarget: networkState?.cidr ?? "192.168.1.0/24")
        sessionState.refreshGoogleDriveSnapshot(from: dataDirectory)
        sessionState.refreshCustomerProfileSnapshot(from: dataDirectory, networkState: networkState)
        RuntimeMetadataStore.persistIdentity(startupIdentity, to: dataDirectory)
        RuntimeMetadataStore.persistCapabilities(capabilities, to: dataDirectory)
        RuntimeMetadataStore.persistToolchain(toolchain, to: dataDirectory)
        Task {
            let freshNetworkState = await RuntimeNetworkState.current()
            await MainActor.run {
                RuntimeDiagnosticsLogger.log("Network state resolved localIP=\(freshNetworkState.localIP) mask=\(freshNetworkState.mask) cidr=\(freshNetworkState.cidr) publicIP=\(freshNetworkState.publicIP) hops=\(freshNetworkState.tracerouteHops.count)")
                let refreshedCustomerProfile = RuntimeCustomerProfile.current(
                    prefix: RuntimeMetadataStore.loadCustomerProfilePrefix(from: dataDirectory),
                    networkState: freshNetworkState
                )
                self.sessionState.updateBootstrapSnapshot(
                    runtimeIdentity: self.sessionState.runtimeIdentity,
                    runtimeCapabilities: self.sessionState.runtimeCapabilities,
                    runtimeToolchain: self.sessionState.runtimeToolchain,
                    runtimeNetworkState: freshNetworkState,
                    runtimeCustomerProfile: refreshedCustomerProfile
                )
                self.sessionState.refreshAutoScanSnapshot(from: dataDirectory, fallbackTarget: freshNetworkState.cidr)
                self.sessionState.refreshCustomerProfileSnapshot(from: dataDirectory, networkState: freshNetworkState)
                self.sessionState.emitInitialData()
                self.sessionState.emitSyncState(
                    version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
                    hosts: []
                )
                self.sessionState.emitTracerouteHops()
                self.sessionState.emitAutoScanConfig()
                self.sessionState.emitCustomerProfile()
                self.emitCurrentRuntimeSnapshotToWebView()
            }
            RuntimeMetadataStore.persistNetworkState(freshNetworkState, to: dataDirectory)
            if let runtimeCustomerProfile = self.sessionState.runtimeCustomerProfile {
                RuntimeMetadataStore.persistCustomerProfile(runtimeCustomerProfile, to: dataDirectory)
            }
        }
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Starting..."
        sessionState.startupHint = "Preparing native shell..."
        sessionState.preloadMessage = "Loading dashboard..."
        sessionState.showLoadingStrip = true
        sessionState.emitBootstrapState(
            version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            hosts: []
        )
        sessionState.emitHistoryData()
        sessionState.emitReportsData()
        sessionState.emitAutoScanConfig()
        sessionState.emitGoogleDriveStatus()
        sessionState.emitCustomerProfile()
        // Re-sync LaunchAgent if auto-scan was already enabled.
        if sessionState.runtimeAutoScanSnapshot.enabled {
            AutoScanScheduler.sync(
                enabled: true,
                recurrence: sessionState.runtimeAutoScanSnapshot.recurrence,
                startTime: sessionState.runtimeAutoScanSnapshot.startTime
            )
        }
        reportRefreshMonitor.start(dataDirectory: dataDirectory) { [weak self] in
            self?.sessionState.emitReportsRefresh()
        }
        sessionState.clearScanSession()
        setupStatusItem()
        syncLaunchAtLoginState()
        NotificationCenter.default.addObserver(
            forName: .runtimeBridgeDidResolveIdentity,
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard let self, let identity = note.object as? RuntimeIdentity else { return }
            Task { @MainActor in
                self.sessionState.runtimeIdentity = identity
                self.sessionState.runtimeCapabilities = RuntimeCapabilities.current()
            }
        }
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
        Task { [weak self] in
            guard let self else { return }
            RuntimeDiagnosticsLogger.log("Preparing runtime lifecycle start")
            await RuntimeBridge.performStartupMaintenance()
            _ = await RuntimeBridge.stopExistingListenerOnPort(RuntimeEndpoints.port)
            _ = await RuntimeBridge.waitForPortToClear(
                host: RuntimeEndpoints.host,
                port: UInt16(RuntimeEndpoints.port),
                timeout: 5
            )
            await MainActor.run {
                RuntimeDiagnosticsLogger.log("Starting runtime process")
                self.runtimeLifecycleController.start(
                    onBrowserOpen: { [weak self] in self?.handleRuntimeBrowserOpen() },
                    onLaunchFailure: { [weak self] in self?.handleRuntimeLaunchFailure() },
                    onStartupTimeout: { [weak self] in self?.handleRuntimeStartupTimeout() },
                    onRuntimeExitFinalFailure: { [weak self] terminationStatus in
                        self?.handleRuntimeExitFinalFailure(terminationStatus: terminationStatus)
                    },
                    onStateChanged: { [weak self] in self?.handleRuntimeStateChanged() }
                )
            }
        }
    }

    func startQuickScanFromNativeShell() {
        let target = sessionState.runtimeNetworkState?.cidr
            ?? sessionState.runtimeAutoScanSnapshot.target.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            ?? "192.168.1.0/24"
        startScanFromNativeShell(target: target, scanKind: "quick", vpnHelper: false)
    }

    func startScanFromNativeShell(target: String, scanKind: String, vpnHelper: Bool) {
        let normalizedTarget = normalizedScanTarget(target)
        RuntimeDiagnosticsLogger.log("Native scan requested target=\(normalizedTarget) scanKind=\(scanKind) vpnHelper=\(vpnHelper)")
        Task { [weak self] in
            guard let self else { return }
            _ = await self.startSwiftManagedScan(
                target: normalizedTarget,
                usePn: false,
                vpnHelper: vpnHelper,
                scanKind: scanKind
            )
        }
    }

    func startSwiftManagedScan(target: String, usePn: Bool, vpnHelper: Bool, scanKind: String) async -> ScanCoordinator.ScanResult {
        let normalizedTarget = normalizedScanTarget(target)
        RuntimeDiagnosticsLogger.log(
            "Starting scan target=\(normalizedTarget) scanKind=\(scanKind) usePn=\(usePn) vpnHelper=\(vpnHelper) euid=\(geteuid()) helperReady=\(PrivilegeHelperClient.isHelperReachable)"
        )
        let request = ScanCoordinator.ScanRequest(
            target: normalizedTarget,
            usePn: usePn,
            vpnHelper: vpnHelper,
            scanKind: ScanCoordinator.ScanKind(scanKind),
            allowInteractivePrivilegePrompt: true
        )
        sessionState.updateScanSession(
            scanStartTime: ISO8601DateFormatter().string(from: Date()),
            currentScanPhase: 1,
            currentTarget: normalizedTarget,
            currentScanKind: scanKind
        )
        sessionState.eventRouter.emitScanLifecycle(
            phase: 1,
            target: normalizedTarget,
            startTime: sessionState.runtimeScanSession.scanStartTime,
            scanKind: scanKind
        )
        let result = await scanCoordinator.runFullScan(request)
        if let summary = result.summary {
            RuntimeDiagnosticsLogger.log("Scan phase \(result.phase.rawValue) completed hosts=\(summary.hostCount) openPorts=\(summary.openPortCount)")
        } else {
            RuntimeDiagnosticsLogger.log("Scan phase \(result.phase.rawValue) completed without summary error=\(result.error ?? "none")")
        }
        if let summary = result.summary {
            sessionState.eventRouter.emitPhaseStats(phase: result.phase.rawValue, summary: summary)
        }

        let shouldGenerateReport = result.completed
            && result.xmlPath != nil
            && (scanKind == "complete" || scanKind == "dragnet")
            && result.phase != .phase1
        if shouldGenerateReport, let xmlPath = result.xmlPath {
            await generateAndPublishReport(
                xmlPath: xmlPath,
                target: normalizedTarget,
                duration: result.duration,
                hostCount: result.summary?.hostCount ?? 0,
                scanKind: scanKind,
                status: "success",
                error: nil
            )
        }

        sessionState.emitScanComplete(
            phase: result.phase.rawValue,
            duration: result.duration,
            hostCount: result.summary?.hostCount,
            openPortCount: result.summary?.openPortCount,
            criticalCVECount: result.summary?.criticalCVECount,
            lowCVECount: result.summary?.lowCVECount,
            status: result.completed ? "success" : (result.error == "Scan cancelled" ? "cancelled" : "failed")
        )
        sessionState.clearScanSession()
        sessionState.emitSyncState(
            version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            hosts: result.summary?.hosts ?? []
        )
        sessionState.refreshDataSnapshot(from: RuntimeSettingsStore.currentDataDirectoryURL())
        sessionState.emitHistoryData()
        sessionState.emitReportsData()
        emitPrivilegeHelperStatus()
        return result
    }

    func generateAndPublishReport(
        xmlPath: URL,
        target: String,
        duration: String,
        hostCount: Int,
        scanKind: String,
        status: String,
        error: String?
    ) async {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        let profile = sessionState.runtimeCustomerProfile
            ?? RuntimeCustomerProfile.current(
                prefix: sessionState.runtimeCustomerProfileSnapshot.prefix,
                networkState: sessionState.runtimeNetworkState
            )
        do {
            let generated = try ReportGenerator.generate(
                xmlSource: xmlPath,
                dataDirectory: dataDirectory,
                customerProfile: profile,
                target: target,
                duration: duration,
                hostCount: hostCount,
                scanKind: scanKind,
                status: status,
                error: error
            )
            RuntimeDiagnosticsLogger.log("Report generated html=\(generated.htmlURL.path) pdf=\(generated.pdfURL?.path ?? "none")")
            sessionState.eventRouter.emitReportReady(
                reportUrl: generated.fileReportURL,
                pdfUrl: generated.filePdfURL,
                xmlUrl: generated.fileXmlURL,
                customerProfile: profile
            )
            sessionState.refreshDataSnapshot(from: dataDirectory)
            sessionState.emitReportsRefresh()
            sessionState.emitHistoryData()
            sessionState.emitReportsData()
        } catch {
            RuntimeDiagnosticsLogger.error("Report generation failed: \(error.localizedDescription)")
        }
    }

    func emitPrivilegeHelperStatus() {
        let ready = PrivilegeHelperClient.isHelperReachable
        let payload: [String: Any] = [
            "ready": ready,
            "status": ready ? "Privileged scanner helper is ready" : "Helper not installed — full scans will prompt once for admin",
            "socketPath": PrivilegeHelperClient.socketPath,
            "installPath": PrivilegeHelperClient.helperInstallPath
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let json = String(data: data, encoding: .utf8) else { return }
        WebPortalViewCoordinatorBridge.shared.emitRuntimeEvent(event: "privilege_helper_status", payloadJSON: json)
    }

    @MainActor
    func installPrivilegeHelperFromSettings() {
        do {
            try PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true)
            RuntimeDiagnosticsLogger.log("Privilege helper installed from Settings")
        } catch {
            PrivilegeElevationController.presentHelperInstallFailure(error)
        }
        emitPrivilegeHelperStatus()
    }

    func openReportPath(_ path: String) {
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        if path.hasPrefix("file:"), let url = URL(string: path) {
            NSWorkspace.shared.open(url)
            return
        }
        if let url = ReportGenerator.resolveFileURL(forReportPath: path, dataDirectory: dataDirectory) {
            NSWorkspace.shared.open(url)
            return
        }
        if let url = URL(string: path), ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
            NSWorkspace.shared.open(url)
        }
    }

    func stopSwiftManagedScan() {
        RuntimeDiagnosticsLogger.log("Stop scan requested")
        scanCoordinator.cancel()
        sessionState.emitScanStopped()
        sessionState.clearScanSession()
        sessionState.emitSyncState(
            version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            hosts: []
        )
    }

    private func normalizedScanTarget(_ target: String) -> String {
        target.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            ?? sessionState.runtimeNetworkState?.cidr
            ?? sessionState.runtimeAutoScanSnapshot.target.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
            ?? "192.168.1.0/24"
    }

    func emitCurrentRuntimeSnapshotToWebView() {
        RuntimeDiagnosticsLogger.log("Emitting current runtime snapshot to web dashboard")
        if let networkState = sessionState.runtimeNetworkState {
            WebPortalViewCoordinatorBridge.shared.applyNetworkSnapshot(networkState)
        }
        sessionState.emitInitialData()
        sessionState.emitSyncState(
            version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            hosts: []
        )
        sessionState.emitTracerouteHops()
        sessionState.emitHistoryData()
        sessionState.emitReportsData()
        sessionState.emitAutoScanConfig()
        sessionState.emitGoogleDriveStatus()
        sessionState.emitCustomerProfile()
        emitPrivilegeHelperStatus()
    }

    private func handleRuntimeBrowserOpen() {
        RuntimeDiagnosticsLogger.log("Runtime ready")
        sessionState.runtimeIsReady = true
        sessionState.runtimeStatusText = "Ready"
        sessionState.startupHint = "Ready to scan"
        sessionState.preloadMessage = "Dashboard ready"
        sessionState.showLoadingStrip = false
        sessionState.clearScanSession()
        sessionState.emitSyncState(
            version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            hosts: []
        )
        syncRuntimeMenuState()
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            self.emitCurrentRuntimeSnapshotToWebView()
        }
    }

    private func handleRuntimeLaunchFailure() {
        RuntimeDiagnosticsLogger.error("Runtime failed to launch")
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Error"
        sessionState.startupHint = "Runtime failed to start"
        sessionState.preloadMessage = "Runtime failed to start"
        sessionState.showLoadingStrip = false
        sessionState.runtimeIdentity = nil
        syncRuntimeMenuState()
        runtimeAlertPresenter.presentLaunchFailureAlert()
    }

    private func handleRuntimeStartupTimeout() {
        RuntimeDiagnosticsLogger.log("Runtime startup timeout reached; showing waiting state")
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Waiting"
        sessionState.startupHint = "Backend is still booting"
        sessionState.preloadMessage = "Keeping the shell open"
        sessionState.showLoadingStrip = true
        syncRuntimeMenuState()
        handleRuntimeBrowserOpen()
    }

    private func handleRuntimeExitFinalFailure(terminationStatus: Int32) {
        RuntimeDiagnosticsLogger.error("Runtime exited unexpectedly status=\(terminationStatus)")
        sessionState.runtimeIsReady = false
        sessionState.runtimeStatusText = "Error"
        sessionState.startupHint = "Runtime stopped unexpectedly"
        sessionState.preloadMessage = "Runtime stopped unexpectedly"
        sessionState.showLoadingStrip = false
        sessionState.runtimeIdentity = nil
        sessionState.emitScanStopped()
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

    private static func copyBundledStylesheetIfNeeded() {
        let workDir = RuntimeSettingsStore.currentRuntimeWorkDirectoryURL()
        let destination = workDir.appendingPathComponent("nmap-modern.xsl")
        if FileManager.default.fileExists(atPath: destination.path) {
            return
        }
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent("nmap-modern.xsl"),
            Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/nmap-modern.xsl"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("nmap-modern.xsl")
        ].compactMap { $0 }
        for source in candidates where FileManager.default.fileExists(atPath: source.path) {
            try? FileManager.default.copyItem(at: source, to: destination)
            return
        }
    }
}
