import AppKit
import Foundation

@MainActor
final class RuntimeLifecycleController {
    private let processLauncher: ProcessLauncher
    private let startupCoordinator: StartupCoordinator

    private var runtimeProcess: Process?
    private var runtimeStopRequested = false
    private var runtimeAutoRestartAttempted = false
    private var pendingAutoRestartWorkItem: DispatchWorkItem?

    var runtimeIsReady = false
    var runtimeStatusText = "Starting..."

    init(processLauncher: ProcessLauncher, startupCoordinator: StartupCoordinator) {
        self.processLauncher = processLauncher
        self.startupCoordinator = startupCoordinator
    }

    func start(
        onBrowserOpen: @escaping @MainActor () -> Void,
        onLaunchFailure: @escaping @MainActor () -> Void,
        onStartupTimeout: @escaping @MainActor () -> Void,
        onRuntimeExitFinalFailure: @escaping @MainActor (Int32) -> Void,
        onStateChanged: @escaping @MainActor () -> Void
    ) {
        pendingAutoRestartWorkItem?.cancel()
        pendingAutoRestartWorkItem = nil
        runtimeStopRequested = false
        runtimeProcess = processLauncher.launchRuntimeIfNeeded()
        if runtimeProcess == nil {
            runtimeStatusText = "Error"
            RuntimeDiagnosticsLogger.error("Runtime launcher returned nil")
            onStateChanged()
            onLaunchFailure()
            return
        }
        RuntimeDiagnosticsLogger.log("Runtime process started pid=\(runtimeProcess?.processIdentifier ?? -1)")

        attachRuntimeTerminationHandler(
            onBrowserOpen: onBrowserOpen,
            onLaunchFailure: onLaunchFailure,
            onStartupTimeout: onStartupTimeout,
            onRuntimeExitFinalFailure: onRuntimeExitFinalFailure,
            onStateChanged: onStateChanged
        )
        beginStartupWatch(
            onBrowserOpen: onBrowserOpen,
            onStartupTimeout: onStartupTimeout,
            onStateChanged: onStateChanged
        )
    }

    func restartAfterPreferenceChange(
        onBrowserOpen: @escaping @MainActor () -> Void,
        onLaunchFailure: @escaping @MainActor () -> Void,
        onStartupTimeout: @escaping @MainActor () -> Void,
        onRuntimeExitFinalFailure: @escaping @MainActor (Int32) -> Void,
        onStateChanged: @escaping @MainActor () -> Void
    ) {
        pendingAutoRestartWorkItem?.cancel()
        pendingAutoRestartWorkItem = nil
        runtimeStopRequested = true
        stopRuntime()
        runtimeIsReady = false
        runtimeAutoRestartAttempted = false
        runtimeStatusText = "Starting..."
        onStateChanged()
        start(
            onBrowserOpen: onBrowserOpen,
            onLaunchFailure: onLaunchFailure,
            onStartupTimeout: onStartupTimeout,
            onRuntimeExitFinalFailure: onRuntimeExitFinalFailure,
            onStateChanged: onStateChanged
        )
    }

    func stopForQuitOrUninstall() {
        pendingAutoRestartWorkItem?.cancel()
        pendingAutoRestartWorkItem = nil
        runtimeStopRequested = true
        stopRuntime()
    }

    private func beginStartupWatch(
        onBrowserOpen: @escaping @MainActor () -> Void,
        onStartupTimeout: @escaping @MainActor () -> Void,
        onStateChanged: @escaping @MainActor () -> Void
    ) {
        startupCoordinator.begin()
        Task { [weak self] in
            guard let self else { return }
            let result = await self.startupCoordinator.observeStartup()
            guard let result else { return }
            switch result {
            case .ready:
                RuntimeDiagnosticsLogger.log("Startup coordinator reported ready")
                self.runtimeIsReady = true
                self.runtimeStatusText = "Ready"
                self.runtimeAutoRestartAttempted = false
                onStateChanged()
                onBrowserOpen()
            case .timeout:
                RuntimeDiagnosticsLogger.log("Startup coordinator reported timeout")
                self.runtimeIsReady = false
                self.runtimeStatusText = "Waiting"
                onStateChanged()
                onStartupTimeout()
            }
        }
    }

    private func handleRuntimeExit(
        terminationStatus: Int32,
        onRuntimeExitFinalFailure: @escaping @MainActor (Int32) -> Void,
        onStateChanged: @escaping @MainActor () -> Void,
        onRetry: @escaping @MainActor () -> Void
    ) {
        runtimeProcess = nil
        runtimeIsReady = false
        runtimeStatusText = "Error"
        RuntimeDiagnosticsLogger.error("Runtime process exited status=\(terminationStatus)")
        onStateChanged()

        guard !runtimeStopRequested else { return }

        if !runtimeAutoRestartAttempted {
            runtimeAutoRestartAttempted = true
            runtimeStatusText = "Restarting..."
            onStateChanged()
            let workItem = DispatchWorkItem { [weak self] in
                guard let self, !self.runtimeStopRequested else { return }
                self.pendingAutoRestartWorkItem = nil
                Task { @MainActor in
                    onRetry()
                }
            }
            pendingAutoRestartWorkItem = workItem
            DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: workItem)
            return
        }

        onRuntimeExitFinalFailure(terminationStatus)
    }

    private func stopRuntime() {
        processLauncher.stop(runtimeProcess: runtimeProcess)
        runtimeProcess = nil
    }

    private func attachRuntimeTerminationHandler(
        onBrowserOpen: @escaping @MainActor () -> Void,
        onLaunchFailure: @escaping @MainActor () -> Void,
        onStartupTimeout: @escaping @MainActor () -> Void,
        onRuntimeExitFinalFailure: @escaping @MainActor (Int32) -> Void,
        onStateChanged: @escaping @MainActor () -> Void
    ) {
        runtimeProcess?.terminationHandler = { [weak self] process in
            Task { @MainActor in
                guard let self else { return }
                if process.terminationStatus == 0 {
                    RuntimeDiagnosticsLogger.log("Runtime process exited cleanly; not restarting")
                    self.runtimeProcess = nil
                    self.runtimeIsReady = true
                    self.runtimeStatusText = "Ready"
                    onStateChanged()
                    onBrowserOpen()
                    return
                }
                self.handleRuntimeExit(
                    terminationStatus: process.terminationStatus,
                    onRuntimeExitFinalFailure: onRuntimeExitFinalFailure,
                    onStateChanged: onStateChanged,
                    onRetry: {
                        self.restartAfterPreferenceChange(
                            onBrowserOpen: onBrowserOpen,
                            onLaunchFailure: onLaunchFailure,
                            onStartupTimeout: onStartupTimeout,
                            onRuntimeExitFinalFailure: onRuntimeExitFinalFailure,
                            onStateChanged: onStateChanged
                        )
                    }
                )
            }
        }
    }
}
