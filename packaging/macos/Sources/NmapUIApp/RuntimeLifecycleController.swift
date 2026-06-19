import AppKit
import Foundation

@MainActor
final class RuntimeLifecycleController {
    enum StartupResult {
        case ready
        case timeout
    }

    private let processLauncher: ProcessLauncher
    private let startupCoordinator: StartupCoordinator
    private let runtimeURL: URL

    private var runtimeProcess: Process?
    private var runtimeStopRequested = false
    private var runtimeAutoRestartAttempted = false

    var runtimeIsReady = false
    var runtimeStatusText = "Starting..."

    init(processLauncher: ProcessLauncher, startupCoordinator: StartupCoordinator, runtimeURL: URL) {
        self.processLauncher = processLauncher
        self.startupCoordinator = startupCoordinator
        self.runtimeURL = runtimeURL
    }

    func start(
        onBrowserOpen: @escaping @MainActor () -> Void,
        onLaunchFailure: @escaping @MainActor () -> Void,
        onStartupTimeout: @escaping @MainActor () -> Void,
        onRuntimeExitFinalFailure: @escaping @MainActor (Int32) -> Void,
        onStateChanged: @escaping @MainActor () -> Void
    ) {
        runtimeStopRequested = false
        runtimeProcess = processLauncher.launchRuntimeIfNeeded()
        if runtimeProcess == nil {
            runtimeStatusText = "Error"
            onStateChanged()
            onLaunchFailure()
            return
        }

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
                self.runtimeIsReady = true
                self.runtimeStatusText = "Ready"
                self.runtimeAutoRestartAttempted = false
                onStateChanged()
                onBrowserOpen()
            case .timeout:
                self.runtimeIsReady = false
                self.runtimeStatusText = "Starting..."
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
        onStateChanged()

        guard !runtimeStopRequested else { return }

        if !runtimeAutoRestartAttempted {
            runtimeAutoRestartAttempted = true
            runtimeStatusText = "Restarting..."
            onStateChanged()
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                Task { @MainActor in
                    onRetry()
                }
            }
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
