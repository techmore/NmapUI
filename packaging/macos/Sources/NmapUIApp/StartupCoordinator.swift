import AppKit
import Foundation

@MainActor
final class StartupCoordinator {
    enum Result {
        case ready
        case timeout
    }

    private let readinessURL: URL
    private let runtimeURL: URL
    private var launchToken = UUID()
    private var startupTimeoutPrompted = false

    init(readinessURL: URL, runtimeURL: URL) {
        self.readinessURL = readinessURL
        self.runtimeURL = runtimeURL
    }

    func begin() {
        launchToken = UUID()
        startupTimeoutPrompted = false
    }

    func observeStartup() async -> Result? {
        let token = launchToken
        let isReady = await ProcessLauncher.waitForRuntime(url: readinessURL, timeout: 20)
        guard launchToken == token else { return nil }
        if isReady {
            startupTimeoutPrompted = false
            return .ready
        }
        guard !startupTimeoutPrompted else { return nil }
        startupTimeoutPrompted = true
        return .timeout
    }
}
