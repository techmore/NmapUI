import Foundation

@MainActor
final class StartupCoordinator {
    enum Result {
        case ready
        case timeout
    }

    private let readinessURL: URL
    private var launchToken = UUID()
    private var startupTimeoutPrompted = false

    init(readinessURL: URL) {
        self.readinessURL = readinessURL
    }

    func begin() {
        launchToken = UUID()
        startupTimeoutPrompted = false
    }

    func observeStartup() async -> Result? {
        let token = launchToken
        if readinessURL.isFileURL {
            guard launchToken == token else { return nil }
            return .ready
        }
        let isReachable = await RuntimeBridge.waitForReachability(
            host: "127.0.0.1",
            port: 9000,
            timeout: 5
        )
        guard launchToken == token else { return nil }
        guard isReachable else {
            guard !startupTimeoutPrompted else { return nil }
            startupTimeoutPrompted = true
            return .timeout
        }

        let identity = await RuntimeBridge.waitForIdentity(url: readinessURL, timeout: 20)
        guard launchToken == token else { return nil }
        if let identity {
            startupTimeoutPrompted = false
            NotificationCenter.default.post(name: .runtimeBridgeDidResolveIdentity, object: identity)
            return .ready
        }
        guard !startupTimeoutPrompted else { return nil }
        startupTimeoutPrompted = true
        return .timeout
    }
}

extension Notification.Name {
    static let runtimeBridgeDidResolveIdentity = Notification.Name("runtimeBridgeDidResolveIdentity")
}
