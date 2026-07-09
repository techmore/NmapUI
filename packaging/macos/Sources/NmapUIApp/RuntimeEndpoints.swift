import Foundation

enum RuntimeEndpoints {
    static let host = "127.0.0.1"
    static let port = 9000

    static var baseURL: URL {
        dashboardURL
    }

    static var readinessURL: URL {
        dashboardURL
    }

    static func googleDriveOAuthCallbackURL(port: Int = port) -> URL {
        URL(string: "http://localhost:\(port)/google-drive/oauth2callback")!
    }

    static var fixedPortString: String {
        String(port)
    }

    static var dashboardURL: URL {
        let fileManager = FileManager.default
        if let resourceURL = Bundle.main.resourceURL?.appendingPathComponent("index.html"),
           fileManager.fileExists(atPath: resourceURL.path) {
            RuntimeDiagnosticsLogger.log("Dashboard URL resolved to bundled resource \(resourceURL.path)")
            return resourceURL
        }

        let sourceFileURL = URL(fileURLWithPath: #filePath)
        if let developmentURL = firstAncestorContainingSourceDashboard(startingAt: sourceFileURL.deletingLastPathComponent()) {
            RuntimeDiagnosticsLogger.log("Dashboard URL resolved to source resource \(developmentURL.path)")
            return developmentURL
        }
        if let generatedURL = firstAncestorContainingGeneratedDashboard(startingAt: sourceFileURL.deletingLastPathComponent()) {
            RuntimeDiagnosticsLogger.log("Dashboard URL resolved to generated resource \(generatedURL.path)")
            return generatedURL
        }

        let currentDir = URL(fileURLWithPath: fileManager.currentDirectoryPath, isDirectory: true)
        if let developmentURL = firstAncestorContainingSourceDashboard(startingAt: currentDir) {
            RuntimeDiagnosticsLogger.log("Dashboard URL resolved to development resource \(developmentURL.path)")
            return developmentURL
        }
        if let generatedURL = firstAncestorContainingGeneratedDashboard(startingAt: currentDir) {
            RuntimeDiagnosticsLogger.log("Dashboard URL resolved to generated development resource \(generatedURL.path)")
            return generatedURL
        }

        let fallbackURL = currentDir.appendingPathComponent("index.html")
        RuntimeDiagnosticsLogger.error("Dashboard URL fallback does not exist: \(fallbackURL.path)")
        return fallbackURL
    }

    private static func firstAncestorContainingSourceDashboard(startingAt startURL: URL) -> URL? {
        firstAncestor(startingAt: startURL) { candidate in
            dashboardURL(in: candidate)
        }
    }

    private static func firstAncestorContainingGeneratedDashboard(startingAt startURL: URL) -> URL? {
        firstAncestor(startingAt: startURL) { candidate in
            let generatedResourcesURL = candidate
                .appendingPathComponent("build", isDirectory: true)
                .appendingPathComponent("NmapUI.app", isDirectory: true)
                .appendingPathComponent("Contents", isDirectory: true)
                .appendingPathComponent("Resources", isDirectory: true)
            return dashboardURL(in: generatedResourcesURL)
        }
    }

    private static func firstAncestor(startingAt startURL: URL, matching match: (URL) -> URL?) -> URL? {
        var candidate = startURL.standardizedFileURL

        while true {
            if let url = match(candidate) {
                return url
            }

            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path {
                return nil
            }
            candidate = parent
        }
    }

    private static func dashboardURL(in directoryURL: URL) -> URL? {
        let fileManager = FileManager.default
        let dashboardURL = directoryURL.appendingPathComponent("index.html")
        let staticDirectoryURL = directoryURL.appendingPathComponent("static", isDirectory: true)
        guard fileManager.fileExists(atPath: dashboardURL.path),
              fileManager.fileExists(atPath: staticDirectoryURL.path) else {
            return nil
        }
        return dashboardURL
    }
}
