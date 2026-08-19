import Foundation

enum RuntimeVulners {
    private static let missingScriptPath = "/Library/Application Support/NmapUI/nmap-vulners/vulners.nse"

    static var resolvedScriptURL: URL? {
        let sourceRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // NmapUIApp
            .deletingLastPathComponent() // Sources
            .deletingLastPathComponent() // packaging/macos
            .deletingLastPathComponent() // packaging
            .deletingLastPathComponent() // repository root
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent("nmap-vulners/vulners.nse"),
            Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/nmap-vulners/vulners.nse"),
            sourceRoot.appendingPathComponent("nmap-vulners/vulners.nse")
        ].compactMap { $0 }
        return candidates.first(where: { FileManager.default.isReadableFile(atPath: $0.path) })
    }

    static func scriptPath() -> String {
        // Never fall back to the cwd or to Nmap's implicit script search. The
        // privileged installer must receive the deterministic bundled script.
        return resolvedScriptURL?.path ?? missingScriptPath
    }
}
