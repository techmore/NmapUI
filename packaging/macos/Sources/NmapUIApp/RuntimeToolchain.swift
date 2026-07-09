import Foundation

struct RuntimeToolchain: Codable {
    let nmapPath: String?
    let traceroutePath: String?
    let brewPath: String?
    let gowitnessPath: String?
    let googleDriveHelperPath: String?

    var displaySummary: String {
        [
            nmapPath.map { "nmap: \($0)" },
            brewPath.map { "brew: \($0)" },
            traceroutePath.map { "traceroute: \($0)" },
            gowitnessPath.map { "gowitness: \($0)" }
        ]
        .compactMap { $0 }
        .joined(separator: " | ")
    }

    static func current() -> RuntimeToolchain {
        RuntimeToolchain(
            nmapPath: resolveExecutable(
                explicitPath: ProcessInfo.processInfo.environment["NMAP_PATH"],
                candidates: [
                    "/opt/homebrew/bin/nmap",
                    "/usr/local/bin/nmap",
                    "/usr/bin/nmap",
                    "/bin/nmap",
                    "nmap"
                ]
            ),
            traceroutePath: resolveExecutable(
                explicitPath: ProcessInfo.processInfo.environment["TRACEROUTE_PATH"],
                candidates: [
                    "/usr/sbin/traceroute",
                    "/sbin/traceroute",
                    "/opt/homebrew/bin/traceroute",
                    "/usr/local/bin/traceroute",
                    "traceroute"
                ]
            ),
            brewPath: resolveExecutable(
                explicitPath: ProcessInfo.processInfo.environment["BREW_PATH"],
                candidates: [
                    "/opt/homebrew/bin/brew",
                    "/usr/local/bin/brew",
                    "brew"
                ]
            ),
            gowitnessPath: resolveExecutable(
                explicitPath: ProcessInfo.processInfo.environment["GOWITNESS_PATH"],
                candidates: [
                    "/opt/homebrew/bin/gowitness",
                    "/usr/local/bin/gowitness",
                    "gowitness"
                ]
            ),
            googleDriveHelperPath: resolveExecutable(
                explicitPath: ProcessInfo.processInfo.environment["NMAPUI_GOOGLE_DRIVE_HELPER"],
                candidates: {
                    var paths: [String] = []
                    if let execDir = Bundle.main.executableURL?.deletingLastPathComponent().path {
                        paths.append(execDir + "/GoogleDriveHelper")
                    }
                    let cwd = FileManager.default.currentDirectoryPath
                    paths.append(contentsOf: [
                        cwd + "/packaging/macos/.build/debug/GoogleDriveHelper",
                        cwd + "/packaging/macos/.build/release/GoogleDriveHelper",
                        cwd + "/packaging/macos/.build/out/Products/Debug/GoogleDriveHelper",
                        cwd + "/.build/debug/GoogleDriveHelper"
                    ])
                    return paths
                }()
            )
        )
    }

    private static func resolveExecutable(explicitPath: String?, candidates: [String]) -> String? {
        var allCandidates: [String] = []
        if let explicitPath {
            allCandidates.append(expandUserPath(explicitPath))
        }
        allCandidates.append(contentsOf: candidates.map(expandUserPath))

        let searchPaths = (ProcessInfo.processInfo.environment["PATH"] ?? "")
            .split(separator: ":")
            .map(String.init)
        for candidate in candidates where !candidate.contains("/") {
            allCandidates.append(contentsOf: searchPaths.map { "\($0)/\(candidate)" })
        }
        return allCandidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
    }

    private static func expandUserPath(_ path: String) -> String {
        guard path.hasPrefix("~") else { return path }
        return NSString(string: path).expandingTildeInPath
    }
}
