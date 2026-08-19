import Darwin
import Foundation

/// Installs/removes a per-user LaunchAgent that runs scheduled scans without UI intervention.
/// Scans execute via `NmapUI --scheduled-scan`, which uses the privileged nmap helper.
enum AutoScanScheduler {
    static let launchAgentLabel = "com.techmore.nmapui.autoscan"

    static var launchAgentPlistURL: URL {
        let agents = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        return agents.appendingPathComponent("\(launchAgentLabel).plist")
    }

    @discardableResult
    static func sync(enabled: Bool, recurrence: String, startTime: String) -> Result<Void, Error> {
        if enabled {
            do {
                try install(recurrence: recurrence, startTime: startTime)
                RuntimeDiagnosticsLogger.log("Auto-scan LaunchAgent installed recurrence=\(recurrence) startTime=\(startTime)")
                return .success(())
            } catch {
                RuntimeDiagnosticsLogger.error("Auto-scan LaunchAgent install failed: \(error.localizedDescription)")
                return .failure(error)
            }
        } else {
            remove()
            RuntimeDiagnosticsLogger.log("Auto-scan LaunchAgent removed")
            return .success(())
        }
    }

    static func install(recurrence: String, startTime: String) throws {
        guard let executableURL = resolveAppExecutableURL() else {
            throw NSError(
                domain: "NmapUI.AutoScan",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Could not locate NmapUI executable for scheduled scans."]
            )
        }

        let fileManager = FileManager.default
        try fileManager.createDirectory(at: launchAgentPlistURL.deletingLastPathComponent(), withIntermediateDirectories: true)

        let calendar = calendarInterval(recurrence: recurrence, startTime: startTime)
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL().path
        let environment: [String: String] = [
            "NMAPUI_DATA_DIR": dataDirectory,
            "NMAPUI_RUNTIME_WORKDIR": RuntimeSettingsStore.currentRuntimeWorkDirectoryURL().path
        ]

        var root: [String: Any] = [
            "Label": launchAgentLabel,
            "ProgramArguments": [
                executableURL.path,
                "--scheduled-scan"
            ],
            "RunAtLoad": false,
            "WorkingDirectory": RuntimeSettingsStore.currentRuntimeWorkDirectoryURL().path,
            "EnvironmentVariables": environment,
            "StandardOutPath": RuntimeSettingsStore.currentDataDirectoryURL().appendingPathComponent("logs/autoscan.out.log").path,
            "StandardErrorPath": RuntimeSettingsStore.currentDataDirectoryURL().appendingPathComponent("logs/autoscan.err.log").path
        ]

        if let interval = calendar.intervalSeconds {
            root["StartInterval"] = interval
        }
        if let startCalendarInterval = calendar.startCalendarInterval {
            root["StartCalendarInterval"] = startCalendarInterval
        }

        let data = try PropertyListSerialization.data(fromPropertyList: root, format: .xml, options: 0)
        do {
            try data.write(to: launchAgentPlistURL, options: [.atomic])
            _ = try? runLaunchctl(["bootout", "gui/\(getuid())/\(launchAgentLabel)"])
            _ = try runLaunchctl(["bootstrap", "gui/\(getuid())", launchAgentPlistURL.path])
            _ = try runLaunchctl(["enable", "gui/\(getuid())/\(launchAgentLabel)"])
        } catch {
            _ = try? runLaunchctl(["bootout", "gui/\(getuid())/\(launchAgentLabel)"])
            try? FileManager.default.removeItem(at: launchAgentPlistURL)
            throw error
        }
    }

    static func remove() {
        _ = try? runLaunchctl(["bootout", "gui/\(getuid())/\(launchAgentLabel)"])
        try? FileManager.default.removeItem(at: launchAgentPlistURL)
    }

    private struct ScheduleSpec {
        let intervalSeconds: Int?
        let startCalendarInterval: [String: Int]?
    }

    private static func calendarInterval(recurrence: String, startTime: String) -> ScheduleSpec {
        let parts = startTime.split(separator: ":")
        let hour = parts.count > 0 ? Int(parts[0]) ?? 1 : 1
        let minute = parts.count > 1 ? Int(parts[1]) ?? 0 : 0

        switch recurrence {
        case "hourly":
            return ScheduleSpec(intervalSeconds: 3600, startCalendarInterval: nil)
        case "weekly":
            // Monday at the chosen time.
            return ScheduleSpec(
                intervalSeconds: nil,
                startCalendarInterval: [
                    "Weekday": 1,
                    "Hour": hour,
                    "Minute": minute
                ]
            )
        case "monthly":
            return ScheduleSpec(
                intervalSeconds: nil,
                startCalendarInterval: [
                    "Day": 1,
                    "Hour": hour,
                    "Minute": minute
                ]
            )
        default: // daily
            return ScheduleSpec(
                intervalSeconds: nil,
                startCalendarInterval: [
                    "Hour": hour,
                    "Minute": minute
                ]
            )
        }
    }

    private static func resolveAppExecutableURL() -> URL? {
        if let url = Bundle.main.executableURL {
            // Prefer the real binary when a shell wrapper is present.
            let real = url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + ".real")
            if FileManager.default.isExecutableFile(atPath: real.path) {
                return real
            }
            if FileManager.default.isExecutableFile(atPath: url.path) {
                return url
            }
        }
        return nil
    }

    @discardableResult
    private static func runLaunchctl(_ arguments: [String]) throws -> String {
        let result = try ExternalProcessRunner.run(
            executable: URL(fileURLWithPath: "/bin/launchctl"),
            arguments: arguments,
            timeout: 30
        )
        // bootout returns non-zero if not loaded; ignore that at call sites.
        return result.stdout + result.stderr
    }
}
