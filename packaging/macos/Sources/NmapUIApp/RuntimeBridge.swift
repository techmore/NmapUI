import Foundation
import Network
import Darwin

@MainActor
enum RuntimeBridge {
    static func performStartupMaintenance() async {
        await updateHomebrewIfAvailable()
        await updateNmapScriptDatabaseIfAvailable()
    }

    static func waitForPortToClear(host: String, port: UInt16, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await !isPortReachable(host: host, port: port) {
                return true
            }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    static func stopExistingListenerOnPort(_ port: Int) async -> Bool {
        guard let listenerPids = await listeningPids(on: port) else { return false }
        let pids = listenerPids.filter { $0 != getpid() }
        guard !pids.isEmpty else { return false }

        for pid in pids {
            kill(pid, SIGTERM)
        }
        try? await Task.sleep(nanoseconds: 1_200_000_000)

        if let remaining = await listeningPids(on: port) {
            for pid in remaining.filter({ $0 != getpid() }) {
                kill(pid, SIGKILL)
            }
        }
        return true
    }

    static func waitForReachability(host: String, port: UInt16, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await isPortReachable(host: host, port: port) {
                return true
            }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    private static func isPortReachable(host: String, port: UInt16) async -> Bool {
        let deadline = Date().addingTimeInterval(1.0)
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!,
            using: .tcp
        )
        connection.start(queue: .global(qos: .utility))
        defer { connection.cancel() }

        while true {
            switch connection.state {
            case .ready:
                return true
            case .failed, .cancelled:
                return false
            case .setup, .preparing, .waiting:
                break
            @unknown default:
                break
            }
            if Date() >= deadline { break }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    static func waitForIdentity(url: URL, timeout: TimeInterval) async -> RuntimeIdentity? {
        let deadline = Date().addingTimeInterval(timeout)
        let session = URLSession(configuration: .ephemeral)
        while Date() < deadline {
            do {
                let (data, response) = try await session.data(from: url)
                guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
                    try? await Task.sleep(nanoseconds: 500_000_000)
                    continue
                }
                if let identity = try? JSONDecoder().decode(RuntimeIdentity.self, from: data),
                   identity.app == RuntimeIdentity.expectedApp,
                   !identity.name.isEmpty,
                   !identity.version.isEmpty {
                    return identity
                }
            } catch {
                // Keep polling until timeout.
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        return nil
    }

    private static func listeningPids(on port: Int) async -> [Int32]? {
        await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
            process.arguments = ["-ti", "tcp:\(port)", "-sTCP:LISTEN"]

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = Pipe()

            do {
                try process.run()
            } catch {
                continuation.resume(returning: nil)
                return
            }

            process.terminationHandler = { _ in
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let stdout = String(data: data, encoding: .utf8) ?? ""
                let pids = stdout
                    .split(whereSeparator: \.isNewline)
                    .compactMap { Int32($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
                continuation.resume(returning: pids)
            }
        }
    }

    private static func updateHomebrewIfAvailable() async {
        guard let brewPath = findExecutable(named: "brew") else { return }
        _ = await runProcess(executable: brewPath, arguments: ["update"])
        _ = await runProcess(executable: brewPath, arguments: ["upgrade", "nmap"])
    }

    private static func updateNmapScriptDatabaseIfAvailable() async {
        guard let nmapPath = findExecutable(named: "nmap") else { return }
        _ = await runProcess(executable: nmapPath, arguments: ["--script-updatedb"])
    }

    private static func findExecutable(named name: String) -> String? {
        let searchPaths = (ProcessInfo.processInfo.environment["PATH"] ?? "")
            .split(separator: ":")
            .map(String.init)
        let candidates = searchPaths.map { "\($0)/\(name)" } + ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)"]
        return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
    }

    private static func runProcess(executable: String, arguments: [String]) async -> Bool {
        await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            process.terminationHandler = { _ in
                continuation.resume(returning: process.terminationStatus == 0)
            }
            do {
                try process.run()
            } catch {
                continuation.resume(returning: false)
            }
        }
    }
}
