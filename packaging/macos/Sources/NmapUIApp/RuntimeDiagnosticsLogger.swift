import Foundation
import OSLog

enum RuntimeDiagnosticsLogger {
    private static let osLogger = Logger(subsystem: "com.nmapui.app", category: "runtime")
    private static let lock = NSLock()
    nonisolated(unsafe) private static var logFileURL: URL?

    static func configure(dataDirectory: URL) {
        lock.lock()
        defer { lock.unlock() }
        logFileURL = dataDirectory.appendingPathComponent("runtime-diagnostics.log")
    }

    static func log(_ message: String) {
        osLogger.info("\(message, privacy: .public)")
        append("[\(timestamp())] \(message)")
    }

    static func error(_ message: String) {
        osLogger.error("\(message, privacy: .public)")
        append("[\(timestamp())] ERROR \(message)")
    }

    private static func append(_ line: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let logFileURL else { return }
        let output = line + "\n"
        let data = Data(output.utf8)
        if FileManager.default.fileExists(atPath: logFileURL.path) {
            if let handle = try? FileHandle(forWritingTo: logFileURL) {
                _ = try? handle.seekToEnd()
                _ = try? handle.write(contentsOf: data)
                try? handle.close()
            }
        } else {
            try? FileManager.default.createDirectory(at: logFileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? data.write(to: logFileURL, options: [.atomic])
        }
    }

    private static func timestamp() -> String {
        ISO8601DateFormatter().string(from: Date())
    }
}
