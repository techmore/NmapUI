import Foundation
import CryptoKit

enum GowitnessManager {
    static let version = "3.1.1"
    #if arch(arm64)
    static let downloadURL = URL(string: "https://github.com/sensepost/gowitness/releases/download/3.1.1/gowitness-3.1.1-darwin-arm64")!
    static let sha256 = "485f0c52887a499d5f6b324d5f55f515763f277deff38c64efc1399f787bf854"
    #else
    static let downloadURL: URL? = nil
    static let sha256: String? = nil
    #endif

    private static let installationGate = GowitnessInstallationGate()

    static func managedBinaryURL(dataDirectory: URL = RuntimeSettingsStore.currentDataDirectoryURL()) -> URL {
        dataDirectory.appendingPathComponent("tools/gowitness/gowitness")
    }

    static func resolvedBinaryURL() -> URL? {
        let managed = managedBinaryURL()
        guard FileManager.default.isExecutableFile(atPath: managed.path),
              let data = try? Data(contentsOf: managed) else { return nil }
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #if arch(arm64)
        return hash == sha256 ? managed : nil
        #else
        return nil
        #endif
    }

    static func install() async throws -> URL {
        try await installationGate.run {
            try await performInstall()
        }
    }

    private static func performInstall() async throws -> URL {
        #if !arch(arm64)
        throw GowitnessError.unsupportedArchitecture
        #else
        let destination = managedBinaryURL()
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 5 * 60
        let session = URLSession(configuration: configuration)
        let (temporaryURL, response) = try await session.download(from: downloadURL)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw GowitnessError.downloadFailed }
        let attributes = try FileManager.default.attributesOfItem(atPath: temporaryURL.path)
        guard (attributes[.size] as? NSNumber)?.intValue ?? 0 > 1_000_000 else { throw GowitnessError.invalidBinary }
        let downloadedHash = SHA256.hash(data: try Data(contentsOf: temporaryURL)).map { String(format: "%02x", $0) }.joined()
        guard downloadedHash == sha256 else { throw GowitnessError.invalidBinary }
        let staged = destination.appendingPathExtension("new")
        try? FileManager.default.removeItem(at: staged)
        try FileManager.default.moveItem(at: temporaryURL, to: staged)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: staged.path)
        guard try versionOutput(binary: staged).contains(version) else {
            try? FileManager.default.removeItem(at: staged)
            throw GowitnessError.invalidBinary
        }
        let backup = destination.appendingPathExtension("previous")
        try? FileManager.default.removeItem(at: backup)
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.moveItem(at: destination, to: backup)
        }
        do {
            try FileManager.default.moveItem(at: staged, to: destination)
        } catch {
            if FileManager.default.fileExists(atPath: backup.path) {
                try? FileManager.default.moveItem(at: backup, to: destination)
            }
            throw error
        }
        return destination
        #endif
    }

    static func versionOutput(binary: URL) throws -> String {
        let result = try ExternalProcessRunner.run(executable: binary, arguments: ["version"], timeout: 15)
        guard result.exitCode == 0, !result.timedOut else { throw GowitnessError.invalidBinary }
        return result.stdout + result.stderr
    }
}

private actor GowitnessInstallationGate {
    private var activeTask: Task<URL, Error>?

    func run(_ operation: @escaping @Sendable () async throws -> URL) async throws -> URL {
        if let activeTask { return try await activeTask.value }
        let task = Task { try await operation() }
        activeTask = task
        defer { activeTask = nil }
        return try await task.value
    }
}

enum GowitnessError: LocalizedError {
    case downloadFailed
    case invalidBinary
    case unsupportedArchitecture

    var errorDescription: String? {
        switch self {
        case .downloadFailed: return "Could not download GoWitness"
        case .invalidBinary: return "Downloaded GoWitness failed version verification"
        case .unsupportedArchitecture: return "This GoWitness build does not support the current Mac architecture"
        }
    }
}
