import Foundation
import RuntimeContracts

/// Thin wrapper around the GoogleDriveHelper executable for status and report uploads.
enum GoogleDriveService {
    struct Status: Sendable {
        let success: Bool
        let status: String
        let configured: Bool
        let connected: Bool
        let error: String?
    }

    struct UploadResult: Sendable {
        let success: Bool
        let status: String
        let error: String?
        let uploaded: [[String: String]]
    }

    struct CommandResult: Sendable {
        let success: Bool
        let status: String?
        let error: String?
        let authURL: String?
        let configured: Bool?
        let connected: Bool?
    }

    static func resolveHelperURL() -> URL? {
        if let path = RuntimeToolchain.current().googleDriveHelperPath,
           FileManager.default.isExecutableFile(atPath: path) {
            return URL(fileURLWithPath: path)
        }

        var candidates: [URL] = []
        if let exec = Bundle.main.executableURL {
            candidates.append(exec.deletingLastPathComponent().appendingPathComponent("GoogleDriveHelper"))
            candidates.append(exec.deletingLastPathComponent().appendingPathComponent("GoogleDriveHelper.real"))
        }
        let packaging = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        candidates.append(packaging.appendingPathComponent(".build/debug/GoogleDriveHelper"))
        candidates.append(packaging.appendingPathComponent(".build/release/GoogleDriveHelper"))
        candidates.append(packaging.appendingPathComponent(".build/out/Products/Debug/GoogleDriveHelper"))
        return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0.path) })
    }

    static func status(dataDirectory: URL) -> Status {
        guard let helper = resolveHelperURL() else {
            return Status(
                success: false,
                status: "Google Drive helper unavailable",
                configured: false,
                connected: false,
                error: "GoogleDriveHelper binary not found"
            )
        }
        do {
            let output = try runHelper(helper: helper, arguments: ["status", "--root", dataDirectory.path])
            let json = parseJSON(output)
            return Status(
                success: (json["success"] as? Bool) ?? false,
                status: (json["status"] as? String) ?? "Unknown",
                configured: (json["configured"] as? Bool) ?? false,
                connected: (json["connected"] as? Bool) ?? false,
                error: json["error"] as? String
            )
        } catch {
            return Status(
                success: false,
                status: "Google Drive status failed",
                configured: false,
                connected: false,
                error: error.localizedDescription
            )
        }
    }

    static func saveCredentials(_ credentialsJson: String, dataDirectory: URL) -> CommandResult {
        guard let helper = resolveHelperURL() else {
            return CommandResult(success: false, status: nil, error: "GoogleDriveHelper binary not found", authURL: nil, configured: nil, connected: nil)
        }
        let normalized = normalizeCredentialsJSON(credentialsJson)
        do {
            let output = try runHelper(
                helper: helper,
                arguments: ["save-credentials", "--root", dataDirectory.path, "--credentials-json", normalized]
            )
            let json = parseJSON(output)
            // Keep a convenience copy for the app as well.
            RuntimeMetadataStore.persistGoogleDriveCredentials(normalized, to: dataDirectory)
            return CommandResult(
                success: (json["success"] as? Bool) ?? false,
                status: json["status"] as? String,
                error: json["error"] as? String,
                authURL: nil,
                configured: true,
                connected: nil
            )
        } catch {
            return CommandResult(success: false, status: nil, error: error.localizedDescription, authURL: nil, configured: nil, connected: nil)
        }
    }

    static func authURL(dataDirectory: URL, redirectURI: String) -> CommandResult {
        guard let helper = resolveHelperURL() else {
            return CommandResult(success: false, status: nil, error: "GoogleDriveHelper binary not found", authURL: nil, configured: nil, connected: nil)
        }
        do {
            let output = try runHelper(
                helper: helper,
                arguments: ["auth-url", "--root", dataDirectory.path, "--redirect-uri", redirectURI]
            )
            let json = parseJSON(output)
            return CommandResult(
                success: (json["success"] as? Bool) ?? false,
                status: json["status"] as? String,
                error: json["error"] as? String,
                authURL: json["authURL"] as? String,
                configured: json["configured"] as? Bool,
                connected: json["connected"] as? Bool
            )
        } catch {
            return CommandResult(success: false, status: nil, error: error.localizedDescription, authURL: nil, configured: nil, connected: nil)
        }
    }

    static func exchangeCode(code: String, state: String, dataDirectory: URL) -> CommandResult {
        guard let helper = resolveHelperURL() else {
            return CommandResult(success: false, status: nil, error: "GoogleDriveHelper binary not found", authURL: nil, configured: nil, connected: nil)
        }
        do {
            let output = try runHelper(
                helper: helper,
                arguments: ["exchange-code", "--root", dataDirectory.path, "--code", code, "--state", state]
            )
            let json = parseJSON(output)
            return CommandResult(
                success: (json["success"] as? Bool) ?? false,
                status: json["status"] as? String,
                error: json["error"] as? String,
                authURL: nil,
                configured: json["configured"] as? Bool,
                connected: true
            )
        } catch {
            return CommandResult(success: false, status: nil, error: error.localizedDescription, authURL: nil, configured: nil, connected: nil)
        }
    }

    static func disconnect(dataDirectory: URL) -> CommandResult {
        guard let helper = resolveHelperURL() else {
            return CommandResult(success: false, status: nil, error: "GoogleDriveHelper binary not found", authURL: nil, configured: nil, connected: nil)
        }
        do {
            let output = try runHelper(
                helper: helper,
                arguments: ["disconnect", "--root", dataDirectory.path]
            )
            let json = parseJSON(output)
            return CommandResult(
                success: (json["success"] as? Bool) ?? false,
                status: json["status"] as? String ?? "Google Drive disconnected",
                error: json["error"] as? String,
                authURL: nil,
                configured: json["configured"] as? Bool,
                connected: false
            )
        } catch {
            return CommandResult(success: false, status: nil, error: error.localizedDescription, authURL: nil, configured: nil, connected: nil)
        }
    }

    /// Accept either flat `{client_id, client_secret}` or Google console `installed`/`web` JSON.
    static func normalizeCredentialsJSON(_ raw: String) -> String {
        guard let data = raw.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return raw
        }
        if object["client_id"] != nil, object["client_secret"] != nil {
            return raw
        }
        let nested = (object["installed"] as? [String: Any]) ?? (object["web"] as? [String: Any])
        if let nested,
           let clientId = nested["client_id"] as? String,
           let clientSecret = nested["client_secret"] as? String {
            let flat: [String: String] = [
                "client_id": clientId,
                "client_secret": clientSecret
            ]
            if let encoded = try? JSONSerialization.data(withJSONObject: flat),
               let text = String(data: encoded, encoding: .utf8) {
                return text
            }
        }
        return raw
    }

    static func uploadReportArtifacts(
        files: [URL],
        dataDirectory: URL,
        folderId: String?
    ) -> UploadResult {
        guard let helper = resolveHelperURL() else {
            return UploadResult(
                success: false,
                status: "Google Drive helper unavailable",
                error: "GoogleDriveHelper binary not found",
                uploaded: []
            )
        }
        let existing = files.filter { FileManager.default.fileExists(atPath: $0.path) }
        guard !existing.isEmpty else {
            return UploadResult(success: false, status: "No report files to upload", error: "missing files", uploaded: [])
        }

        var arguments = ["upload", "--root", dataDirectory.path]
        if let folderId, !folderId.isEmpty {
            arguments.append(contentsOf: ["--folder-id", folderId])
        }
        arguments.append(contentsOf: existing.map(\.path))

        do {
            let output = try runHelper(helper: helper, arguments: arguments)
            let json = parseJSON(output)
            let uploaded = (json["uploaded"] as? [[String: Any]] ?? []).map { row in
                row.reduce(into: [String: String]()) { result, entry in
                    result[entry.key] = String(describing: entry.value)
                }
            }
            return UploadResult(
                success: (json["success"] as? Bool) ?? false,
                status: (json["status"] as? String) ?? "Upload finished",
                error: json["error"] as? String,
                uploaded: uploaded
            )
        } catch {
            return UploadResult(
                success: false,
                status: "Google Drive upload failed",
                error: error.localizedDescription,
                uploaded: []
            )
        }
    }

    private static func runHelper(helper: URL, arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = helper
        process.arguments = arguments
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        let out = String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let err = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        if process.terminationStatus != 0, out.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw NSError(
                domain: "NmapUI.GoogleDrive",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: err.isEmpty ? "GoogleDriveHelper failed" : err]
            )
        }
        return out
    }

    private static func parseJSON(_ text: String) -> [String: Any] {
        guard let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return object
    }
}
