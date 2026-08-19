import Foundation
import Darwin
import RuntimeContracts

enum RuntimeMetadataStoreError: LocalizedError {
    case lockUnavailable(String)
    case corruptConfiguration

    var errorDescription: String? {
        switch self {
        case .lockUnavailable(let path): return "Could not lock metadata file at \(path)"
        case .corruptConfiguration: return "Configuration is corrupt and no valid backup is available"
        }
    }
}

struct RuntimeMetadataStore {
    static func persistIdentity(_ identity: RuntimeIdentity, to directoryURL: URL) {
        let fileManager = FileManager.default
        let metadataURL = directoryURL.appendingPathComponent("runtime-identity.json")
        do {
            try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try JSONEncoder().encode(identity).write(to: metadataURL, options: [.atomic])
        } catch {
            NSLog("Failed to persist runtime identity metadata: \(error.localizedDescription)")
        }
    }

    static func loadIdentity(from directoryURL: URL) -> RuntimeIdentity? {
        let metadataURL = directoryURL.appendingPathComponent("runtime-identity.json")
        guard let data = try? Data(contentsOf: metadataURL) else { return nil }
        return try? JSONDecoder().decode(RuntimeIdentity.self, from: data)
    }

    static func persistCapabilities(_ capabilities: RuntimeCapabilities, to directoryURL: URL) {
        let fileManager = FileManager.default
        let metadataURL = directoryURL.appendingPathComponent("runtime-capabilities.json")
        do {
            try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try JSONEncoder().encode(capabilities).write(to: metadataURL, options: [.atomic])
        } catch {
            NSLog("Failed to persist runtime capabilities metadata: \(error.localizedDescription)")
        }
    }

    static func persistToolchain(_ toolchain: RuntimeToolchain, to directoryURL: URL) {
        let fileManager = FileManager.default
        let metadataURL = directoryURL.appendingPathComponent("runtime-toolchain.json")
        do {
            try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try JSONEncoder().encode(toolchain).write(to: metadataURL, options: [.atomic])
        } catch {
            NSLog("Failed to persist runtime toolchain metadata: \(error.localizedDescription)")
        }
    }

    static func loadToolchain(from directoryURL: URL) -> RuntimeToolchain? {
        let metadataURL = directoryURL.appendingPathComponent("runtime-toolchain.json")
        guard let data = try? Data(contentsOf: metadataURL) else { return nil }
        return try? JSONDecoder().decode(RuntimeToolchain.self, from: data)
    }

    static func persistNetworkState(_ state: RuntimeNetworkState, to directoryURL: URL) {
        let fileManager = FileManager.default
        let metadataURL = directoryURL.appendingPathComponent("runtime-network.json")
        do {
            try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try JSONEncoder().encode(state).write(to: metadataURL, options: [.atomic])
        } catch {
            NSLog("Failed to persist runtime network metadata: \(error.localizedDescription)")
        }
    }

    static func loadNetworkState(from directoryURL: URL) -> RuntimeNetworkState? {
        let metadataURL = directoryURL.appendingPathComponent("runtime-network.json")
        guard let data = try? Data(contentsOf: metadataURL) else { return nil }
        return try? JSONDecoder().decode(RuntimeNetworkState.self, from: data)
    }

    static func persistCustomerProfile(_ profile: RuntimeCustomerProfile, to directoryURL: URL) {
        let fileManager = FileManager.default
        let metadataURL = directoryURL.appendingPathComponent("runtime-customer-profile.json")
        do {
            try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try JSONEncoder().encode(profile).write(to: metadataURL, options: [.atomic])
        } catch {
            NSLog("Failed to persist runtime customer profile metadata: \(error.localizedDescription)")
        }
    }

    static func loadCustomerProfile(from directoryURL: URL) -> RuntimeCustomerProfile? {
        let metadataURL = directoryURL.appendingPathComponent("runtime-customer-profile.json")
        guard let data = try? Data(contentsOf: metadataURL) else { return nil }
        return try? JSONDecoder().decode(RuntimeCustomerProfile.self, from: data)
    }

    static func loadCustomerProfilePrefix(from directoryURL: URL) -> String {
        let configURL = directoryURL.appendingPathComponent("config.json")
        guard
            let data = try? Data(contentsOf: configURL),
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let prefix = (json["customerProfile"] as? [String: Any])?["prefix"] as? String,
            !prefix.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            return "CSP"
        }
        return prefix
    }

    @discardableResult
    static func persistConfigSection(_ key: String, values: [String: RuntimeJSONValue], to directoryURL: URL) -> Result<Void, Error> {
        do {
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            let lockURL = directoryURL.appendingPathComponent("config.lock")
            let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
            guard descriptor >= 0 else { throw RuntimeMetadataStoreError.lockUnavailable(lockURL.path) }
            defer { flock(descriptor, LOCK_UN); close(descriptor) }
            guard flock(descriptor, LOCK_EX) == 0 else { throw RuntimeMetadataStoreError.lockUnavailable(lockURL.path) }

            let configURL = directoryURL.appendingPathComponent("config.json")
            let backupURL = configURL.appendingPathExtension("backup")
            var config: [String: Any]
            var recoveredFromBackup = false
            if let data = try? Data(contentsOf: configURL),
               let decoded = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                config = decoded
            } else if let data = try? Data(contentsOf: backupURL),
                      let decoded = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                config = decoded
                RuntimeDiagnosticsLogger.error("Configuration file is corrupt; recovered the previous snapshot")
                recoveredFromBackup = true
            } else if FileManager.default.fileExists(atPath: configURL.path) {
                throw RuntimeMetadataStoreError.corruptConfiguration
            } else {
                config = [:]
            }

            config[key] = values.mapValues { $0.toAnyJSONValue() }
            let data = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys, .prettyPrinted])
            if FileManager.default.fileExists(atPath: configURL.path), !recoveredFromBackup {
                try? FileManager.default.removeItem(at: backupURL)
                try FileManager.default.copyItem(at: configURL, to: backupURL)
            }
            try data.write(to: configURL, options: [.atomic])
            return .success(())
        } catch {
            RuntimeDiagnosticsLogger.error("Failed to persist configuration section \(key): \(error.localizedDescription)")
            return .failure(error)
        }
    }

    static func persistGoogleDriveCredentials(_ credentialsJson: String, to directoryURL: URL) {
        let fileURL = directoryURL.appendingPathComponent("runtime-google-drive-credentials.json")
        do {
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            guard let data = credentialsJson.data(using: .utf8) else { return }
            try data.write(to: fileURL, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            NSLog("Failed to persist runtime Google Drive credentials: \(error.localizedDescription)")
        }
    }

    static func loadGoogleDriveCredentials(from directoryURL: URL) -> String? {
        let fileURL = directoryURL.appendingPathComponent("runtime-google-drive-credentials.json")
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func persistReportMetadata(_ metadata: RuntimeReportMetadata, to reportPath: URL) {
        let metadataURL = reportPath.appendingPathExtension("drive.json")
        do {
            try FileManager.default.createDirectory(at: reportPath.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(metadata).write(to: metadataURL, options: [.atomic])
        } catch {
            NSLog("Failed to persist report drive metadata: \(error.localizedDescription)")
        }
    }

    static func loadReportMetadata(from reportPath: URL) -> RuntimeReportMetadata? {
        let metadataURL = reportPath.appendingPathExtension("drive.json")
        guard let data = try? Data(contentsOf: metadataURL) else { return nil }
        return try? JSONDecoder().decode(RuntimeReportMetadata.self, from: data)
    }

    @discardableResult
    static func persistHistory(_ history: [RuntimeReportHistoryEntry], to directoryURL: URL) -> Result<Void, Error> {
        let fileManager = FileManager.default
        let metadataURL = directoryURL.appendingPathComponent("history.json")
        let lockURL = directoryURL.appendingPathComponent("history.lock")
        try? fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else {
            NSLog("Failed to lock runtime history metadata")
            return .failure(CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey: "Could not open the history lock file."]))
        }
        defer { flock(descriptor, LOCK_UN); close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else {
            return .failure(CocoaError(.fileLocking, userInfo: [NSLocalizedDescriptionKey: "Could not lock the history file."]))
        }
        do {
            let existing = loadHistoryUnlocked(from: metadataURL)
            let incomingKeys = Set(history.map(historyKey))
            let merged = (history + existing.filter { !incomingKeys.contains(historyKey($0)) })
                .sorted { $0.timestamp > $1.timestamp }
            let backupURL = metadataURL.appendingPathExtension("backup")
            if fileManager.fileExists(atPath: metadataURL.path) {
                if fileManager.fileExists(atPath: backupURL.path) { try fileManager.removeItem(at: backupURL) }
                try fileManager.copyItem(at: metadataURL, to: backupURL)
            }
            try JSONEncoder().encode(Array(merged.prefix(200))).write(to: metadataURL, options: [.atomic])
            return .success(())
        } catch {
            NSLog("Failed to persist runtime history metadata: \(error.localizedDescription)")
            return .failure(error)
        }
    }

    static func loadHistory(from directoryURL: URL) -> [RuntimeReportHistoryEntry] {
        let metadataURL = directoryURL.appendingPathComponent("history.json")
        return loadHistoryUnlocked(from: metadataURL)
    }

    private static func loadHistoryUnlocked(from metadataURL: URL) -> [RuntimeReportHistoryEntry] {
        let backupURL = metadataURL.appendingPathExtension("backup")
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: metadataURL.path) || fileManager.fileExists(atPath: backupURL.path) else {
            return []
        }
        if FileManager.default.fileExists(atPath: metadataURL.path),
           let data = try? Data(contentsOf: metadataURL),
           let history = try? JSONDecoder().decode([RuntimeReportHistoryEntry].self, from: data) {
            return history
        }
        if let data = try? Data(contentsOf: backupURL), let history = try? JSONDecoder().decode([RuntimeReportHistoryEntry].self, from: data) {
            RuntimeDiagnosticsLogger.error("History file is corrupt; recovered the previous snapshot")
            return history
        }
        RuntimeDiagnosticsLogger.error("History file is corrupt and no valid backup exists")
        return []
    }

    private static func historyKey(_ entry: RuntimeReportHistoryEntry) -> String {
        if let reportUrl = entry.reportUrl, !reportUrl.isEmpty {
            return "report:\(reportUrl)"
        }
        return [
            entry.timestamp,
            entry.target,
            entry.scanKind,
            entry.customerProfile?.customerID ?? ""
        ].joined(separator: "\u{1f}")
    }

    static func loadReportsSnapshot(reportsDirectory: URL, historyPath: URL) -> RuntimeReportsSnapshot {
        let history = loadHistory(from: historyPath.deletingLastPathComponent())
        // History can contain retry/migration duplicates; keep the newest entry instead of trapping.
        let historyByReportUrl = history.reduce(into: [String: RuntimeReportHistoryEntry]()) { result, entry in
            guard let reportUrl = entry.reportUrl else { return }
            if let existing = result[reportUrl], existing.timestamp >= entry.timestamp { return }
            result[reportUrl] = entry
        }
        var reports: [RuntimeReportListEntry] = []
        guard FileManager.default.fileExists(atPath: reportsDirectory.path) else {
            return RuntimeReportsSnapshot.make(reports: [])
        }

        let enumerator = FileManager.default.enumerator(at: reportsDirectory, includingPropertiesForKeys: [.isDirectoryKey, .contentModificationDateKey], options: [.skipsHiddenFiles])
        while let fileURL = enumerator?.nextObject() as? URL {
            let values = try? fileURL.resourceValues(forKeys: [.isDirectoryKey])
            if values?.isDirectory == true { continue }
            guard fileURL.pathExtension.lowercased() == "html" else { continue }

            let reportDirectory = fileURL.deletingLastPathComponent()
            let folder = reportDirectory.lastPathComponent
            let name = fileURL.lastPathComponent
            let url = "/reports/\(folder)/\(name)"
            let pdfName = fileURL.deletingPathExtension().lastPathComponent + ".pdf"
            let xmlName = fileURL.deletingPathExtension().lastPathComponent + ".xml"
            let pdfURL = reportDirectory.appendingPathComponent(pdfName)
            let xmlURL = reportDirectory.appendingPathComponent(xmlName)
            let historyEntry = historyByReportUrl[url]
            let driveMetadata = loadReportMetadata(from: fileURL)
            let driveHTMLURL = driveMetadata?.links.first(where: { $0.name == name })?.webViewLink
            let drivePDFURL = driveMetadata?.links.first(where: { $0.name == pdfName })?.webViewLink
            let fileDate = (try? fileURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)?.ISO8601Format()
            let date = historyEntry?.timestamp ?? fileDate ?? Date().ISO8601Format()
            reports.append(RuntimeReportListEntry(
                name: name,
                folder: folder,
                url: url,
                pdfName: FileManager.default.fileExists(atPath: pdfURL.path) ? pdfName : nil,
                pdfUrl: FileManager.default.fileExists(atPath: pdfURL.path) ? "/reports/\(folder)/\(pdfName)" : nil,
                xmlName: FileManager.default.fileExists(atPath: xmlURL.path) ? xmlName : nil,
                xmlUrl: FileManager.default.fileExists(atPath: xmlURL.path) ? "/reports/\(folder)/\(xmlName)" : nil,
                driveHtmlUrl: driveHTMLURL,
                drivePdfUrl: drivePDFURL,
                date: date,
                duration: historyEntry?.duration,
                hostCount: historyEntry?.hostCount,
                status: historyEntry?.status,
                error: historyEntry?.error
            ))
        }

        history
            .filter { $0.status == "failed" }
            .forEach { entry in
                let date = entry.timestamp
                let scanLabel = entry.scanKind == "complete" ? "Complete+PDF" : (entry.scanKind.isEmpty ? "Scan" : entry.scanKind)
                reports.append(RuntimeReportListEntry(
                    name: "Failed \(scanLabel) scan - \(date)",
                    folder: entry.customerProfile?.folderName ?? "",
                    url: nil,
                    pdfName: nil,
                    pdfUrl: nil,
                    xmlName: nil,
                    xmlUrl: nil,
                    driveHtmlUrl: nil,
                    drivePdfUrl: nil,
                    date: date,
                    duration: entry.duration,
                    hostCount: entry.hostCount,
                    status: "failed",
                    error: entry.error
                ))
            }

        return RuntimeReportsSnapshot.make(reports: reports.sorted { $0.date > $1.date })
    }

    static func loadCapabilities(from directoryURL: URL) -> RuntimeCapabilities? {
        let metadataURL = directoryURL.appendingPathComponent("runtime-capabilities.json")
        guard let data = try? Data(contentsOf: metadataURL) else { return nil }
        return try? JSONDecoder().decode(RuntimeCapabilities.self, from: data)
    }
}

private extension RuntimeJSONValue {
    func toAnyJSONValue() -> Any {
        switch self {
        case .string(let value): return value
        case .bool(let value): return value
        case .int(let value): return value
        case .double(let value): return value
        case .array(let values): return values.map { $0.toAnyJSONValue() }
        case .object(let value): return value.mapValues { $0.toAnyJSONValue() }
        case .null: return NSNull()
        }
    }
}
