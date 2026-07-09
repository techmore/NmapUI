import Foundation
import RuntimeContracts

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

    static func persistConfigSection(_ key: String, values: [String: RuntimeJSONValue], to directoryURL: URL) {
        let configURL = directoryURL.appendingPathComponent("config.json")
        let existing = (try? Data(contentsOf: configURL)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        var config = existing
        config[key] = values.mapValues { $0.toAnyJSONValue() }
        if let data = try? JSONSerialization.data(withJSONObject: config, options: [.sortedKeys, .prettyPrinted]) {
            try? data.write(to: configURL, options: [.atomic])
        }
    }

    static func persistGoogleDriveCredentials(_ credentialsJson: String, to directoryURL: URL) {
        let fileURL = directoryURL.appendingPathComponent("runtime-google-drive-credentials.json")
        do {
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try credentialsJson.data(using: .utf8)?.write(to: fileURL, options: [.atomic])
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

    static func persistHistory(_ history: [RuntimeReportHistoryEntry], to directoryURL: URL) {
        let fileManager = FileManager.default
        let metadataURL = directoryURL.appendingPathComponent("history.json")
        do {
            try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try JSONEncoder().encode(history).write(to: metadataURL, options: [.atomic])
        } catch {
            NSLog("Failed to persist runtime history metadata: \(error.localizedDescription)")
        }
    }

    static func loadHistory(from directoryURL: URL) -> [RuntimeReportHistoryEntry] {
        let metadataURL = directoryURL.appendingPathComponent("history.json")
        guard let data = try? Data(contentsOf: metadataURL) else { return [] }
        return (try? JSONDecoder().decode([RuntimeReportHistoryEntry].self, from: data)) ?? []
    }

    static func loadReportsSnapshot(reportsDirectory: URL, historyPath: URL) -> RuntimeReportsSnapshot {
        let history = loadHistory(from: historyPath.deletingLastPathComponent())
        let historyByReportUrl: [String: RuntimeReportHistoryEntry] = Dictionary(uniqueKeysWithValues: history.compactMap { entry in
            guard let reportUrl = entry.reportUrl else { return nil }
            return (reportUrl, entry)
        })
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
                driveHtmlUrl: nil,
                drivePdfUrl: nil,
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
