import Foundation
import RuntimeContracts

extension RuntimeReportMetadata {
    static func make(from uploadResult: [String: Any], uploadedAt: Date = Date()) -> RuntimeReportMetadata {
        let links = (uploadResult["uploaded"] as? [[String: Any]] ?? []).compactMap { file -> RuntimeReportDriveFile? in
            let name = (file["name"] as? String) ?? ""
            let webViewLink = (file["webViewLink"] as? String) ?? ""
            let id = (file["id"] as? String) ?? ""
            guard !name.isEmpty || !webViewLink.isEmpty || !id.isEmpty else { return nil }
            return RuntimeReportDriveFile(name: name, webViewLink: webViewLink, id: id)
        }
        return RuntimeReportMetadata(
            uploadedAt: ISO8601DateFormatter().string(from: uploadedAt),
            folderId: uploadResult["folder_id"] as? String,
            dayFolderId: uploadResult["day_folder_id"] as? String,
            links: links
        )
    }
}

enum RuntimeReportListBuilder {
    static func makeEntry(
        name: String,
        folder: String,
        url: String?,
        pdfName: String?,
        pdfUrl: String?,
        xmlName: String?,
        xmlUrl: String?,
        driveHtmlUrl: String?,
        drivePdfUrl: String?,
        date: Date,
        duration: String?,
        hostCount: Int?,
        status: String? = nil,
        error: String? = nil
    ) -> RuntimeReportListEntry {
        RuntimeReportListEntry(
            name: name,
            folder: folder,
            url: url,
            pdfName: pdfName,
            pdfUrl: pdfUrl,
            xmlName: xmlName,
            xmlUrl: xmlUrl,
            driveHtmlUrl: driveHtmlUrl,
            drivePdfUrl: drivePdfUrl,
            date: ISO8601DateFormatter().string(from: date),
            duration: duration,
            hostCount: hostCount,
            status: status,
            error: error
        )
    }
}

enum RuntimeFailedScanBuilder {
    static func makeEntry(
        timestamp: String,
        scanKind: String,
        folder: String,
        error: String,
        hostCount: Int,
        duration: String
    ) -> RuntimeFailedScanEntry {
        let scanLabel = scanKind == "complete" ? "Complete+PDF" : (scanKind.isEmpty ? "Scan" : scanKind)
        return RuntimeFailedScanEntry(
            timestamp: timestamp,
            scanLabel: scanLabel,
            folder: folder,
            status: "failed",
            error: error,
            hostCount: hostCount,
            duration: duration
        )
    }
}
