import Foundation
import RuntimeContracts

/// Builds HTML/PDF/XML report artifacts under Application Support after a scan.
enum ReportGenerator {
    struct GeneratedReport: Sendable {
        let folderName: String
        let htmlURL: URL
        let pdfURL: URL?
        let xmlURL: URL
        let reportUrlPath: String
        let pdfUrlPath: String?
        let xmlUrlPath: String
        let fileReportURL: String
        let filePdfURL: String?
        let fileXmlURL: String
    }

    enum GeneratorError: LocalizedError {
        case missingXML(URL)
        case missingStylesheet
        case xsltFailed(String)
        case copyFailed(String)

        var errorDescription: String? {
            switch self {
            case .missingXML(let url):
                return "Scan XML not found at \(url.path)"
            case .missingStylesheet:
                return "nmap-modern.xsl stylesheet was not found"
            case .xsltFailed(let message):
                return "HTML report generation failed: \(message)"
            case .copyFailed(let message):
                return "Failed to store report artifacts: \(message)"
            }
        }
    }

    static func generate(
        xmlSource: URL,
        dataDirectory: URL,
        customerProfile: RuntimeCustomerProfile,
        target: String,
        duration: String,
        hostCount: Int,
        scanKind: String,
        status: String = "success",
        error: String? = nil
    ) throws -> GeneratedReport {
        guard FileManager.default.fileExists(atPath: xmlSource.path) else {
            throw GeneratorError.missingXML(xmlSource)
        }

        let reportsRoot = dataDirectory.appendingPathComponent("reports_archive", isDirectory: true)
        let folderURL = reportsRoot.appendingPathComponent(customerProfile.folderName, isDirectory: true)
        try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true)

        let stamp = RuntimeReportNaming.formatTimestamp()
        let baseName = "\(customerProfile.reportLabel)-\(stamp)"
        let htmlURL = folderURL.appendingPathComponent("\(baseName).html")
        let pdfURL = folderURL.appendingPathComponent("\(baseName).pdf")
        let xmlURL = folderURL.appendingPathComponent("\(baseName).xml")

        do {
            if FileManager.default.fileExists(atPath: xmlURL.path) {
                try FileManager.default.removeItem(at: xmlURL)
            }
            try FileManager.default.copyItem(at: xmlSource, to: xmlURL)
        } catch {
            throw GeneratorError.copyFailed(error.localizedDescription)
        }

        let stylesheet = resolveStylesheetURL()
        guard let stylesheet else {
            throw GeneratorError.missingStylesheet
        }

        try runXSLT(xml: xmlURL, stylesheet: stylesheet, output: htmlURL)

        let generatedPDF = generatePDF(htmlURL: htmlURL, pdfURL: pdfURL) ? pdfURL : nil

        let reportPath = "/reports/\(customerProfile.folderName)/\(htmlURL.lastPathComponent)"
        let pdfPath = generatedPDF.map { "/reports/\(customerProfile.folderName)/\($0.lastPathComponent)" }
        let xmlPath = "/reports/\(customerProfile.folderName)/\(xmlURL.lastPathComponent)"

        let historyEntry = RuntimeReportHistoryEntry(
            timestamp: ISO8601DateFormatter().string(from: Date()),
            target: target,
            duration: duration,
            hostCount: hostCount,
            scanKind: scanKind,
            status: status,
            error: error,
            reportUrl: reportPath,
            pdfUrl: pdfPath,
            xmlUrl: xmlPath,
            customerProfile: customerProfile
        )
        var history = RuntimeMetadataStore.loadHistory(from: dataDirectory)
        history.insert(historyEntry, at: 0)
        if history.count > 200 {
            history = Array(history.prefix(200))
        }
        RuntimeMetadataStore.persistHistory(history, to: dataDirectory)

        return GeneratedReport(
            folderName: customerProfile.folderName,
            htmlURL: htmlURL,
            pdfURL: generatedPDF,
            xmlURL: xmlURL,
            reportUrlPath: reportPath,
            pdfUrlPath: pdfPath,
            xmlUrlPath: xmlPath,
            fileReportURL: htmlURL.absoluteString,
            filePdfURL: generatedPDF?.absoluteString,
            fileXmlURL: xmlURL.absoluteString
        )
    }

    static func resolveFileURL(forReportPath path: String, dataDirectory: URL) -> URL? {
        // Accept "/reports/folder/file.ext" or plain relative paths.
        var normalized = path
        if normalized.hasPrefix("/reports/") {
            normalized = String(normalized.dropFirst("/reports/".count))
        } else if normalized.hasPrefix("reports/") {
            normalized = String(normalized.dropFirst("reports/".count))
        }
        guard !normalized.isEmpty else { return nil }
        let url = dataDirectory
            .appendingPathComponent("reports_archive", isDirectory: true)
            .appendingPathComponent(normalized)
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    // MARK: - Tools

    private static func resolveStylesheetURL() -> URL? {
        let candidates = [
            RuntimeSettingsStore.currentRuntimeWorkDirectoryURL().appendingPathComponent("nmap-modern.xsl"),
            Bundle.main.resourceURL?.appendingPathComponent("nmap-modern.xsl"),
            Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/nmap-modern.xsl"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("nmap-modern.xsl")
        ].compactMap { $0 }
        return candidates.first(where: { FileManager.default.fileExists(atPath: $0.path) })
    }

    private static func runXSLT(xml: URL, stylesheet: URL, output: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xsltproc")
        process.arguments = ["-o", output.path, stylesheet.path, xml.path]
        let stderr = Pipe()
        process.standardError = stderr
        process.standardOutput = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            throw GeneratorError.xsltFailed(error.localizedDescription)
        }
        guard process.terminationStatus == 0, FileManager.default.fileExists(atPath: output.path) else {
            let message = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "xsltproc failed"
            throw GeneratorError.xsltFailed(message.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    private static func generatePDF(htmlURL: URL, pdfURL: URL) -> Bool {
        if runChromePDF(htmlURL: htmlURL, pdfURL: pdfURL) {
            return true
        }
        if runWkhtmlPDF(htmlURL: htmlURL, pdfURL: pdfURL) {
            return true
        }
        RuntimeDiagnosticsLogger.log("PDF generation skipped; no chromium/wkhtmltopdf available")
        return false
    }

    private static func runChromePDF(htmlURL: URL, pdfURL: URL) -> Bool {
        let chromeCandidates = [
            ProcessInfo.processInfo.environment["CHROME_PATH"],
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/opt/homebrew/bin/chromium",
            "/usr/local/bin/chromium"
        ].compactMap { $0 }

        guard let chrome = chromeCandidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return false
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: chrome)
        process.arguments = [
            "--headless=new",
            "--disable-gpu",
            "--no-pdf-header-footer",
            "--print-to-pdf=\(pdfURL.path)",
            htmlURL.absoluteString
        ]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return false
        }
        return process.terminationStatus == 0 && FileManager.default.fileExists(atPath: pdfURL.path)
    }

    private static func runWkhtmlPDF(htmlURL: URL, pdfURL: URL) -> Bool {
        let candidates = [
            "/usr/local/bin/wkhtmltopdf",
            "/opt/homebrew/bin/wkhtmltopdf",
            "/usr/bin/wkhtmltopdf"
        ]
        guard let binary = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return false
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = [
            "--quiet",
            "--enable-local-file-access",
            htmlURL.path,
            pdfURL.path
        ]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return false
        }
        return process.terminationStatus == 0 && FileManager.default.fileExists(atPath: pdfURL.path)
    }
}
