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
        screenshotURLs: [URL] = [],
        status: String = "success",
        error: String? = nil
    ) throws -> GeneratedReport {
        guard FileManager.default.fileExists(atPath: xmlSource.path) else {
            throw GeneratorError.missingXML(xmlSource)
        }

        let reportsRoot = dataDirectory.appendingPathComponent("reports_archive", isDirectory: true)
        let safeFolderName = RuntimeReportNaming.sanitizeSegment(customerProfile.folderName, fallback: "unknown")
        let folderURL = reportsRoot.appendingPathComponent(safeFolderName, isDirectory: true).standardizedFileURL
        guard folderURL.path.hasPrefix(reportsRoot.standardizedFileURL.path + "/") else {
            throw GeneratorError.copyFailed("Unsafe customer report directory")
        }
        try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true)

        let now = Date()
        let milliseconds = Int(now.timeIntervalSince1970 * 1_000) % 1_000
        let uniqueSuffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8)
        let stamp = "\(RuntimeReportNaming.formatTimestamp(now))_\(String(format: "%03d", milliseconds))_\(uniqueSuffix)"
        let baseName = "\(RuntimeReportNaming.sanitizeSegment(customerProfile.reportLabel, fallback: "report"))-\(stamp)"
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

        try archiveScreenshots(screenshotURLs, beside: htmlURL)
        let historyBeforeReport = RuntimeMetadataStore.loadHistory(from: dataDirectory)
        let comparison = previousComparison(
            currentXML: xmlURL,
            target: target,
            customerID: customerProfile.customerID,
            history: historyBeforeReport,
            dataDirectory: dataDirectory
        )
        try archiveComparison(comparison, in: htmlURL)

        let generatedPDF = generatePDF(htmlURL: htmlURL, pdfURL: pdfURL) ? pdfURL : nil
        let pdfUnavailable = scanKind == "complete" && status == "success" && generatedPDF == nil
        let effectiveStatus = pdfUnavailable ? "completedWithoutPDF" : status
        let effectiveError = pdfUnavailable ? (error ?? "PDF renderer unavailable") : error

        let reportPath = "/reports/\(safeFolderName)/\(htmlURL.lastPathComponent)"
        let pdfPath = generatedPDF.map { "/reports/\(safeFolderName)/\($0.lastPathComponent)" }
        let xmlPath = "/reports/\(safeFolderName)/\(xmlURL.lastPathComponent)"

        let historyEntry = RuntimeReportHistoryEntry(
            timestamp: ISO8601DateFormatter().string(from: Date()),
            target: target,
            duration: duration,
            hostCount: hostCount,
            scanKind: scanKind,
            status: effectiveStatus,
            error: effectiveError,
            reportUrl: reportPath,
            pdfUrl: pdfPath,
            xmlUrl: xmlPath,
            customerProfile: customerProfile,
            comparison: comparison
        )
        var history = historyBeforeReport
        history.insert(historyEntry, at: 0)
        if history.count > 200 {
            history = Array(history.prefix(200))
        }
        let persistence = RuntimeMetadataStore.persistHistory(history, to: dataDirectory)
        if case .failure(let persistenceError) = persistence {
            throw GeneratorError.copyFailed("Could not persist report history: \(persistenceError.localizedDescription)")
        }

        return GeneratedReport(
            folderName: safeFolderName,
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

    static func recordHistoryOnly(
        dataDirectory: URL,
        customerProfile: RuntimeCustomerProfile,
        target: String,
        duration: String,
        hostCount: Int,
        scanKind: String,
        status: String,
        error: String?
    ) {
        let entry = RuntimeReportHistoryEntry(
            timestamp: ISO8601DateFormatter().string(from: Date()),
            target: target,
            duration: duration,
            hostCount: hostCount,
            scanKind: scanKind,
            status: status,
            error: error,
            reportUrl: nil,
            pdfUrl: nil,
            xmlUrl: nil,
            customerProfile: customerProfile
        )
        var history = RuntimeMetadataStore.loadHistory(from: dataDirectory)
        history.insert(entry, at: 0)
        RuntimeMetadataStore.persistHistory(Array(history.prefix(200)), to: dataDirectory)
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
        let reportsRoot = dataDirectory.appendingPathComponent("reports_archive", isDirectory: true).standardizedFileURL
        let url = dataDirectory
            .appendingPathComponent("reports_archive", isDirectory: true)
            .appendingPathComponent(normalized)
            .standardizedFileURL
        guard url.path.hasPrefix(reportsRoot.path + "/") else { return nil }
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    // MARK: - Tools

    private static func previousComparison(
        currentXML: URL,
        target: String,
        customerID: String?,
        history: [RuntimeReportHistoryEntry],
        dataDirectory: URL
    ) -> RuntimeScanComparison? {
        guard let previous = history.first(where: {
            $0.status == "success" && $0.target == target && $0.xmlUrl != nil && $0.customerProfile?.customerID == customerID
        }), let xmlPath = previous.xmlUrl,
              let previousXML = resolveFileURL(forReportPath: xmlPath, dataDirectory: dataDirectory),
              let current = RuntimeNmapXMLParser.parse(contentsOf: currentXML),
              let old = RuntimeNmapXMLParser.parse(contentsOf: previousXML) else { return nil }
        let comparison = current.comparison(to: old)
        return comparison.hasChanges ? comparison : nil
    }

    private static func archiveComparison(_ comparison: RuntimeScanComparison?, in htmlURL: URL) throws {
        guard let comparison, comparison.hasChanges else { return }
        let factPairs: [(Int, String)] = [
            (comparison.newHosts.count, "new host(s)"),
            (comparison.removedHosts.count, "removed host(s)"),
            (comparison.changedHosts.count, "changed host(s)"),
            (comparison.newPorts.count, "new port(s)"),
            (comparison.removedPorts.count, "removed port(s)"),
            (comparison.newVulnerabilities.count, "new vulnerability finding(s)"),
            (comparison.resolvedVulnerabilities.count, "resolved vulnerability finding(s)")
        ]
        var factLines: [String] = []
        for (count, label) in factPairs where count > 0 {
            factLines.append("<li>\(count) \(label)</li>")
        }
        let facts = factLines.joined()
        let section = "<section class=\"scan-comparison\"><h2>Changes Since Previous Scan</h2><ul>\(facts)</ul></section>"
        var html = try String(contentsOf: htmlURL, encoding: .utf8)
        if let bodyRange = html.range(of: "</body>", options: .caseInsensitive) {
            html.insert(contentsOf: section, at: bodyRange.lowerBound)
        } else {
            html.append(section)
        }
        try html.write(to: htmlURL, atomically: true, encoding: .utf8)
    }

    private static func archiveScreenshots(_ screenshots: [URL], beside htmlURL: URL) throws {
        guard !screenshots.isEmpty else { return }
        let folderName = htmlURL.deletingPathExtension().lastPathComponent + "-screenshots"
        let destination = htmlURL.deletingLastPathComponent().appendingPathComponent(folderName, isDirectory: true)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        var cards: [String] = []
        for (index, source) in screenshots.enumerated() where FileManager.default.fileExists(atPath: source.path) {
            let safeName = "\(index + 1)-\(RuntimeReportNaming.sanitizeSegment(source.lastPathComponent, fallback: "screenshot.jpg"))"
            let target = destination.appendingPathComponent(safeName)
            if FileManager.default.fileExists(atPath: target.path) { try FileManager.default.removeItem(at: target) }
            try FileManager.default.copyItem(at: source, to: target)
            let escapedLabel = source.lastPathComponent.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            cards.append("<article class=\"gowitness-card\"><a href=\"\(folderName)/\(safeName)\"><img src=\"\(folderName)/\(safeName)\" alt=\"\(escapedLabel)\"></a><div>\(escapedLabel)</div></article>")
        }
        guard !cards.isEmpty else { return }
        var html = try String(contentsOf: htmlURL, encoding: .utf8)
        let section = "<section class=\"gowitness-section\"><h2>Web Service Screenshots</h2><div class=\"gowitness-grid\">\(cards.joined())</div></section>"
        if let bodyRange = html.range(of: "</body>", options: .caseInsensitive) {
            html.insert(contentsOf: section, at: bodyRange.lowerBound)
        } else {
            html.append(section)
        }
        try html.write(to: htmlURL, atomically: true, encoding: .utf8)
    }

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
        do {
            let result = try ExternalProcessRunner.run(
                executable: URL(fileURLWithPath: "/usr/bin/xsltproc"),
                arguments: ["-o", output.path, stylesheet.path, xml.path],
                timeout: 2 * 60
            )
            guard result.exitCode == 0, !result.timedOut, FileManager.default.fileExists(atPath: output.path) else {
                throw GeneratorError.xsltFailed(result.timedOut ? "xsltproc timed out" : result.stderr)
            }
        } catch {
            if let error = error as? GeneratorError { throw error }
            throw GeneratorError.xsltFailed(error.localizedDescription)
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

        let arguments = [
            "--headless=new",
            "--disable-gpu",
            "--no-pdf-header-footer",
            "--print-to-pdf=\(pdfURL.path)",
            htmlURL.absoluteString
        ]
        do {
            let result = try ExternalProcessRunner.run(executable: URL(fileURLWithPath: chrome), arguments: arguments, timeout: 3 * 60)
            return result.exitCode == 0 && !result.timedOut && FileManager.default.fileExists(atPath: pdfURL.path)
        } catch {
            return false
        }
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
        let arguments = [
            "--quiet",
            "--enable-local-file-access",
            htmlURL.path,
            pdfURL.path
        ]
        do {
            let result = try ExternalProcessRunner.run(executable: URL(fileURLWithPath: binary), arguments: arguments, timeout: 3 * 60)
            return result.exitCode == 0 && !result.timedOut && FileManager.default.fileExists(atPath: pdfURL.path)
        } catch {
            return false
        }
    }
}
