import Foundation
import RuntimeContracts

/// Headless entrypoint used by the LaunchAgent for unattended scheduled scans.
enum ScheduledScanRunner {
    static var isScheduledScanInvocation: Bool {
        CommandLine.arguments.contains("--scheduled-scan")
    }

    static func runAndExit() async {
        RuntimeDiagnosticsLogger.log("Scheduled scan invocation starting")
        let dataDirectory = RuntimeSettingsStore.currentDataDirectoryURL()
        RuntimeDiagnosticsLogger.configure(dataDirectory: dataDirectory)
        try? FileManager.default.createDirectory(
            at: dataDirectory.appendingPathComponent("logs", isDirectory: true),
            withIntermediateDirectories: true
        )
        try? FileManager.default.createDirectory(
            at: RuntimeSettingsStore.currentRuntimeWorkDirectoryURL(),
            withIntermediateDirectories: true
        )

        // Ensure nmap-modern.xsl is available in the work directory when bundled.
        copyStylesheetIfNeeded()

        let networkState = await RuntimeNetworkState.current()
        RuntimeMetadataStore.persistNetworkState(networkState, to: dataDirectory)

        let configURL = dataDirectory.appendingPathComponent("config.json")
        let json = (try? Data(contentsOf: configURL)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        let autoScan = (json?["autoScan"] as? [String: Any]) ?? [:]
        let enabled = autoScan["enabled"] as? Bool ?? false
        guard enabled else {
            RuntimeDiagnosticsLogger.log("Scheduled scan skipped: auto-scan disabled")
            exit(0)
        }

        let target = (autoScan["target"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedTarget = (target?.isEmpty == false ? target! : networkState.cidr)
        let scanKind = "complete"

        guard PrivilegeHelperClient.isHelperReachable else {
            RuntimeDiagnosticsLogger.error("Scheduled scan aborted: privileged helper is not installed/running")
            exit(2)
        }

        let coordinator = ScanCoordinator(workDirectory: RuntimeSettingsStore.newScanWorkDirectoryURL())
        let request = ScanCoordinator.ScanRequest(
            target: resolvedTarget,
            usePn: false,
            vpnHelper: false,
            scanKind: ScanCoordinator.ScanKind(scanKind),
            allowInteractivePrivilegePrompt: false
        )
        let result = await coordinator.runFullScan(request)
        RuntimeDiagnosticsLogger.log(
            "Scheduled scan finished completed=\(result.completed) phase=\(result.phase.rawValue) duration=\(result.duration) error=\(result.error ?? "none")"
        )

        if result.completed, let xmlPath = result.xmlPath, result.phase != .phase1 {
            let networkState = await RuntimeNetworkState.current()
            let profile = RuntimeCustomerProfile.current(prefix: "CSP", networkState: networkState)
            do {
                _ = try ReportGenerator.generate(
                    xmlSource: xmlPath,
                    dataDirectory: dataDirectory,
                    customerProfile: profile,
                    target: resolvedTarget,
                    duration: result.duration,
                    hostCount: result.summary?.hostCount ?? 0,
                    scanKind: scanKind,
                    status: "success",
                    error: nil
                )
                RuntimeDiagnosticsLogger.log("Scheduled scan report generated")
            } catch {
                RuntimeDiagnosticsLogger.error("Scheduled report generation failed: \(error.localizedDescription)")
            }
        } else if let summary = result.summary {
            var history = RuntimeMetadataStore.loadHistory(from: dataDirectory)
            let entry = RuntimeReportHistoryEntry(
                timestamp: ISO8601DateFormatter().string(from: Date()),
                target: resolvedTarget,
                duration: result.duration,
                hostCount: summary.hostCount,
                scanKind: scanKind,
                status: result.completed ? "success" : "failed",
                error: result.error,
                reportUrl: nil,
                pdfUrl: nil,
                xmlUrl: result.xmlPath.map { $0.path },
                customerProfile: nil
            )
            history.insert(entry, at: 0)
            if history.count > 200 {
                history = Array(history.prefix(200))
            }
            RuntimeMetadataStore.persistHistory(history, to: dataDirectory)
        }

        exit(result.completed ? 0 : 1)
    }

    private static func copyStylesheetIfNeeded() {
        let workDir = RuntimeSettingsStore.currentRuntimeWorkDirectoryURL()
        let destination = workDir.appendingPathComponent("nmap-modern.xsl")
        if FileManager.default.fileExists(atPath: destination.path) {
            return
        }
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent("nmap-modern.xsl"),
            Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/nmap-modern.xsl")
        ].compactMap { $0 }
        for source in candidates where FileManager.default.fileExists(atPath: source.path) {
            try? FileManager.default.copyItem(at: source, to: destination)
            return
        }
    }
}
