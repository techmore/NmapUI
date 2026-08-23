import Darwin
import Foundation
import RuntimeContracts

final class ScanCoordinator: @unchecked Sendable {
    private enum Artifact {
        static let phase1XML = "phase1_results.xml"
        static let phase2XML = "phase2_results.xml"
        static let phase2Progress = "phase2_progress.gnmap"
        static let targets = "targets.tmp"
    }

    enum Phase: Int {
        case phase1 = 1
        case phase2 = 2
        case phase3 = 3
    }

    enum ScanKind {
        case quick
        case complete
        case dragnet

        init(_ value: String) {
            switch value {
            case "complete":
                self = .complete
            case "dragnet":
                self = .dragnet
            default:
                self = .quick
            }
        }

        /// Complete/dragnet use privileged scan types (-sS/-O). Quick host discovery usually does not.
        var requiresPrivilegedNmap: Bool {
            switch self {
            case .quick:
                return false
            case .complete, .dragnet:
                return true
            }
        }
    }

    struct ScanRequest {
        let target: String
        let usePn: Bool
        let vpnHelper: Bool
        let scanKind: ScanKind
        /// When false (scheduled runs), never show an interactive admin prompt.
        let allowInteractivePrivilegePrompt: Bool
    }

    struct ScanResult: Sendable {
        let phase: Phase
        let duration: String
        let xmlPath: URL?
        let summary: RuntimeNmapXMLSummary?
        let completed: Bool
        let error: String?
    }

    private let workDirectory: URL
    private let nmapPath: String
    let scanID: UUID
    private let stateQueue = DispatchQueue(label: "com.techmore.nmapui.scan-coordinator")
    private var cancelRequested = false

    init(
        workDirectory: URL = RuntimeSettingsStore.currentRuntimeWorkDirectoryURL(),
        nmapPath: String = RuntimeToolchain.current().nmapPath ?? "nmap",
        scanID: UUID = UUID()
    ) {
        self.workDirectory = workDirectory
        self.nmapPath = nmapPath
        self.scanID = scanID
    }

    var workDirectoryURL: URL { workDirectory }

    func cancel() {
        stateQueue.sync {
            cancelRequested = true
        }
        PrivilegeHelperClient.cancelActiveScan(scanID: scanID)
        RuntimeDiagnosticsLogger.log("Scan cancel requested")
    }

    func resetCancelFlag() {
        stateQueue.sync {
            cancelRequested = false
        }
    }

    func runPhase1(_ request: ScanRequest) async -> ScanResult {
        guard let target = try? ScanTargetValidator.validate(request.target) else {
            return invalidTargetResult(request.target)
        }
        let privilegedARP = request.scanKind.requiresPrivilegedNmap
        return await run(
            nmapArguments: Self.phase1Arguments(target: target, privilegedARP: privilegedARP),
            phase: .phase1,
            preferPrivileged: privilegedARP,
            useInstalledHelper: privilegedARP,
            allowInteractivePrivilegePrompt: request.allowInteractivePrivilegePrompt
        )
    }

    static func phase1Arguments(target: String, privilegedARP: Bool) -> [String] {
        var arguments = ["-sn"]
        if privilegedARP { arguments.append("-PR") }
        arguments.append(contentsOf: ["-T4", "--host-timeout", "12s", "--max-retries", "1", "-oX", Artifact.phase1XML])
        arguments.append(contentsOf: target.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init))
        return arguments
    }

    func runPhase2(
        _ request: ScanRequest,
        onHostProgress: @MainActor @Sendable @escaping ([RuntimeNmapXMLHostSummary]) -> Void = { _ in }
    ) async -> ScanResult {
        let args = Self.completeScanArguments(usePn: request.usePn, vpnHelper: request.vpnHelper)
        return await run(
            nmapArguments: args,
            phase: .phase2,
            preferPrivileged: true,
            onHostProgress: onHostProgress,
            allowInteractivePrivilegePrompt: request.allowInteractivePrivilegePrompt
        )
    }

    /// Quick scans use TCP connect rather than SYN scanning so they do not need elevation.
    func runQuickPortScan(_ request: ScanRequest) async -> ScanResult {
        await run(
            nmapArguments: Self.quickPortScanArguments(vpnHelper: request.vpnHelper, target: nil),
            phase: .phase2,
            preferPrivileged: false,
            useInstalledHelper: false,
            allowInteractivePrivilegePrompt: request.allowInteractivePrivilegePrompt
        )
    }

    func runDragnet(allowInteractivePrivilegePrompt: Bool) async -> ScanResult {
        let args = ["-sV", "-p-", "--script", RuntimeVulners.scriptPath(), "--script-args", "mincvss=0,threads=10", "-oX", Artifact.phase2XML, "-iL", Artifact.targets]
        return await run(
            nmapArguments: args,
            phase: .phase3,
            preferPrivileged: true,
            allowInteractivePrivilegePrompt: allowInteractivePrivilegePrompt
        )
    }

    func runFullScan(
        _ request: ScanRequest,
        onPhaseStarted: @MainActor @Sendable @escaping (Phase, String) -> Void = { _, _ in },
        onPhaseCompleted: @MainActor @Sendable @escaping (ScanResult) -> Void = { _ in },
        onHostProgress: @MainActor @Sendable @escaping ([RuntimeNmapXMLHostSummary]) -> Void = { _ in }
    ) async -> ScanResult {
        resetCancelFlag()
        do {
            _ = try ScanTargetValidator.validate(request.target)
        } catch {
            return invalidTargetResult(request.target, error: error.localizedDescription)
        }
        if request.scanKind.requiresPrivilegedNmap, RuntimeVulners.resolvedScriptURL == nil {
            return ScanResult(
                phase: .phase1,
                duration: "0.00",
                xmlPath: nil,
                summary: nil,
                completed: false,
                error: "The bundled Vulners script is missing; install or repair the NmapUI bundle before running a complete scan."
            )
        }
        RuntimeDiagnosticsLogger.log(
            "Running full scan target=\(request.target) kind=\(request.scanKind) interactivePrivilege=\(request.allowInteractivePrivilegePrompt) euid=\(geteuid())"
        )

        if request.scanKind.requiresPrivilegedNmap {
            do {
                if request.allowInteractivePrivilegePrompt {
                    try await PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true)
                } else if !PrivilegeHelperClient.isHelperReachable {
                    return ScanResult(
                        phase: .phase1,
                        duration: "0.00",
                        xmlPath: nil,
                        summary: nil,
                        completed: false,
                        error: "Privileged helper is not installed; cannot run unattended privileged scan."
                    )
                }
            } catch {
                await MainActor.run {
                    PrivilegeElevationController.presentHelperInstallFailure(error)
                }
                return ScanResult(
                    phase: .phase1,
                    duration: "0.00",
                    xmlPath: nil,
                    summary: nil,
                    completed: false,
                    error: error.localizedDescription
                )
            }
        }

        await onPhaseStarted(.phase1, "Phase 1 of 2: discovering live hosts and collecting network identity")
        let phase1Raw = await runPhase1(request)
        let phase1: ScanResult
        if let summary = phase1Raw.summary {
            let enriched = await ARPDiscovery.enrich(summary, target: request.target)
            phase1 = ScanResult(phase: phase1Raw.phase, duration: phase1Raw.duration, xmlPath: phase1Raw.xmlPath, summary: enriched, completed: phase1Raw.completed, error: phase1Raw.error)
        } else {
            phase1 = phase1Raw
        }
        await onPhaseCompleted(phase1)
        if isCancelled {
            return cancelledResult(phase: .phase1, duration: phase1.duration)
        }
        guard phase1.completed, let summary = phase1.summary, summary.hosts.isEmpty == false else {
            RuntimeDiagnosticsLogger.log("Phase 1 finished completed=\(phase1.completed) hosts=\(phase1.summary?.hostCount ?? 0)")
            return phase1
        }
        writeTargetsFile(from: summary)
        if request.scanKind == .dragnet {
            await onPhaseStarted(.phase3, "Phase 3: deep all-port and vulnerability scan of \(summary.hostCount) discovered hosts")
            RuntimeDiagnosticsLogger.log("Entering dragnet phase")
            let result = await runDragnet(allowInteractivePrivilegePrompt: request.allowInteractivePrivilegePrompt)
            return isCancelled ? cancelledResult(phase: .phase3, duration: result.duration) : result
        }
        if request.scanKind == .quick {
            await onPhaseStarted(.phase2, "Phase 2 of 2: common-port and service scan of \(summary.hostCount) discovered hosts")
            RuntimeDiagnosticsLogger.log("Entering quick TCP port scan")
            let result = await runQuickPortScan(request)
            return isCancelled ? cancelledResult(phase: .phase2, duration: result.duration) : result
        }
        await onPhaseStarted(.phase2, "Phase 2 of 2: deep SYN, service, OS, and vulnerability scan of \(summary.hostCount) discovered hosts")
        RuntimeDiagnosticsLogger.log("Entering phase 2")
        let result = await runPhase2(request, onHostProgress: onHostProgress)
        return isCancelled ? cancelledResult(phase: .phase2, duration: result.duration) : result
    }

    private var isCancelled: Bool {
        stateQueue.sync { cancelRequested }
    }

    private func cancelledResult(phase: Phase, duration: String) -> ScanResult {
        ScanResult(
            phase: phase,
            duration: duration,
            xmlPath: nil,
            summary: nil,
            completed: false,
            error: "Scan cancelled"
        )
    }

    private func run(
        nmapArguments: [String],
        phase: Phase,
        preferPrivileged: Bool,
        useInstalledHelper: Bool = true,
        onHostProgress: @MainActor @Sendable @escaping ([RuntimeNmapXMLHostSummary]) -> Void = { _ in },
        allowInteractivePrivilegePrompt: Bool
    ) async -> ScanResult {
        let startedAt = Date()
        try? FileManager.default.createDirectory(at: workDirectory, withIntermediateDirectories: true)

        let resolvedNmap = resolvedNmapPath()
        RuntimeDiagnosticsLogger.log(
            "Launching nmap phase=\(phase.rawValue) preferPrivileged=\(preferPrivileged) helperReady=\(PrivilegeHelperClient.isHelperReachable) euid=\(geteuid()) nmap=\(resolvedNmap) args=\(nmapArguments.joined(separator: " ")) workDirectory=\(workDirectory.path)"
        )

        if isCancelled {
            return cancelledResult(phase: phase, duration: "0.00")
        }

        let progressTask = phase == .phase2 ? Task {
            var lastSignature = ""
            while !Task.isCancelled {
                let hosts = RuntimeNmapGrepableParser.parse(contentsOf: workDirectory.appendingPathComponent(Artifact.phase2Progress))
                let signature = hosts.map { "\($0.ip)|\($0.ports)|\($0.version)" }.joined(separator: "\n")
                if !hosts.isEmpty, signature != lastSignature {
                    lastSignature = signature
                    await onHostProgress(hosts)
                }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        } : nil
        defer { progressTask?.cancel() }

        let useHelper = preferPrivileged || (useInstalledHelper && PrivilegeHelperClient.isHelperReachable)
        if useHelper && (PrivilegeHelperClient.isHelperReachable || (preferPrivileged && allowInteractivePrivilegePrompt)) {
            do {
                if preferPrivileged && !PrivilegeHelperClient.isHelperReachable && allowInteractivePrivilegePrompt {
                    try await PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true)
                }
                let result = try PrivilegeHelperClient.runNmap(
                    nmapPath: resolvedNmap,
                    arguments: nmapArguments,
                    workDirectory: workDirectory,
                    scanID: scanID,
                    allowInteractiveFallback: allowInteractivePrivilegePrompt
                )
                return makeResult(phase: phase, startedAt: startedAt, exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr)
            } catch {
                // If privilege was not required, fall through to local unprivileged run.
                if preferPrivileged {
                    RuntimeDiagnosticsLogger.error("Privileged nmap failed phase=\(phase.rawValue) error=\(error.localizedDescription)")
                    return ScanResult(
                        phase: phase,
                        duration: String(format: "%.2f", Date().timeIntervalSince(startedAt)),
                        xmlPath: nil,
                        summary: nil,
                        completed: false,
                        error: error.localizedDescription
                    )
                }
                RuntimeDiagnosticsLogger.log("Helper unavailable for unprivileged phase; running locally: \(error.localizedDescription)")
            }
        }

        return await runLocally(nmapArguments: nmapArguments, phase: phase, startedAt: startedAt, resolvedNmap: resolvedNmap)
    }

    private func runLocally(
        nmapArguments: [String],
        phase: Phase,
        startedAt: Date,
        resolvedNmap: String
    ) async -> ScanResult {
        let executable: URL
        let arguments: [String]
        if resolvedNmap.contains("/") {
            executable = URL(fileURLWithPath: resolvedNmap)
            arguments = nmapArguments
        } else {
            executable = URL(fileURLWithPath: "/usr/bin/env")
            arguments = [resolvedNmap] + nmapArguments
        }
        do {
            // Drain both pipes concurrently. Waiting on Process directly can
            // deadlock when an unprivileged scan produces enough diagnostics
            // to fill either pipe's kernel buffer.
            let result = try await Task.detached(priority: .userInitiated) {
                try ExternalProcessRunner.run(
                    executable: executable,
                    arguments: arguments,
                    currentDirectory: self.workDirectory,
                    timeout: NmapPrivilegedHelperContract.maximumScanRuntime,
                    isCancelled: { self.isCancelled }
                )
            }.value
            return makeResult(
                phase: phase,
                startedAt: startedAt,
                exitCode: result.exitCode,
                stdout: result.stdout,
                stderr: result.stderr
            )
        } catch {
            RuntimeDiagnosticsLogger.error("Nmap launch failed phase=\(phase.rawValue) error=\(error.localizedDescription)")
            return ScanResult(phase: phase, duration: "0.00", xmlPath: nil, summary: nil, completed: false, error: error.localizedDescription)
        }
    }

    private func makeResult(phase: Phase, startedAt: Date, exitCode: Int32, stdout: String, stderr: String) -> ScanResult {
        if exitCode != 0 || !stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            RuntimeDiagnosticsLogger.error("Nmap phase=\(phase.rawValue) exited status=\(exitCode) stderr=\(stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        if !stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            RuntimeDiagnosticsLogger.log("Nmap phase=\(phase.rawValue) stdout=\(stdout.trimmingCharacters(in: .whitespacesAndNewlines).prefix(2000))")
        }

        let duration = String(format: "%.2f", Date().timeIntervalSince(startedAt))
        if isCancelled {
            return cancelledResult(phase: phase, duration: duration)
        }
        let xmlPath = workDirectory.appendingPathComponent(xmlFileName(for: phase))
        let summary = RuntimeNmapXMLParser.parse(contentsOf: xmlPath)
        let artifactIsValid = FileManager.default.fileExists(atPath: xmlPath.path) && summary != nil
        let completed = exitCode == 0 && artifactIsValid
        return ScanResult(
            phase: phase,
            duration: duration,
            xmlPath: FileManager.default.fileExists(atPath: xmlPath.path) ? xmlPath : nil,
            summary: summary,
            completed: completed,
            error: completed ? nil : (exitCode == 0 ? "Nmap completed without a valid XML result" : "Nmap exited with status \(exitCode)")
        )
    }

    private func resolvedNmapPath() -> String {
        if nmapPath.contains("/") {
            return nmapPath
        }
        return RuntimeToolchain.current().nmapPath ?? nmapPath
    }

    private func normalizeTargets(_ target: String) -> [String] {
        target
            .split(whereSeparator: { $0 == "," || $0 == "\n" })
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    static func completeScanArguments(usePn: Bool, vpnHelper: Bool, target: String? = nil) -> [String] {
        var args = ["-sS", "-sV", "-O", "-sC"]
        if usePn { args.append("-Pn") }
        args.append(vpnHelper ? "-T2" : "-T3")
        args.append(contentsOf: [
            "--open",
            "--host-timeout", "4m",
            "--script-timeout", "45s",
            "--max-retries", "1",
            "--max-rtt-timeout", "1000ms",
            "--min-hostgroup", "8",
            "--max-hostgroup", "16",
            "--script", RuntimeVulners.scriptPath(),
            "--script-args", vpnHelper ? "mincvss=0,threads=5" : "mincvss=0,threads=10",
            "--stylesheet", "nmap-modern.xsl",
            "-oX", Artifact.phase2XML,
            "-oG", Artifact.phase2Progress
        ])
        if let target, !target.isEmpty {
            args.append(contentsOf: target.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init))
        } else {
            args.append(contentsOf: ["-iL", Artifact.targets])
        }
        return args
    }

    static func quickPortScanArguments(vpnHelper: Bool, target: String? = nil) -> [String] {
        var args = [
            "-sT",
            "-sV",
            "--version-light",
            "--top-ports", "100",
            // #167 follow-up: 25s starves -sV version probes on slow IoT devices
            // (cameras/NAS), causing nmap to abort every host with zero ports.
            // 2m accommodates slow responders while still bounding runaway scans.
            "--host-timeout", "2m",
            "--max-retries", "1",
            vpnHelper ? "-T2" : "-T4",
            "--open",
            "-oX", Artifact.phase2XML
        ]
        if let target, !target.isEmpty {
            args.append(contentsOf: target.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init))
        } else {
            args.append(contentsOf: ["-iL", Artifact.targets])
        }
        return args
    }

    private func invalidTargetResult(_ target: String, error: String? = nil) -> ScanResult {
        ScanResult(
            phase: .phase1,
            duration: "0.00",
            xmlPath: nil,
            summary: nil,
            completed: false,
            error: error ?? "Invalid scan target: \(target)"
        )
    }

    private func xmlFileName(for phase: Phase) -> String {
        switch phase {
        case .phase1:
            return Artifact.phase1XML
        default:
            return Artifact.phase2XML
        }
    }

    private func writeTargetsFile(from summary: RuntimeNmapXMLSummary) {
        let targets = summary.hosts.map(\.ip).filter { !$0.isEmpty }.joined(separator: "\n")
        guard !targets.isEmpty else { return }
        let targetsURL = workDirectory.appendingPathComponent(Artifact.targets)
        try? targets.write(to: targetsURL, atomically: true, encoding: .utf8)
    }
}
