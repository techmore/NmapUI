import Darwin
import Foundation
import RuntimeContracts

final class ScanCoordinator: @unchecked Sendable {
    private enum Artifact {
        static let phase1XML = "phase1_results.xml"
        static let phase2XML = "phase2_results.xml"
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

    struct ScanResult {
        let phase: Phase
        let duration: String
        let xmlPath: URL?
        let summary: RuntimeNmapXMLSummary?
        let completed: Bool
        let error: String?
    }

    private let workDirectory: URL
    private let nmapPath: String
    private let stateQueue = DispatchQueue(label: "com.techmore.nmapui.scan-coordinator")
    private var cancelRequested = false
    private var activeLocalProcess: Process?

    init(
        workDirectory: URL = RuntimeSettingsStore.currentRuntimeWorkDirectoryURL(),
        nmapPath: String = RuntimeToolchain.current().nmapPath ?? "nmap"
    ) {
        self.workDirectory = workDirectory
        self.nmapPath = nmapPath
    }

    func cancel() {
        let process: Process? = stateQueue.sync {
            cancelRequested = true
            return activeLocalProcess
        }
        process?.terminate()
        PrivilegeHelperClient.cancelActiveScan()
        RuntimeDiagnosticsLogger.log("Scan cancel requested")
    }

    func resetCancelFlag() {
        stateQueue.sync {
            cancelRequested = false
        }
    }

    func runPhase1(_ request: ScanRequest) async -> ScanResult {
        // Host discovery: prefer unprivileged; still works elevated if needed.
        await run(
            nmapArguments: ["-sn", "-T4", "-oX", Artifact.phase1XML] + normalizeTargets(request.target),
            phase: .phase1,
            preferPrivileged: false,
            allowInteractivePrivilegePrompt: request.allowInteractivePrivilegePrompt
        )
    }

    func runPhase2(_ request: ScanRequest) async -> ScanResult {
        let args = buildPhase2Args(usePn: request.usePn, vpnHelper: request.vpnHelper)
        return await run(
            nmapArguments: args,
            phase: .phase2,
            preferPrivileged: true,
            allowInteractivePrivilegePrompt: request.allowInteractivePrivilegePrompt
        )
    }

    func runDragnet(allowInteractivePrivilegePrompt: Bool) async -> ScanResult {
        let args = ["-sV", "-p-", "--script", "vulners", "--script-args", "mincvss=0,threads=10", "-oX", Artifact.phase2XML, "-iL", Artifact.targets]
        return await run(
            nmapArguments: args,
            phase: .phase3,
            preferPrivileged: true,
            allowInteractivePrivilegePrompt: allowInteractivePrivilegePrompt
        )
    }

    func runFullScan(_ request: ScanRequest) async -> ScanResult {
        resetCancelFlag()
        RuntimeDiagnosticsLogger.log(
            "Running full scan target=\(request.target) kind=\(request.scanKind) interactivePrivilege=\(request.allowInteractivePrivilegePrompt) euid=\(geteuid())"
        )

        if request.scanKind.requiresPrivilegedNmap {
            do {
                if request.allowInteractivePrivilegePrompt {
                    try await MainActor.run {
                        try PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true)
                    }
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

        let phase1 = await runPhase1(request)
        if isCancelled {
            return cancelledResult(phase: .phase1, duration: phase1.duration)
        }
        guard phase1.completed, let summary = phase1.summary, summary.hosts.isEmpty == false else {
            RuntimeDiagnosticsLogger.log("Phase 1 finished completed=\(phase1.completed) hosts=\(phase1.summary?.hostCount ?? 0)")
            return phase1
        }
        writeTargetsFile(from: summary)
        if request.scanKind == .dragnet {
            RuntimeDiagnosticsLogger.log("Entering dragnet phase")
            let result = await runDragnet(allowInteractivePrivilegePrompt: request.allowInteractivePrivilegePrompt)
            return isCancelled ? cancelledResult(phase: .phase3, duration: result.duration) : result
        }
        if request.scanKind == .quick {
            return phase1
        }
        RuntimeDiagnosticsLogger.log("Entering phase 2")
        let result = await runPhase2(request)
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

        let useHelper = preferPrivileged || PrivilegeHelperClient.isHelperReachable
        if useHelper && (PrivilegeHelperClient.isHelperReachable || (preferPrivileged && allowInteractivePrivilegePrompt)) {
            do {
                if preferPrivileged && !PrivilegeHelperClient.isHelperReachable && allowInteractivePrivilegePrompt {
                    try await MainActor.run {
                        try PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true)
                    }
                }
                let result = try PrivilegeHelperClient.runNmap(
                    nmapPath: resolvedNmap,
                    arguments: nmapArguments,
                    workDirectory: workDirectory,
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
        let process = Process()
        process.currentDirectoryURL = workDirectory
        if resolvedNmap.contains("/") {
            process.executableURL = URL(fileURLWithPath: resolvedNmap)
            process.arguments = nmapArguments
        } else {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = [resolvedNmap] + nmapArguments
        }
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        stateQueue.sync { activeLocalProcess = process }
        defer { stateQueue.sync { activeLocalProcess = nil } }

        do {
            try process.run()
        } catch {
            RuntimeDiagnosticsLogger.error("Nmap launch failed phase=\(phase.rawValue) error=\(error.localizedDescription)")
            return ScanResult(phase: phase, duration: "0.00", xmlPath: nil, summary: nil, completed: false, error: error.localizedDescription)
        }

        // Wait off the cooperative thread pool so cancellation can still interrupt.
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                process.waitUntilExit()
                continuation.resume()
            }
        }
        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return makeResult(phase: phase, startedAt: startedAt, exitCode: process.terminationStatus, stdout: stdout, stderr: stderr)
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
        return ScanResult(
            phase: phase,
            duration: duration,
            xmlPath: FileManager.default.fileExists(atPath: xmlPath.path) ? xmlPath : nil,
            summary: summary,
            completed: exitCode == 0,
            error: exitCode == 0 ? nil : "Nmap exited with status \(exitCode)"
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

    private func buildPhase2Args(usePn: Bool, vpnHelper: Bool) -> [String] {
        var args = ["-sS", "-sV", "-O"]
        if usePn { args.append("-Pn") }
        args.append(vpnHelper ? "-T2" : "-T3")
        args.append(contentsOf: [
            "--open",
            "--script", "vulners",
            "--script-args", vpnHelper ? "mincvss=0,threads=5" : "mincvss=0,threads=10",
            "--stylesheet", "nmap-modern.xsl",
            "-oX", Artifact.phase2XML,
            "-iL", Artifact.targets
        ])
        return args
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
