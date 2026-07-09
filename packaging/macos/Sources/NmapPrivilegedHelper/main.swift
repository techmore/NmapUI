import Darwin
import Foundation

/// Root-only helper that runs allowlisted nmap invocations for NmapUI.
///
/// Modes:
/// - `daemon`: listen on a Unix domain socket and service run/cancel/ping requests
/// - `run --work-dir DIR -- nmapPath arg...`: one-shot elevated run (used by interactive fallback)
enum HelperConstants {
    static let socketPath = "/Library/Application Support/NmapUI/helper.sock"
    static let socketDirectory = "/Library/Application Support/NmapUI"
    static let maxArgumentCount = 64
    static let maxArgumentLength = 4096
}

@main
struct NmapPrivilegedHelperMain {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let mode = args.first else {
            fputs("usage: NmapPrivilegedHelper daemon | run --work-dir DIR -- <nmapPath> [args...]\n", stderr)
            exit(2)
        }

        switch mode {
        case "daemon":
            runDaemon()
        case "run":
            do {
                try runOneShot(Array(args.dropFirst()))
            } catch {
                fputs("\(error.localizedDescription)\n", stderr)
                exit(1)
            }
        default:
            fputs("unknown mode: \(mode)\n", stderr)
            exit(2)
        }
    }
}

// MARK: - One-shot

private func runOneShot(_ args: [String]) throws {
    guard geteuid() == 0 else {
        throw HelperError.notRoot
    }
    let request = try parseRunCLIArguments(args)
    let result = try executeNmap(request)
    if !result.stdout.isEmpty {
        fputs(result.stdout, stdout)
    }
    if !result.stderr.isEmpty {
        fputs(result.stderr, stderr)
    }
    exit(Int32(result.exitCode))
}

private func parseRunCLIArguments(_ args: [String]) throws -> HelperRunRequest {
    var workDirectory: String?
    var command: [String] = []
    var index = 0
    while index < args.count {
        let arg = args[index]
        if arg == "--work-dir" {
            index += 1
            guard index < args.count else { throw HelperError.invalidRequest("missing --work-dir value") }
            workDirectory = args[index]
        } else if arg == "--" {
            command = Array(args.suffix(from: index + 1))
            break
        } else {
            command = Array(args.suffix(from: index))
            break
        }
        index += 1
    }
    guard let workDirectory, !workDirectory.isEmpty else {
        throw HelperError.invalidRequest("work directory required")
    }
    guard let nmapPath = command.first, command.count >= 1 else {
        throw HelperError.invalidRequest("nmap command required")
    }
    return HelperRunRequest(
        nmapPath: nmapPath,
        arguments: Array(command.dropFirst()),
        workDirectory: workDirectory
    )
}

// MARK: - Daemon

private final class DaemonState: @unchecked Sendable {
    private let lock = NSLock()
    private var activeProcess: Process?

    func setActive(_ process: Process?) {
        lock.lock()
        activeProcess = process
        lock.unlock()
    }

    func cancelActive() {
        lock.lock()
        let process = activeProcess
        lock.unlock()
        process?.terminate()
    }
}

private let daemonState = DaemonState()

private func runDaemon() {
    guard geteuid() == 0 else {
        fputs("daemon must run as root\n", stderr)
        exit(1)
    }

    try? FileManager.default.createDirectory(
        atPath: HelperConstants.socketDirectory,
        withIntermediateDirectories: true
    )
    unlink(HelperConstants.socketPath)

    let serverFD = socket(AF_UNIX, SOCK_STREAM, 0)
    guard serverFD >= 0 else {
        fputs("failed to create socket\n", stderr)
        exit(1)
    }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let path = HelperConstants.socketPath
    path.withCString { cString in
        withUnsafeMutablePointer(to: &addr.sun_path.0) { dest in
            _ = strcpy(dest, cString)
        }
    }

    let bindResult = withUnsafePointer(to: &addr) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
            bind(serverFD, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard bindResult == 0 else {
        fputs("failed to bind \(path): \(String(cString: strerror(errno)))\n", stderr)
        exit(1)
    }

    chmod(HelperConstants.socketPath, 0o666)
    guard listen(serverFD, 8) == 0 else {
        fputs("failed to listen on socket\n", stderr)
        exit(1)
    }

    fputs("NmapUI privileged helper listening on \(path)\n", stderr)

    while true {
        let clientFD = accept(serverFD, nil, nil)
        if clientFD < 0 {
            continue
        }
        DispatchQueue.global(qos: .userInitiated).async {
            handleClient(clientFD)
        }
    }
}

private func handleClient(_ clientFD: Int32) {
    defer { close(clientFD) }
    guard let line = readLine(from: clientFD) else {
        writeLine(to: clientFD, HelperResponse(ok: false, exitCode: 1, stdout: "", stderr: "empty request", error: "empty request"))
        return
    }

    guard let data = line.data(using: .utf8),
          let request = try? JSONDecoder().decode(HelperRequest.self, from: data) else {
        writeLine(to: clientFD, HelperResponse(ok: false, exitCode: 1, stdout: "", stderr: "invalid json", error: "invalid json"))
        return
    }

    switch request.cmd {
    case "ping":
        writeLine(to: clientFD, HelperResponse(ok: true, exitCode: 0, stdout: "pong", stderr: "", error: nil))
    case "cancel":
        daemonState.cancelActive()
        writeLine(to: clientFD, HelperResponse(ok: true, exitCode: 0, stdout: "cancelled", stderr: "", error: nil))
    case "run":
        do {
            guard let run = request.run else {
                throw HelperError.invalidRequest("missing run payload")
            }
            let result = try executeNmap(run)
            writeLine(
                to: clientFD,
                HelperResponse(
                    ok: result.exitCode == 0,
                    exitCode: result.exitCode,
                    stdout: result.stdout,
                    stderr: result.stderr,
                    error: result.exitCode == 0 ? nil : "nmap exited with status \(result.exitCode)"
                )
            )
        } catch {
            writeLine(
                to: clientFD,
                HelperResponse(ok: false, exitCode: 1, stdout: "", stderr: error.localizedDescription, error: error.localizedDescription)
            )
        }
    default:
        writeLine(to: clientFD, HelperResponse(ok: false, exitCode: 1, stdout: "", stderr: "unknown cmd", error: "unknown cmd"))
    }
}

// MARK: - Execute

private struct ExecuteResult {
    let exitCode: Int
    let stdout: String
    let stderr: String
}

private func executeNmap(_ request: HelperRunRequest) throws -> ExecuteResult {
    try validate(request)

    let process = Process()
    process.currentDirectoryURL = URL(fileURLWithPath: request.workDirectory, isDirectory: true)
    process.executableURL = URL(fileURLWithPath: request.nmapPath)
    process.arguments = request.arguments

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    daemonState.setActive(process)
    defer { daemonState.setActive(nil) }

    try process.run()
    process.waitUntilExit()

    let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

    // Ensure scan artifacts are user-readable even though we ran as root.
    relaxOwnership(of: request.workDirectory)

    return ExecuteResult(exitCode: Int(process.terminationStatus), stdout: stdout, stderr: stderr)
}

private func validate(_ request: HelperRunRequest) throws {
    let nmapPath = request.nmapPath
    guard nmapPath.hasPrefix("/"), !nmapPath.contains("..") else {
        throw HelperError.invalidRequest("nmap path must be absolute")
    }
    let allowedNames = ["nmap"]
    let base = URL(fileURLWithPath: nmapPath).lastPathComponent
    guard allowedNames.contains(base) else {
        throw HelperError.invalidRequest("executable must be nmap")
    }
    guard FileManager.default.isExecutableFile(atPath: nmapPath) else {
        throw HelperError.invalidRequest("nmap is not executable at \(nmapPath)")
    }

    let work = request.workDirectory
    guard work.hasPrefix("/"), !work.contains("..") else {
        throw HelperError.invalidRequest("invalid work directory")
    }
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: work, isDirectory: &isDir), isDir.boolValue else {
        throw HelperError.invalidRequest("work directory does not exist")
    }

    guard request.arguments.count <= HelperConstants.maxArgumentCount else {
        throw HelperError.invalidRequest("too many arguments")
    }
    for argument in request.arguments {
        guard argument.count <= HelperConstants.maxArgumentLength else {
            throw HelperError.invalidRequest("argument too long")
        }
        if argument.contains("\0") || argument.contains(";") || argument.contains("|") || argument.contains("&") || argument.contains("`") || argument.contains("$(") {
            throw HelperError.invalidRequest("argument contains forbidden characters")
        }
    }
}

private func relaxOwnership(of directoryPath: String) {
    let fileManager = FileManager.default
    guard let enumerator = fileManager.enumerator(atPath: directoryPath) else { return }
    let root = URL(fileURLWithPath: directoryPath)
    let paths = [directoryPath] + enumerator.compactMap { $0 as? String }.map { root.appendingPathComponent($0).path }
    for path in paths {
        chmod(path, 0o644)
        // Prefer staff-writable for directories.
        var isDir: ObjCBool = false
        if fileManager.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue {
            chmod(path, 0o755)
        }
    }
}

// MARK: - Wire protocol

private struct HelperRunRequest: Codable {
    let nmapPath: String
    let arguments: [String]
    let workDirectory: String
}

private struct HelperRequest: Codable {
    let cmd: String
    let run: HelperRunRequest?
}

private struct HelperResponse: Codable {
    let ok: Bool
    let exitCode: Int
    let stdout: String
    let stderr: String
    let error: String?
}

private enum HelperError: LocalizedError {
    case notRoot
    case invalidRequest(String)

    var errorDescription: String? {
        switch self {
        case .notRoot:
            return "helper must run as root"
        case .invalidRequest(let message):
            return message
        }
    }
}

private func readLine(from fd: Int32) -> String? {
    var buffer = [UInt8]()
    var byte: UInt8 = 0
    while true {
        let n = read(fd, &byte, 1)
        if n <= 0 { break }
        if byte == UInt8(ascii: "\n") { break }
        buffer.append(byte)
        if buffer.count > 1_000_000 { break }
    }
    guard !buffer.isEmpty else { return nil }
    return String(bytes: buffer, encoding: .utf8)
}

private func writeLine(to fd: Int32, _ response: HelperResponse) {
    guard let data = try? JSONEncoder().encode(response),
          var line = String(data: data, encoding: .utf8) else {
        return
    }
    line.append("\n")
    line.withCString { pointer in
        _ = write(fd, pointer, strlen(pointer))
    }
}
