import AppKit
import Darwin
import Foundation

/// Client for the root-only nmap helper.
///
/// The GUI app stays a normal user process. Privileged nmap runs either:
/// 1. Through the installed LaunchDaemon helper (preferred, no prompt after install), or
/// 2. Via a one-shot `osascript` admin elevation of the helper `run` mode (interactive fallback).
enum PrivilegeHelperClient {
    static let helperLabel = "com.techmore.nmapui.nmap-helper"
    static let helperInstallPath = "/Library/PrivilegedHelperTools/com.techmore.nmapui.nmap-helper"
    static let launchDaemonPlistPath = "/Library/LaunchDaemons/com.techmore.nmapui.nmap-helper.plist"
    static let socketPath = "/Library/Application Support/NmapUI/helper.sock"

    struct RunResult: Sendable {
        let exitCode: Int32
        let stdout: String
        let stderr: String
    }

    enum ClientError: LocalizedError {
        case helperBinaryMissing
        case installFailed(String)
        case communicationFailed(String)
        case notAvailable

        var errorDescription: String? {
            switch self {
            case .helperBinaryMissing:
                return "The privileged nmap helper binary is missing from the app bundle."
            case .installFailed(let message):
                return "Could not install the privileged scanner helper. \(message)"
            case .communicationFailed(let message):
                return "Could not talk to the privileged scanner helper. \(message)"
            case .notAvailable:
                return "Privileged scanner helper is not available."
            }
        }
    }

    static var isHelperReachable: Bool {
        (try? ping()) == true
    }

    static func ping() throws -> Bool {
        let response = try send(requestJSON: #"{"cmd":"ping"}"#)
        return response.ok && response.stdout == "pong"
    }

    @MainActor
    static func ensureInstalled(presentingWindow: NSWindow? = nil) throws {
        if isHelperReachable {
            return
        }
        try installHelper()
        // Give launchd a moment to start the daemon.
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline {
            if isHelperReachable {
                return
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        if !isHelperReachable {
            throw ClientError.installFailed("Helper installed but is not responding yet. Try again in a moment.")
        }
    }

    static func cancelActiveScan() {
        _ = try? send(requestJSON: #"{"cmd":"cancel"}"#)
    }

    /// Runs nmap with root privileges via the helper daemon, or interactive elevation fallback.
    static func runNmap(
        nmapPath: String,
        arguments: [String],
        workDirectory: URL,
        allowInteractiveFallback: Bool
    ) throws -> RunResult {
        try FileManager.default.createDirectory(at: workDirectory, withIntermediateDirectories: true)

        if isHelperReachable {
            return try runViaSocket(nmapPath: nmapPath, arguments: arguments, workDirectory: workDirectory)
        }

        guard allowInteractiveFallback else {
            throw ClientError.notAvailable
        }

        return try runViaInteractiveElevation(nmapPath: nmapPath, arguments: arguments, workDirectory: workDirectory)
    }

    // MARK: - Install

    private static func installHelper() throws {
        guard let helperURL = resolveHelperBinaryURL() else {
            throw ClientError.helperBinaryMissing
        }

        let helperSource = shellQuoted(helperURL.path)
        let installPath = shellQuoted(helperInstallPath)
        let plistPath = shellQuoted(launchDaemonPlistPath)
        let socketDir = shellQuoted("/Library/Application Support/NmapUI")

        let plistBody = """
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
        <plist version=\"1.0\">
        <dict>
            <key>Label</key>
            <string>\(helperLabel)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(helperInstallPath)</string>
                <string>daemon</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardErrorPath</key>
            <string>/var/log/nmapui-helper.err.log</string>
            <key>StandardOutPath</key>
            <string>/var/log/nmapui-helper.out.log</string>
        </dict>
        </plist>
        """

        let encodedPlist = plistBody
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")

        let script = """
        mkdir -p /Library/PrivilegedHelperTools
        mkdir -p \(socketDir)
        cp \(helperSource) \(installPath)
        chown root:wheel \(installPath)
        chmod 755 \(installPath)
        printf "%b" "\(encodedPlist)" > \(plistPath)
        chown root:wheel \(plistPath)
        chmod 644 \(plistPath)
        launchctl bootout system/\(helperLabel) 2>/dev/null || true
        launchctl bootstrap system \(plistPath)
        launchctl enable system/\(helperLabel)
        launchctl kickstart -k system/\(helperLabel)
        """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = [
            "-e",
            "do shell script \(appleScriptString(script)) with administrator privileges"
        ]
        let stderrPipe = Pipe()
        let stdoutPipe = Pipe()
        process.standardError = stderrPipe
        process.standardOutput = stdoutPipe
        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw ClientError.installFailed(stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    private static func resolveHelperBinaryURL() -> URL? {
        let fileManager = FileManager.default
        var candidates: [URL] = []

        if let resourceURL = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/NmapPrivilegedHelper") as URL? {
            candidates.append(resourceURL)
        }
        if let executable = Bundle.main.executableURL {
            candidates.append(executable.deletingLastPathComponent().appendingPathComponent("NmapPrivilegedHelper"))
            // SwiftPM run: .build/debug/NmapUI sibling
            candidates.append(executable.deletingLastPathComponent().appendingPathComponent("NmapPrivilegedHelper"))
        }

        let sourceFile = URL(fileURLWithPath: #filePath)
        let packagingMacOS = sourceFile
            .deletingLastPathComponent() // NmapUIApp
            .deletingLastPathComponent() // Sources
            .deletingLastPathComponent() // packaging/macos
        candidates.append(packagingMacOS.appendingPathComponent(".build/debug/NmapPrivilegedHelper"))
        candidates.append(packagingMacOS.appendingPathComponent(".build/release/NmapPrivilegedHelper"))

        return candidates.first(where: { fileManager.isExecutableFile(atPath: $0.path) })
    }

    // MARK: - Socket run

    private static func runViaSocket(
        nmapPath: String,
        arguments: [String],
        workDirectory: URL
    ) throws -> RunResult {
        let payload: [String: Any] = [
            "cmd": "run",
            "run": [
                "nmapPath": nmapPath,
                "arguments": arguments,
                "workDirectory": workDirectory.path
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: payload)
        guard let json = String(data: data, encoding: .utf8) else {
            throw ClientError.communicationFailed("could not encode request")
        }
        let response = try send(requestJSON: json)
        return RunResult(exitCode: Int32(response.exitCode), stdout: response.stdout, stderr: response.stderr)
    }

    private static func runViaInteractiveElevation(
        nmapPath: String,
        arguments: [String],
        workDirectory: URL
    ) throws -> RunResult {
        guard let helperURL = resolveHelperBinaryURL() else {
            throw ClientError.helperBinaryMissing
        }

        var commandParts = [
            shellQuoted(helperURL.path),
            "run",
            "--work-dir",
            shellQuoted(workDirectory.path),
            "--",
            shellQuoted(nmapPath)
        ]
        commandParts.append(contentsOf: arguments.map(shellQuoted))
        let shellCommand = commandParts.joined(separator: " ")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = [
            "-e",
            "do shell script \(appleScriptString(shellCommand)) with administrator privileges"
        ]
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        try process.run()
        process.waitUntilExit()

        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return RunResult(exitCode: process.terminationStatus, stdout: stdout, stderr: stderr)
    }

    // MARK: - Framing

    private struct HelperResponse: Decodable {
        let ok: Bool
        let exitCode: Int
        let stdout: String
        let stderr: String
        let error: String?
    }

    private static func send(requestJSON: String) throws -> HelperResponse {
        let clientFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard clientFD >= 0 else {
            throw ClientError.communicationFailed("socket() failed")
        }
        defer { close(clientFD) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = socketPath
        path.withCString { cString in
            withUnsafeMutablePointer(to: &addr.sun_path.0) { dest in
                _ = strcpy(dest, cString)
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                connect(clientFD, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            throw ClientError.communicationFailed("connect failed: \(String(cString: strerror(errno)))")
        }

        var payload = requestJSON
        if !payload.hasSuffix("\n") {
            payload.append("\n")
        }
        let writeOK = payload.withCString { pointer in
            write(clientFD, pointer, strlen(pointer)) >= 0
        }
        guard writeOK else {
            throw ClientError.communicationFailed("write failed")
        }

        guard let line = readLine(from: clientFD),
              let data = line.data(using: .utf8),
              let response = try? JSONDecoder().decode(HelperResponse.self, from: data) else {
            throw ClientError.communicationFailed("invalid helper response")
        }
        return response
    }

    private static func readLine(from fd: Int32) -> String? {
        var buffer = [UInt8]()
        var byte: UInt8 = 0
        while true {
            let n = read(fd, &byte, 1)
            if n <= 0 { break }
            if byte == UInt8(ascii: "\n") { break }
            buffer.append(byte)
            if buffer.count > 2_000_000 { break }
        }
        guard !buffer.isEmpty else { return nil }
        return String(bytes: buffer, encoding: .utf8)
    }

    private static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func appleScriptString(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "\"" + escaped + "\""
    }
}
