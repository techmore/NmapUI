import Darwin
import Foundation

struct ExternalProcessResult: Sendable {
    let exitCode: Int32
    let stdout: String
    let stderr: String
    let timedOut: Bool
}

enum ExternalProcessRunner {
    private final class OutputBox: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [Bool: Data] = [:]

        func store(_ data: Data, stderr: Bool) {
            lock.lock()
            values[stderr] = data
            lock.unlock()
        }

        func data(stderr: Bool) -> Data {
            lock.lock()
            defer { lock.unlock() }
            return values[stderr] ?? Data()
        }
    }

    static func run(
        executable: URL,
        arguments: [String],
        currentDirectory: URL? = nil,
        timeout: TimeInterval = 15 * 60,
        maxOutputBytes: Int = 2 * 1024 * 1024,
        input: Data? = nil,
        isCancelled: @Sendable @escaping () -> Bool = { false }
    ) throws -> ExternalProcessResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.currentDirectoryURL = currentDirectory
        let stdout = Pipe()
        let stderr = Pipe()
        let inputPipe = input.map { _ in Pipe() }
        process.standardOutput = stdout
        process.standardError = stderr
        process.standardInput = inputPipe
        let output = OutputBox()
        let group = DispatchGroup()
        for (handle, isError) in [(stdout.fileHandleForReading, false), (stderr.fileHandleForReading, true)] {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                var captured = Data()
                while true {
                    let chunk = handle.readData(ofLength: 32 * 1024)
                    if chunk.isEmpty { break }
                    if captured.count < maxOutputBytes {
                        captured.append(chunk.prefix(maxOutputBytes - captured.count))
                    }
                }
                output.store(captured, stderr: isError)
                group.leave()
            }
        }
        try process.run()
        if let input, let inputPipe {
            inputPipe.fileHandleForWriting.write(input)
            try? inputPipe.fileHandleForWriting.close()
        }
        let deadline = Date().addingTimeInterval(timeout)
        var timedOut = false
        while process.isRunning {
            if isCancelled() {
                process.terminate()
                Thread.sleep(forTimeInterval: 0.25)
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                break
            }
            if Date() >= deadline {
                timedOut = true
                process.terminate()
                Thread.sleep(forTimeInterval: 0.25)
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        process.waitUntilExit()
        group.wait()
        return ExternalProcessResult(
            exitCode: process.terminationStatus,
            stdout: String(data: output.data(stderr: false), encoding: .utf8) ?? "",
            stderr: String(data: output.data(stderr: true), encoding: .utf8) ?? "",
            timedOut: timedOut
        )
    }
}
