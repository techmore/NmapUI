import Foundation

enum GowitnessCapture {
    static func capture(nmapXML: URL, workDirectory: URL) throws -> [URL] {
        guard let binary = GowitnessManager.resolvedBinaryURL() else { throw GowitnessError.invalidBinary }
        let outputDirectory = workDirectory.appendingPathComponent("gowitness", isDirectory: true)
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        let arguments = [
            "scan", "nmap", "-f", nmapXML.path,
            "--open-only", "--service-contains", "http",
            "--write-db"
        ]
        let result = try ExternalProcessRunner.run(executable: binary, arguments: arguments, currentDirectory: outputDirectory, timeout: 10 * 60)
        guard result.exitCode == 0, !result.timedOut else {
            let message = result.timedOut ? "GoWitness timed out" : (result.stderr.isEmpty ? "unknown error" : result.stderr)
            throw NSError(domain: "NmapUI.Gowitness", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: message])
        }
        let objects = FileManager.default.enumerator(at: outputDirectory, includingPropertiesForKeys: nil)?.allObjects ?? []
        let screenshots = objects.compactMap { $0 as? URL }
            .filter { ["png", "jpg", "jpeg"].contains($0.pathExtension.lowercased()) }
        return screenshots
    }
}
