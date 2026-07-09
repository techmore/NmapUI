import Foundation

@MainActor
final class RuntimeReportRefreshMonitor {
    private var task: Task<Void, Never>?
    private var lastSignature: String?

    func start(dataDirectory: URL, onChange: @escaping @MainActor () -> Void) {
        task?.cancel()
        lastSignature = currentSignature(for: dataDirectory)
        task = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                let signature = self.currentSignature(for: dataDirectory)
                guard signature != self.lastSignature else { continue }
                self.lastSignature = signature
                await MainActor.run {
                    onChange()
                }
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    private func currentSignature(for dataDirectory: URL) -> String {
        let historySignature = fileSignature(at: dataDirectory.appendingPathComponent("history.json"))
        let reportsSignature = directorySignature(at: dataDirectory.appendingPathComponent("reports_archive"))
        return "\(historySignature)|\(reportsSignature)"
    }

    private func fileSignature(at url: URL) -> String {
        guard let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey]),
              let date = values.contentModificationDate
        else { return "missing" }
        return "\(date.timeIntervalSince1970)-\(values.fileSize ?? 0)"
    }

    private func directorySignature(at url: URL) -> String {
        guard let enumerator = FileManager.default.enumerator(
            at: url,
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
            options: [.skipsHiddenFiles]
        ) else {
            return "missing"
        }
        var components: [String] = []
        for case let fileURL as URL in enumerator {
            guard fileURL.pathExtension.lowercased() == "html" || fileURL.pathExtension.lowercased() == "pdf" || fileURL.pathExtension.lowercased() == "xml" || fileURL.lastPathComponent == "drive.json" else {
                continue
            }
            let signature = fileSignature(at: fileURL)
            components.append("\(fileURL.lastPathComponent):\(signature)")
        }
        return components.sorted().joined(separator: ";")
    }
}
