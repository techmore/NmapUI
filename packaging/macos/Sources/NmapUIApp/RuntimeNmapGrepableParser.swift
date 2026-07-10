import Foundation
import RuntimeContracts

enum RuntimeNmapGrepableParser {
    static func parse(contentsOf url: URL) -> [RuntimeNmapXMLHostSummary] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return parse(text: text)
    }

    static func parse(text: String) -> [RuntimeNmapXMLHostSummary] {
        let hosts = text.split(separator: "\n").compactMap(parseHostLine)
        return hosts.reduce(into: [String: RuntimeNmapXMLHostSummary]()) { result, host in
            result[host.ip] = host
        }
        .values.sorted { $0.ip < $1.ip }
    }

    private static func parseHostLine(_ line: Substring) -> RuntimeNmapXMLHostSummary? {
        guard line.hasPrefix("Host: ") else { return nil }
        let fields = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard fields.count > 1 else { return nil }
        let ip = String(fields[1])
        let portsText = line.components(separatedBy: "Ports: ").dropFirst().first ?? ""
        let open = portsText.split(separator: ",").compactMap { entry -> (String, String)? in
            let parts = entry.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count >= 5, parts[1] == "open" else { return nil }
            let port = String(parts[0])
            let service = String(parts[4]).trimmingCharacters(in: .whitespaces)
            return (port, service)
        }
        return RuntimeNmapXMLHostSummary(
            ip: ip, mac: "", vendor: "", hostname: "", os: "--", latency: "--",
            ports: open.map(\.0).joined(separator: ", "),
            version: open.map { "\($0.0):\($0.1)" }.joined(separator: " | "),
            highCVEs: "", lowCVECount: 0
        )
    }
}
