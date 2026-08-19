import Foundation
import CryptoKit
import RuntimeContracts

struct RuntimeReportHistoryPayload: Codable {
    let timestamp: String
    let target: String
    let duration: String
    let hostCount: Int
    let scanKind: String
    let status: String?
    let error: String?
    let reportUrl: String
    let pdfUrl: String?
    let xmlUrl: String?
    let customerProfile: RuntimeCustomerProfile
}

struct RuntimeGowitnessScreenshot: Codable {
    let ip: String
    let port: String
    let url: String
    let fileName: String
    let reportSrc: String
    let dashboardUrl: String
}

struct RuntimeHostBufferResult: Codable {
    let updates: [String: String]
}

private final class HostBuilder {
    var ip = ""
    var mac = ""
    var vendor = ""
    var hostname = ""
    var os = "--"
    var latency = "--"
    private var openPorts: [String] = []
    private var versions: [String] = []
    private var highCVEs = Set<String>()
    private var lowCVEs = Set<String>()
    private var currentPortId = ""
    private var currentPortOpen = false
    private var currentService: [String: String] = [:]
    private var inVulnersScript = false
    private var currentElemKey = ""
    private var pendingCVSS = ""
    private var pendingCVEId = ""

    func captureAddress(attributes: [String: String]) {
        switch attributes["addrtype"] {
        case "ipv4":
            ip = attributes["addr"] ?? ip
        case "mac":
            mac = attributes["addr"] ?? mac
            vendor = attributes["vendor"] ?? vendor
        default:
            break
        }
    }

    func startPort(attributes: [String: String]) {
        currentPortId = attributes["portid"] ?? ""
        currentPortOpen = false
        currentService = [:]
    }

    func updatePortState(attributes: [String: String]) {
        currentPortOpen = attributes["state"] == "open"
        if currentPortOpen && !currentPortId.isEmpty {
            openPorts.append(currentPortId)
        }
    }

    func updateService(attributes: [String: String]) {
        currentService = attributes
        guard currentPortOpen, !currentPortId.isEmpty else { return }
        let value = "\(attributes["name"] ?? "") \(attributes["product"] ?? "") \(attributes["version"] ?? "")"
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if !value.isEmpty {
            versions.append("\(currentPortId):\(value)")
        }
    }

    func startVulners() {
        inVulnersScript = true
    }

    func captureVulnersElement(attributes: [String: String]) {
        guard inVulnersScript else { return }
        currentElemKey = attributes["name"] ?? attributes["key"] ?? ""
    }

    func appendCharacters(_ string: String) {
        guard inVulnersScript else { return }
        if currentElemKey == "cvss" {
            pendingCVSS += string
        } else if currentElemKey == "id" {
            pendingCVEId += string
        }
    }

    func endElement(_ elementName: String) {
        if elementName == "elem" {
            let normalizedId = pendingCVEId.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            let normalizedScore = pendingCVSS.trimmingCharacters(in: .whitespacesAndNewlines)
            if !normalizedId.isEmpty, !normalizedScore.isEmpty, let score = Double(normalizedScore), normalizedId.hasPrefix("CVE-") {
                if score >= 7.0 {
                    highCVEs.insert("\(normalizedId)(\(score))")
                } else {
                    lowCVEs.insert(normalizedId)
                }
            }
            currentElemKey = ""
        } else if elementName == "script" {
            inVulnersScript = false
            currentElemKey = ""
            pendingCVSS = ""
            pendingCVEId = ""
        }
    }

    func build() -> RuntimeNmapXMLHostSummary {
        RuntimeNmapXMLHostSummary(
            ip: ip,
            mac: mac,
            vendor: vendor,
            hostname: hostname,
            os: os,
            latency: latency,
            ports: openPorts.joined(separator: ", "),
            version: versions.joined(separator: " | "),
            highCVEs: Array(highCVEs).joined(separator: ", "),
            lowCVECount: lowCVEs.count
        )
    }
}

enum RuntimeNmapXMLParser {
    static func parse(contentsOf url: URL) -> RuntimeNmapXMLSummary? {
        guard let data = try? Data(contentsOf: url), let xml = String(data: data, encoding: .utf8) else { return nil }
        return parse(xml: xml)
    }

    static func parse(xml: String) -> RuntimeNmapXMLSummary? {
        guard xml.contains("<nmaprun"), xml.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("</nmaprun>") else { return nil }
        let delegate = NmapXMLDelegate()
        let parser = XMLParser(data: Data(xml.utf8))
        parser.delegate = delegate
        return parser.parse() ? RuntimeNmapXMLSummary(hosts: delegate.hosts) : nil
    }

    private final class NmapXMLDelegate: NSObject, XMLParserDelegate {
        var hosts: [RuntimeNmapXMLHostSummary] = []
        private var currentHost: HostBuilder?

        func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String : String] = [:]) {
            if elementName == "host" {
                currentHost = HostBuilder()
            } else if elementName == "address" {
                currentHost?.captureAddress(attributes: attributeDict)
            } else if elementName == "hostname" {
                currentHost?.hostname = attributeDict["name"] ?? currentHost?.hostname ?? ""
            } else if elementName == "osmatch" {
                currentHost?.os = attributeDict["name"] ?? currentHost?.os ?? "--"
            } else if elementName == "times" {
                if let srtt = attributeDict["srtt"], let micros = Double(srtt) {
                    currentHost?.latency = String(format: "%.2fms", micros / 1000.0)
                }
            } else if elementName == "port" {
                currentHost?.startPort(attributes: attributeDict)
            } else if elementName == "state" {
                currentHost?.updatePortState(attributes: attributeDict)
            } else if elementName == "service" {
                currentHost?.updateService(attributes: attributeDict)
            } else if elementName == "script", attributeDict["id"] == "vulners" {
                currentHost?.startVulners()
            } else if elementName == "elem" {
                currentHost?.captureVulnersElement(attributes: attributeDict)
            }
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            currentHost?.appendCharacters(string)
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
            if elementName == "host", let host = currentHost?.build() {
                hosts.append(host)
                currentHost = nil
            }
            currentHost?.endElement(elementName)
        }
    }
}

private func parseNmapXML(contentsOf url: URL) -> RuntimeNmapXMLSummary? {
    RuntimeNmapXMLParser.parse(contentsOf: url)
}

struct RuntimeTargetNormalization: Codable {
    let targets: [String]
    let targetLabel: String
}

struct RuntimeScanOrchestrationResult: Codable {
    let scanKind: String
    let targetLabel: String
    let phase1: RuntimePhase1ScanResult
    let phase2: RuntimePhase2ScanResult?
    let targetsPath: String?
}

struct RuntimeAutoScanPlan: Codable {
    let enabled: Bool
    let recurrence: String
    let startTime: String
    let cronExpression: String
    let target: String
}

struct RuntimeWebTarget: Codable {
    let ip: String
    let port: Int
    let url: String
}

struct RuntimeGowitnessReportSection: Codable {
    let html: String
}

struct RuntimeXMLCompleteness: Codable {
    let complete: Bool
}

struct RuntimeTextPayload: Codable {
    let text: String
}

struct RuntimeTimestampPayload: Codable {
    let timestamp: String
}

struct RuntimeCustomerProfilePayload: Codable {
    let prefix: String
    let publicIP: String
    let wan: String
    let fingerprint: String
    let baseName: String
    let reportLabel: String
    let folderName: String
    let topology: [String: [String]]
}

private func runtimeCustomerProfile(from payload: RuntimeCustomerProfilePayload) -> RuntimeCustomerProfile {
    RuntimeCustomerProfile(
        prefix: payload.prefix,
        publicIP: payload.publicIP,
        fingerprint: payload.fingerprint,
        baseName: payload.baseName,
        reportLabel: payload.reportLabel,
        folderName: payload.folderName
    )
}

private func decodeJSONObject(from json: String) -> [String: Any]? {
    guard let data = json.data(using: .utf8) else { return nil }
    return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
}

private func jsonValue(from value: Any) -> RuntimeJSONValue {
    switch value {
    case let string as String: return .string(string)
    case let int as Int: return .int(int)
    case let double as Double: return .double(double)
    case let bool as Bool: return .bool(bool)
    case let dict as [String: Any]:
        return .object(dict.mapValues(jsonValue))
    case let array as [Any]:
        return .array(array.map(jsonValue))
    case is NSNull:
        return .null
    default:
        return .string(String(describing: value))
    }
}

private func jsonObject(from value: [String: Any]) -> [String: RuntimeJSONValue] {
    value.mapValues(jsonValue)
}

private func digestHex(_ data: Data, length: Int = 8) -> String {
    SHA256.hash(data: data)
        .prefix(length / 2)
        .map { String(format: "%02x", $0) }
        .joined()
}

private func loadJSON<T: Decodable>(_ type: T.Type, from url: URL) -> T? {
    guard let data = try? Data(contentsOf: url) else { return nil }
    return try? JSONDecoder().decode(T.self, from: data)
}

private func escape(_ value: String) -> String {
    value
        .replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&apos;")
}

private func sanitizeSegment(_ value: String, fallback: String) -> String {
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
    let sanitized = value
        .replacingOccurrences(of: #"[^A-Za-z0-9_-]+"#, with: "_", options: .regularExpression)
        .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
    return sanitized.isEmpty ? fallback : String(sanitized.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" })
}

private func maskHexToInfo(_ maskHex: String) -> (maskInt: UInt32, prefix: Int, dotted: String)? {
    let normalized = String(maskHex.replacingOccurrences(of: "0x", with: "", options: .caseInsensitive).padding(toLength: 8, withPad: "0", startingAt: 0).suffix(8))
    guard let maskInt = UInt32(normalized, radix: 16) else { return nil }
    let binary = String(maskInt, radix: 2).leftPadding(toLength: 32, withPad: "0")
    guard binary.range(of: #"^1*0*$"#, options: .regularExpression) != nil else { return nil }
    let prefix = binary.firstIndex(of: "0").map { binary.distance(from: binary.startIndex, to: $0) } ?? 32
    return (maskInt, prefix, intToIp(maskInt))
}

private func intToIp(_ value: UInt32) -> String {
    [
        (value >> 24) & 255,
        (value >> 16) & 255,
        (value >> 8) & 255,
        value & 255
    ].map(String.init).joined(separator: ".")
}

private func ipToInt(_ ip: String) -> UInt32? {
    let parts = ip.split(separator: ".").compactMap { UInt32($0) }
    guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return nil }
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
}

private func getNetworkCIDR(localIP: String, maskHex: String) -> String {
    guard let ipInt = ipToInt(localIP), let maskInfo = maskHexToInfo(maskHex) else { return "" }
    return "\(intToIp(ipInt & maskInfo.maskInt))/\(maskInfo.prefix)"
}

private func findExecutable(named name: String) -> String? {
    let searchPaths = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map(String.init)
    let candidates = searchPaths.map { "\($0)/\(name)" } + ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)"]
    return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
}

private func runProcess(executable: String, arguments: [String]) async -> (success: Bool, output: String) {
    await withCheckedContinuation { continuation in
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        process.terminationHandler = { _ in
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            continuation.resume(returning: (process.terminationStatus == 0, String(data: data, encoding: .utf8) ?? ""))
        }
        do {
            try process.run()
        } catch {
            continuation.resume(returning: (false, ""))
        }
    }
}

private func firstCapture(in text: String, pattern: String, group: Int = 1) -> String? {
    guard let regex = try? NSRegularExpression(pattern: pattern, options: [.anchorsMatchLines]) else { return nil }
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    guard let match = regex.firstMatch(in: text, options: [], range: range),
          let captureRange = Range(match.range(at: group), in: text) else { return nil }
    return String(text[captureRange])
}

private func getNetworkSnapshot() async -> RuntimeNetworkSnapshot {
    let defaultGateway = await runProcess(executable: "/usr/sbin/route", arguments: ["get", "default"])
    let iface = defaultGateway.output.range(of: #"interface:\s+(\w+)"#, options: .regularExpression).map { String(defaultGateway.output[$0]).components(separatedBy: .whitespaces).last ?? "en0" } ?? "en0"
    let ifconfig = await runProcess(executable: "/sbin/ifconfig", arguments: [iface])
    let ipMatch = ifconfig.output.range(of: #"inet\s+([0-9.]+)"#, options: .regularExpression).map { String(ifconfig.output[$0]).split(separator: " ").last.map(String.init) ?? "Unknown" } ?? "Unknown"
    let maskMatch = ifconfig.output.range(of: #"netmask\s+0x([0-9a-f]+)"#, options: .regularExpression).map { String(ifconfig.output[$0]).split(separator: " ").last.map(String.init) ?? "" } ?? ""
    let maskInfo = maskMatch.isEmpty ? nil : maskHexToInfo(maskMatch)
    let publicIP = await {
        guard let url = URL(string: "https://api.ipify.org?format=json") else { return "Unknown" }
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            return (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["ip"] as? String ?? "Unknown"
        } catch {
            return "Unknown"
        }
    }()
    return RuntimeNetworkSnapshot(localIP: ipMatch, mask: maskInfo?.dotted ?? (maskMatch.isEmpty ? "Unknown" : "0x\(maskMatch)"), cidr: maskMatch.isEmpty ? "192.168.1.0/24" : (getNetworkCIDR(localIP: ipMatch, maskHex: maskMatch).isEmpty ? "192.168.1.0/24" : getNetworkCIDR(localIP: ipMatch, maskHex: maskMatch)), publicIP: publicIP)
}

private extension String {
    func leftPadding(toLength: Int, withPad character: Character) -> String {
        if count >= toLength { return self }
        return String(repeating: String(character), count: toLength - count) + self
    }
}

private func driveLink(from metadata: [String: Any], matching fileName: String) -> String? {
    guard let links = metadata["links"] as? [[String: Any]] else { return nil }
    return links.first { ($0["name"] as? String) == fileName }?["webViewLink"] as? String
}

private func parseHostBuffer(ip: String, text: String) -> [String: String] {
    var updates: [String: String] = [:]
    if let osMatch = text.range(of: "OS details: ") {
        let os = text[osMatch.upperBound...].split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: true).first.map(String.init) ?? ""
        if !os.isEmpty { updates["os"] = os }
    }

    let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    var ports: [String] = []
    var versions: [String] = []
    for line in lines {
        if let pMatch = line.range(of: #"^(\d+)\/\w+\s+open\s+(.*)"#, options: .regularExpression) {
            let matched = String(line[pMatch])
            if let port = matched.split(separator: "/", maxSplits: 1).first.map(String.init), !port.isEmpty {
                ports.append(port)
                if let detailMatch = matched.range(of: #"^\d+\/\w+\s+open\s+(.*)"#, options: .regularExpression) {
                    let detail = String(matched[detailMatch]).replacingOccurrences(of: #"^\d+\/\w+\s+open\s+"#, with: "", options: .regularExpression).trimmingCharacters(in: .whitespacesAndNewlines)
                    if !detail.isEmpty { versions.append("\(port):\(detail)") }
                }
            }
        }
    }
    if !ports.isEmpty { updates["ports"] = ports.joined(separator: ", ") }
    if !versions.isEmpty { updates["version"] = versions.joined(separator: " | ") }

    var highCVEs = Set<String>()
    var lowCVEs = Set<String>()
    for line in lines {
        let pattern = #"\b(CVE-\d{4}-\d+)\b\s+([0-9]+(?:\.[0-9]+)?)"#
        guard let match = line.range(of: pattern, options: .regularExpression) else { continue }
        let text = String(line[match])
        let parts = text.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard parts.count >= 2 else { continue }
        let cveId = parts[0].uppercased()
        guard let score = Double(parts[1]) else { continue }
        if score >= 7.0 { highCVEs.insert("\(cveId)(\(score))") } else { lowCVEs.insert(cveId) }
    }
    if !highCVEs.isEmpty { updates["highCVEs"] = Array(highCVEs).joined(separator: ", ") }
    if !lowCVEs.isEmpty { updates["lowCVECount"] = String(lowCVEs.count) }
    return updates
}

private func buildScanStats(hosts: [RuntimeNmapXMLHostSummary]) -> RuntimeScanStats {
    RuntimeScanStats(
        hostCount: hosts.count,
        openPortCount: hosts.reduce(0) { total, host in
            total + host.ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }.count
        },
        criticalCVECount: hosts.reduce(0) { total, host in
            total + host.highCVEs.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }.count
        },
        lowCVECount: hosts.reduce(0) { $0 + $1.lowCVECount }
    )
}

private func writeTargetsFile(_ targets: [String], to url: URL) -> Bool {
    let text = targets.joined(separator: "\n")
    guard !text.isEmpty else { return false }
    do {
        try text.write(to: url, atomically: true, encoding: .utf8)
        return true
    } catch {
        return false
    }
}

private func loadDriveMetadata(for reportPath: URL) -> [String: Any] {
    guard let data = try? Data(contentsOf: reportPath.appendingPathExtension("drive.json")) else { return [:] }
    return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
}

private func buildSnapshot(reportsDir: URL, historyPath: URL) -> RuntimeReportsSnapshot {
    let history = loadJSON([RuntimeReportHistoryEntry].self, from: historyPath) ?? []
    let historyByURL = history.reduce(into: [String: RuntimeReportHistoryEntry]()) { result, entry in
        guard let url = entry.reportUrl else { return }
        if let existing = result[url], existing.timestamp >= entry.timestamp { return }
        result[url] = entry
    }

    var reports: [RuntimeReportListEntry] = []
    if let folderURLs = try? FileManager.default.contentsOfDirectory(at: reportsDir, includingPropertiesForKeys: [.isDirectoryKey, .contentModificationDateKey]) {
        for folderURL in folderURLs {
            let folderValues = try? folderURL.resourceValues(forKeys: [.isDirectoryKey])
            if folderValues?.isDirectory == true {
                let files = (try? FileManager.default.contentsOfDirectory(at: folderURL, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
                for htmlURL in files where htmlURL.pathExtension.lowercased() == "html" {
                    let fileName = htmlURL.lastPathComponent
                    let pdfName = htmlURL.deletingPathExtension().appendingPathExtension("pdf").lastPathComponent
                    let xmlName = htmlURL.deletingPathExtension().appendingPathExtension("xml").lastPathComponent
                    let urlBase = "/reports/\(folderURL.lastPathComponent)"
                    let reportUrl = "\(urlBase)/\(fileName)"
                    let driveMetadata = loadDriveMetadata(for: htmlURL)
                    let attrs = try? FileManager.default.attributesOfItem(atPath: htmlURL.path)
                    let mtime = (attrs?[.modificationDate] as? Date) ?? Date()
                    let historyEntry = historyByURL[reportUrl]
                    reports.append(RuntimeReportListEntry(
                        name: fileName,
                        folder: folderURL.lastPathComponent,
                        url: reportUrl,
                        pdfName: FileManager.default.fileExists(atPath: htmlURL.deletingPathExtension().appendingPathExtension("pdf").path) ? pdfName : nil,
                        pdfUrl: FileManager.default.fileExists(atPath: htmlURL.deletingPathExtension().appendingPathExtension("pdf").path) ? "\(urlBase)/\(pdfName)" : nil,
                        xmlName: FileManager.default.fileExists(atPath: htmlURL.deletingPathExtension().appendingPathExtension("xml").path) ? xmlName : nil,
                        xmlUrl: FileManager.default.fileExists(atPath: htmlURL.deletingPathExtension().appendingPathExtension("xml").path) ? "\(urlBase)/\(xmlName)" : nil,
                        driveHtmlUrl: driveLink(from: driveMetadata, matching: fileName),
                        drivePdfUrl: FileManager.default.fileExists(atPath: htmlURL.deletingPathExtension().appendingPathExtension("pdf").path) ? driveLink(from: driveMetadata, matching: pdfName) : nil,
                        date: historyEntry?.timestamp ?? ISO8601DateFormatter().string(from: mtime),
                        duration: historyEntry?.duration,
                        hostCount: historyEntry?.hostCount,
                        status: historyEntry?.status,
                        error: historyEntry?.error
                    ))
                }
            } else if folderURL.pathExtension.lowercased() == "html" {
                let fileName = folderURL.lastPathComponent
                let folder = ""
                let urlBase = "/reports"
                let reportUrl = "\(urlBase)/\(fileName)"
                let driveMetadata = loadDriveMetadata(for: folderURL)
                let attrs = try? FileManager.default.attributesOfItem(atPath: folderURL.path)
                let mtime = (attrs?[.modificationDate] as? Date) ?? Date()
                let historyEntry = historyByURL[reportUrl]
                let pdfURL = folderURL.deletingPathExtension().appendingPathExtension("pdf")
                let xmlURL = folderURL.deletingPathExtension().appendingPathExtension("xml")
                reports.append(RuntimeReportListEntry(
                    name: fileName,
                    folder: folder,
                    url: reportUrl,
                    pdfName: FileManager.default.fileExists(atPath: pdfURL.path) ? pdfURL.lastPathComponent : nil,
                    pdfUrl: FileManager.default.fileExists(atPath: pdfURL.path) ? "\(urlBase)/\(pdfURL.lastPathComponent)" : nil,
                    xmlName: FileManager.default.fileExists(atPath: xmlURL.path) ? xmlURL.lastPathComponent : nil,
                    xmlUrl: FileManager.default.fileExists(atPath: xmlURL.path) ? "\(urlBase)/\(xmlURL.lastPathComponent)" : nil,
                    driveHtmlUrl: driveLink(from: driveMetadata, matching: fileName),
                    drivePdfUrl: FileManager.default.fileExists(atPath: pdfURL.path) ? driveLink(from: driveMetadata, matching: pdfURL.lastPathComponent) : nil,
                    date: historyEntry?.timestamp ?? ISO8601DateFormatter().string(from: mtime),
                    duration: historyEntry?.duration,
                    hostCount: historyEntry?.hostCount,
                    status: historyEntry?.status,
                    error: historyEntry?.error
                ))
            }
        }
    }

    for entry in history where entry.status == "failed" {
        let date = entry.timestamp
        let scanLabel = entry.scanKind == "complete" ? "Complete+PDF" : "Scan"
        reports.append(RuntimeReportListEntry(
            name: "Failed \(scanLabel) scan - \(date)",
            folder: entry.customerProfile?.folderName ?? "",
            url: nil,
            pdfName: nil,
            pdfUrl: nil,
            xmlName: nil,
            xmlUrl: nil,
            driveHtmlUrl: nil,
            drivePdfUrl: nil,
            date: date,
            duration: entry.duration,
            hostCount: entry.hostCount,
            status: "failed",
            error: entry.error ?? "Nmap scan failed before a complete XML report was written."
        ))
    }

    return RuntimeReportsSnapshot(generatedAt: ISO8601DateFormatter().string(from: Date()), reports: reports.sorted { $0.date > $1.date })
}

private func buildFailedScanEntry(timestamp: String, scanKind: String, folder: String, error: String, hostCount: Int, duration: String) -> RuntimeFailedScanEntry {
    let scanLabel = scanKind == "complete" ? "Complete+PDF" : "Scan"
    return RuntimeFailedScanEntry(timestamp: timestamp, scanLabel: scanLabel, folder: folder, status: "failed", error: error, hostCount: hostCount, duration: duration)
}

private func runtimeCustomerProfile(from dictionary: [String: String]) -> RuntimeCustomerProfile {
    RuntimeCustomerProfile(
        prefix: dictionary["prefix"] ?? "CSP",
        publicIP: dictionary["publicIP"] ?? dictionary["publicIp"] ?? "unknown_wan",
        fingerprint: dictionary["fingerprint"] ?? "",
        baseName: dictionary["baseName"] ?? "",
        reportLabel: dictionary["reportLabel"] ?? "",
        folderName: dictionary["folderName"] ?? ""
    )
}

private func buildGowitnessSection(screenshots: [RuntimeGowitnessScreenshot]) -> String {
    guard !screenshots.isEmpty else { return "" }
    let cards = screenshots.map { item in
        """
                    <article class="gowitness-card">
                        <a href="\(escape(item.reportSrc))" target="_blank" rel="noopener noreferrer">
                            <img src="\(escape(item.reportSrc))" alt="Screenshot of \(escape(item.url))" />
                        </a>
                        <div>
                            <strong>\(escape(item.ip)):\(escape(item.port))</strong>
                            <span>\(escape(item.url))</span>
                        </div>
                    </article>
        """
    }.joined()
    return """
            <section class="gowitness-section">
                <h2>Web Service Screenshots</h2>
                <div class="gowitness-grid">\(cards)
                </div>
            </section>
    """
}

private func injectGowitnessSection(reportPath: URL, screenshots: [RuntimeGowitnessScreenshot]) {
    let section = buildGowitnessSection(screenshots: screenshots)
    guard !section.isEmpty, var html = try? String(contentsOf: reportPath, encoding: .utf8) else { return }
    let style = """
        <style>
            .gowitness-section { break-before: page; page-break-before: always; margin: 24px 0; }
            .gowitness-section h2 { margin: 0 0 16px; color: #2f331b; font-size: 22px; }
            .gowitness-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
            .gowitness-card { overflow: hidden; border: 1px solid #c8cf9b; border-radius: 8px; background: #fff; }
            .gowitness-card img { display: block; width: 100%; height: 180px; object-fit: cover; background: #eef0df; }
            .gowitness-card div { padding: 10px 12px; font-size: 11px; color: #444827; }
            .gowitness-card strong, .gowitness-card span { display: block; overflow-wrap: anywhere; }
        </style>
    """
    if !html.contains(".gowitness-section") {
        html = html.replacingOccurrences(of: "</head>", with: "\(style)\n    </head>")
    }
    let footerMarker = "        <!-- Footer -->"
    if html.contains(footerMarker) {
        html = html.replacingOccurrences(of: footerMarker, with: "\(section)\n\n\(footerMarker)")
    } else {
        html = html.replacingOccurrences(of: "</body>", with: "\(section)\n</body>")
    }
    try? html.write(to: reportPath, atomically: true, encoding: .utf8)
}

let args = CommandLine.arguments
let command = args.dropFirst().first ?? ""
let decoder = JSONDecoder()
let encoder = JSONEncoder()
encoder.outputFormatting = [.sortedKeys]

func decodePath(named flag: String) -> String? {
    guard let index = args.firstIndex(of: flag), index + 1 < args.count else { return nil }
    return args[index + 1]
}

switch command {
case "snapshot":
    guard let reportsDir = decodePath(named: "--reports-dir"), let historyPath = decodePath(named: "--history-path") else {
        fputs("{\"success\":false,\"error\":\"Missing required paths\"}", stdout)
        exit(1)
    }
    let snapshot = buildSnapshot(reportsDir: URL(fileURLWithPath: reportsDir), historyPath: URL(fileURLWithPath: historyPath))
    if let data = try? encoder.encode(snapshot), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode snapshot\"}")
        exit(1)
    }
case "failed-scan":
    guard let timestamp = decodePath(named: "--timestamp"), let scanKind = decodePath(named: "--scan-kind"), let folder = decodePath(named: "--folder"), let errorMessage = decodePath(named: "--error"), let hostCountString = decodePath(named: "--host-count"), let duration = decodePath(named: "--duration"), let hostCount = Int(hostCountString) else {
        fputs("{\"success\":false,\"error\":\"Missing required args\"}", stdout)
        exit(1)
    }
    let entry = buildFailedScanEntry(timestamp: timestamp, scanKind: scanKind, folder: folder, error: errorMessage, hostCount: hostCount, duration: duration)
    if let data = try? encoder.encode(entry), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode failed scan entry\"}")
        exit(1)
    }
case "history":
    guard let historyPath = decodePath(named: "--history-path") else {
        fputs("{\"success\":false,\"error\":\"Missing history path\"}", stdout)
        exit(1)
    }
    let history = loadJSON([RuntimeReportHistoryEntry].self, from: URL(fileURLWithPath: historyPath)) ?? []
    if let data = try? encoder.encode(history), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode history\"}")
        exit(1)
    }
case "report-list-entry":
    guard let name = decodePath(named: "--name"), let folder = decodePath(named: "--folder"), let date = decodePath(named: "--date") else {
        fputs("{\"success\":false,\"error\":\"Missing report list entry args\"}", stdout)
        exit(1)
    }
    let payload = RuntimeReportListEntry(
        name: name,
        folder: folder,
        url: decodePath(named: "--url"),
        pdfName: decodePath(named: "--pdf-name"),
        pdfUrl: decodePath(named: "--pdf-url"),
        xmlName: decodePath(named: "--xml-name"),
        xmlUrl: decodePath(named: "--xml-url"),
        driveHtmlUrl: decodePath(named: "--drive-html-url"),
        drivePdfUrl: decodePath(named: "--drive-pdf-url"),
        date: date,
        duration: decodePath(named: "--duration"),
        hostCount: Int(decodePath(named: "--host-count") ?? ""),
        status: decodePath(named: "--status"),
        error: decodePath(named: "--error")
    )
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode report list entry\"}")
        exit(1)
    }
case "report-payload":
    guard let url = decodePath(named: "--url"), let name = decodePath(named: "--name"), let xmlName = decodePath(named: "--xml-name"), let customerProfileJSON = decodePath(named: "--customer-profile") else {
        fputs("{\"success\":false,\"error\":\"Missing report payload args\"}", stdout)
        exit(1)
    }
    let pdfUrl = decodePath(named: "--pdf-url")
    let pdfName = decodePath(named: "--pdf-name")
    let xmlUrl = decodePath(named: "--xml-url")
    let driveHtmlUrl = decodePath(named: "--drive-html-url")
    let drivePdfUrl = decodePath(named: "--drive-pdf-url")
    let customerProfile = runtimeCustomerProfile(from: (try? JSONSerialization.jsonObject(with: Data(customerProfileJSON.utf8)) as? [String: String]) ?? [:])
    let payload = RuntimeReportPayload(
        url: url,
        pdfUrl: pdfUrl,
        name: name,
        pdfName: pdfName,
        xmlName: xmlName,
        xmlUrl: xmlUrl,
        customerProfile: customerProfile,
        driveHtmlUrl: driveHtmlUrl,
        drivePdfUrl: drivePdfUrl
    )
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode report payload\"}")
        exit(1)
    }
case "report-history-entry":
    guard let timestamp = decodePath(named: "--timestamp"), let target = decodePath(named: "--target"), let duration = decodePath(named: "--duration"), let hostCountString = decodePath(named: "--host-count"), let scanKind = decodePath(named: "--scan-kind"), let reportUrl = decodePath(named: "--report-url"), let customerProfileJSON = decodePath(named: "--customer-profile"), let hostCount = Int(hostCountString) else {
        fputs("{\"success\":false,\"error\":\"Missing report history args\"}", stdout)
        exit(1)
    }
    let status = decodePath(named: "--status")
    let errorMessage = decodePath(named: "--error")
    let pdfUrl = decodePath(named: "--pdf-url")
    let xmlUrl = decodePath(named: "--xml-url")
    let customerProfile = runtimeCustomerProfile(from: (try? JSONSerialization.jsonObject(with: Data(customerProfileJSON.utf8)) as? [String: String]) ?? [:])
    let payload = RuntimeReportHistoryPayload(
        timestamp: timestamp,
        target: target,
        duration: duration,
        hostCount: hostCount,
        scanKind: scanKind,
        status: status,
        error: errorMessage,
        reportUrl: reportUrl,
        pdfUrl: pdfUrl,
        xmlUrl: xmlUrl,
        customerProfile: customerProfile
    )
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode report history entry\"}")
        exit(1)
    }
case "append-history-entry":
    guard let historyPath = decodePath(named: "--history-path"), let entryJSON = decodePath(named: "--entry"), let data = entryJSON.data(using: .utf8), let entry = try? JSONDecoder().decode(RuntimeReportHistoryEntry.self, from: data) else {
        fputs("{\"success\":false,\"error\":\"Missing append history args\"}", stdout)
        exit(1)
    }
    let historyURL = URL(fileURLWithPath: historyPath)
    var history = loadJSON([RuntimeReportHistoryEntry].self, from: historyURL) ?? []
    history.insert(entry, at: 0)
    do {
        let encoded = try encoder.encode(Array(history.prefix(50)))
        try encoded.write(to: historyURL, options: [.atomic])
        print("{\"success\":true}")
    } catch {
        print("{\"success\":false,\"error\":\"Failed to write history\"}")
        exit(1)
    }
case "save-drive-metadata":
    guard let reportPath = decodePath(named: "--report-path"), let uploadJSON = decodePath(named: "--upload-json"), let data = uploadJSON.data(using: .utf8), let uploadObject = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        fputs("{\"success\":false,\"error\":\"Missing drive metadata args\"}", stdout)
        exit(1)
    }
    let links = (uploadObject["uploaded"] as? [[String: Any]] ?? []).compactMap { file -> RuntimeReportDriveFile? in
        let name = (file["name"] as? String) ?? ""
        let webViewLink = (file["webViewLink"] as? String) ?? ""
        let id = (file["id"] as? String) ?? ""
        guard !name.isEmpty || !webViewLink.isEmpty || !id.isEmpty else { return nil }
        return RuntimeReportDriveFile(name: name, webViewLink: webViewLink, id: id)
    }
    let metadata = RuntimeReportMetadata(
        uploadedAt: ISO8601DateFormatter().string(from: Date()),
        folderId: uploadObject["folder_id"] as? String,
        dayFolderId: uploadObject["day_folder_id"] as? String,
        links: links
    )
    let metadataPath = URL(fileURLWithPath: reportPath).appendingPathExtension("drive.json")
    do {
        let encoded = try encoder.encode(metadata)
        try encoded.write(to: metadataPath, options: [.atomic])
        print("{\"success\":true}")
    } catch {
        print("{\"success\":false,\"error\":\"Failed to write drive metadata\"}")
        exit(1)
    }
case "load-drive-metadata":
    guard let reportPath = decodePath(named: "--report-path") else {
        fputs("{\"success\":false,\"error\":\"Missing drive metadata path\"}", stdout)
        exit(1)
    }
    let metadataURL = URL(fileURLWithPath: reportPath).appendingPathExtension("drive.json")
    guard let metadata = loadJSON(RuntimeReportMetadata.self, from: metadataURL) else {
        print("{\"success\":false,\"error\":\"Missing drive metadata\"}")
        exit(1)
    }
    if let data = try? encoder.encode(metadata), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode drive metadata\"}")
        exit(1)
    }
case "drive-link":
    guard let reportPath = decodePath(named: "--report-path"), let fileName = decodePath(named: "--file-name") else {
        fputs("{\"success\":false,\"error\":\"Missing drive link args\"}", stdout)
        exit(1)
    }
    let metadataURL = URL(fileURLWithPath: reportPath).appendingPathExtension("drive.json")
    guard let metadata = loadJSON(RuntimeReportMetadata.self, from: metadataURL) else {
        print("{\"success\":false,\"error\":\"Missing drive metadata\"}")
        exit(1)
    }
    let link = metadata.links.first(where: { $0.name == fileName })?.webViewLink ?? ""
    if let data = try? encoder.encode(RuntimeTextPayload(text: link)), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode drive link\"}")
        exit(1)
    }
case "parse-xml":
    guard let xmlPath = decodePath(named: "--xml-path") else {
        fputs("{\"success\":false,\"error\":\"Missing XML path\"}", stdout)
        exit(1)
    }
    guard let summary = parseNmapXML(contentsOf: URL(fileURLWithPath: xmlPath)) else {
        print("{\"success\":false,\"error\":\"Failed to parse XML\"}")
        exit(1)
    }
    if let data = try? encoder.encode(summary), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode XML summary\"}")
        exit(1)
    }
case "process-host-buffer":
    guard let ip = decodePath(named: "--ip"), let text = decodePath(named: "--text") else {
        fputs("{\"success\":false,\"error\":\"Missing host buffer args\"}", stdout)
        exit(1)
    }
    let result = RuntimeHostBufferResult(updates: parseHostBuffer(ip: ip, text: text))
    if let data = try? encoder.encode(result), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode host buffer result\"}")
        exit(1)
    }
case "scan-stats":
    guard let hostsJSON = decodePath(named: "--hosts"), let data = hostsJSON.data(using: .utf8), let hosts = try? JSONDecoder().decode([RuntimeNmapXMLHostSummary].self, from: data) else {
        fputs("{\"success\":false,\"error\":\"Missing scan stats args\"}", stdout)
        exit(1)
    }
    let stats = buildScanStats(hosts: hosts)
    if let data = try? encoder.encode(stats), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode scan stats\"}")
        exit(1)
    }
case "phase1-scan":
    guard let target = decodePath(named: "--target") else {
        fputs("{\"success\":false,\"error\":\"Missing phase1 target\"}", stdout)
        exit(1)
    }
    guard let nmapPath = findExecutable(named: "nmap") else {
        print("{\"success\":false,\"error\":\"Nmap not found\"}")
        exit(1)
    }
    let args = ["-sn", "-T4"] + target
        .split(whereSeparator: { $0 == "," || $0 == "\n" })
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
    let startedAt = Date()
    let output = await runProcess(executable: "/usr/bin/env", arguments: [nmapPath] + args)
    let discovered = output.output
        .split(separator: "\n")
        .compactMap { line -> RuntimePhase1Discovery? in
            guard line.contains("Nmap scan report for") else { return nil }
            let text = String(line)
            let hostname = firstCapture(in: text, pattern: #"report for (.*?)(?: \(([0-9.]+)\))?$"#, group: 1) ?? ""
            let ip = firstCapture(in: text, pattern: #"report for (.*?)(?: \(([0-9.]+)\))?$"#, group: 2) ?? hostname
            return RuntimePhase1Discovery(ip: ip, hostname: hostname == ip ? "" : hostname)
        }
    let result = RuntimePhase1ScanResult(
        success: output.success,
        duration: String(format: "%.2f", Date().timeIntervalSince(startedAt)),
        hosts: discovered,
        error: output.success ? nil : "Phase 1 scan failed"
    )
    if let data = try? encoder.encode(result), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode phase1 result\"}")
        exit(1)
    }
case "phase2-scan":
    guard let targetsPath = decodePath(named: "--targets-path"), let xmlPath = decodePath(named: "--xml-path") else {
        fputs("{\"success\":false,\"error\":\"Missing phase2 args\"}", stdout)
        exit(1)
    }
    guard let nmapPath = findExecutable(named: "nmap") else {
        print("{\"success\":false,\"error\":\"Nmap not found\"}")
        exit(1)
    }
    let usePn = decodePath(named: "--use-pn") == "1"
    let vpnHelper = decodePath(named: "--vpn-helper") == "1"
    var args = ["-sS", "-sV", "-O"]
    if usePn { args.append("-Pn") }
    args.append(vpnHelper ? "-T2" : "-T3")
    args.append(contentsOf: ["--open", "--script", "vulners", "--script-args", vpnHelper ? "mincvss=0,threads=5" : "mincvss=0,threads=10", "--stylesheet", "nmap-modern.xsl", "-oX", xmlPath, "-iL", targetsPath])
    let startedAt = Date()
    let output = await runProcess(executable: "/usr/bin/env", arguments: [nmapPath] + args)
    let summary = RuntimeNmapXMLParser.parse(contentsOf: URL(fileURLWithPath: xmlPath))
    let result = RuntimePhase2ScanResult(
        success: output.success && summary != nil,
        duration: String(format: "%.2f", Date().timeIntervalSince(startedAt)),
        summary: summary,
        xmlPath: FileManager.default.fileExists(atPath: xmlPath) ? xmlPath : nil,
        error: (output.success && summary != nil) ? nil : "Phase 2 scan failed"
    )
    if let data = try? encoder.encode(result), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode phase2 result\"}")
        exit(1)
    }
case "dragnet-scan":
    guard let targetsPath = decodePath(named: "--targets-path"), let xmlPath = decodePath(named: "--xml-path") else {
        fputs("{\"success\":false,\"error\":\"Missing dragnet args\"}", stdout)
        exit(1)
    }
    guard let nmapPath = findExecutable(named: "nmap") else {
        print("{\"success\":false,\"error\":\"Nmap not found\"}")
        exit(1)
    }
    let startedAt = Date()
    let args = ["-sV", "-p-", "--script", "vulners", "--script-args", "mincvss=0,threads=10", "-oX", xmlPath, "-iL", targetsPath]
    let output = await runProcess(executable: "/usr/bin/env", arguments: [nmapPath] + args)
    let summary = RuntimeNmapXMLParser.parse(contentsOf: URL(fileURLWithPath: xmlPath))
    let result = RuntimePhase2ScanResult(
        success: output.success && summary != nil,
        duration: String(format: "%.2f", Date().timeIntervalSince(startedAt)),
        summary: summary,
        xmlPath: FileManager.default.fileExists(atPath: xmlPath) ? xmlPath : nil,
        error: (output.success && summary != nil) ? nil : "Dragnet scan failed"
    )
    if let data = try? encoder.encode(result), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode dragnet result\"}")
        exit(1)
    }
case "normalize-targets":
    guard let rawTarget = decodePath(named: "--target") else {
        fputs("{\"success\":false,\"error\":\"Missing target input\"}", stdout)
        exit(1)
    }
    let targets = rawTarget
        .split(whereSeparator: { $0 == "," || $0 == "\n" })
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
    let payload = RuntimeTargetNormalization(targets: targets, targetLabel: targets.count > 1 ? targets.joined(separator: ", ") : (targets.first ?? ""))
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode normalized targets\"}")
        exit(1)
    }
case "scan-orchestrate":
    let target = decodePath(named: "--target") ?? ""
    let usePn = decodePath(named: "--use-pn") == "1"
    let vpnHelper = decodePath(named: "--vpn-helper") == "1"
    let scanKind = decodePath(named: "--scan-kind") ?? (usePn ? "complete" : "quick")
    let normalizedTargets = target
        .split(whereSeparator: { $0 == "," || $0 == "\n" })
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
    guard !normalizedTargets.isEmpty else {
        fputs("{\"success\":false,\"error\":\"Missing scan target\"}", stdout)
        exit(1)
    }
    guard let nmapPath = findExecutable(named: "nmap") else {
        print("{\"success\":false,\"error\":\"Nmap not found\"}")
        exit(1)
    }
    let workDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let phase1Result: RuntimePhase1ScanResult
    let phase1Hosts: [RuntimePhase1Discovery]
    if scanKind == "dragnet" {
        phase1Hosts = normalizedTargets.map { RuntimePhase1Discovery(ip: $0, hostname: "") }
        phase1Result = RuntimePhase1ScanResult(
            success: true,
            duration: "0.00",
            hosts: phase1Hosts,
            error: nil
        )
    } else {
        let phase1Args = ["-sn", "-T4"] + normalizedTargets
        let phase1StartedAt = Date()
        let phase1Output = await runProcess(executable: "/usr/bin/env", arguments: [nmapPath] + phase1Args)
        phase1Hosts = phase1Output.output
            .split(separator: "\n")
            .compactMap { line -> RuntimePhase1Discovery? in
                guard line.contains("Nmap scan report for") else { return nil }
                let text = String(line)
                let hostname = firstCapture(in: text, pattern: #"report for (.*?)(?: \(([0-9.]+)\))?$"#, group: 1) ?? ""
                let ip = firstCapture(in: text, pattern: #"report for (.*?)(?: \(([0-9.]+)\))?$"#, group: 2) ?? hostname
                return RuntimePhase1Discovery(ip: ip, hostname: hostname == ip ? "" : hostname)
            }
        phase1Result = RuntimePhase1ScanResult(
            success: phase1Output.success,
            duration: String(format: "%.2f", Date().timeIntervalSince(phase1StartedAt)),
            hosts: phase1Hosts,
            error: phase1Output.success ? nil : "Phase 1 scan failed"
        )
    }
    var phase2Result: RuntimePhase2ScanResult? = nil
    var targetsPath: String? = nil
    if phase1Result.success, !phase1Hosts.isEmpty {
        let discoveredTargets = phase1Hosts.map(\.ip).filter { !$0.isEmpty }
        let targetsURL = workDirectory.appendingPathComponent("targets.tmp")
        if writeTargetsFile(discoveredTargets, to: targetsURL) {
            targetsPath = targetsURL.path
            let phase2XMLPath = workDirectory.appendingPathComponent("phase2_results.xml").path
            if scanKind == "dragnet" {
                let startedAt = Date()
                let args = ["-sV", "-p-", "--script", "vulners", "--script-args", "mincvss=0,threads=10", "-oX", phase2XMLPath, "-iL", targetsPath!]
                let output = await runProcess(executable: "/usr/bin/env", arguments: [nmapPath] + args)
                let summary = RuntimeNmapXMLParser.parse(contentsOf: URL(fileURLWithPath: phase2XMLPath))
                phase2Result = RuntimePhase2ScanResult(
                    success: output.success && summary != nil,
                    duration: String(format: "%.2f", Date().timeIntervalSince(startedAt)),
                    summary: summary,
                    xmlPath: FileManager.default.fileExists(atPath: phase2XMLPath) ? phase2XMLPath : nil,
                    error: (output.success && summary != nil) ? nil : "Dragnet scan failed"
                )
            } else {
                var args = ["-sS", "-sV", "-O"]
                if usePn { args.append("-Pn") }
                args.append(vpnHelper ? "-T2" : "-T3")
                args.append(contentsOf: ["--open", "--script", "vulners", "--script-args", vpnHelper ? "mincvss=0,threads=5" : "mincvss=0,threads=10", "--stylesheet", "nmap-modern.xsl", "-oX", phase2XMLPath, "-iL", targetsPath!])
                let startedAt = Date()
                let output = await runProcess(executable: "/usr/bin/env", arguments: [nmapPath] + args)
                let summary = RuntimeNmapXMLParser.parse(contentsOf: URL(fileURLWithPath: phase2XMLPath))
                phase2Result = RuntimePhase2ScanResult(
                    success: output.success && summary != nil,
                    duration: String(format: "%.2f", Date().timeIntervalSince(startedAt)),
                    summary: summary,
                    xmlPath: FileManager.default.fileExists(atPath: phase2XMLPath) ? phase2XMLPath : nil,
                    error: (output.success && summary != nil) ? nil : "Phase 2 scan failed"
                )
            }
        }
    }
    let orchestration = RuntimeScanOrchestrationResult(
        scanKind: scanKind,
        targetLabel: normalizedTargets.count > 1 ? normalizedTargets.joined(separator: ", ") : (normalizedTargets.first ?? ""),
        phase1: phase1Result,
        phase2: phase2Result,
        targetsPath: targetsPath
    )
    if let data = try? encoder.encode(orchestration), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode scan orchestration result\"}")
        exit(1)
    }
case "auto-scan-plan":
    guard let payloadJSON = decodePath(named: "--payload"), let data = payloadJSON.data(using: .utf8), let input = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        fputs("{\"success\":false,\"error\":\"Missing auto scan payload\"}", stdout)
        exit(1)
    }
    let enabled = input["enabled"] as? Bool ?? false
    let rawRecurrence = String(describing: input["recurrence"] as? String ?? "daily")
    let recurrence = ["hourly", "daily", "weekly", "monthly"].contains(rawRecurrence) ? rawRecurrence : "daily"
    let startTime = String(describing: input["startTime"] as? String ?? "01:00")
    let parts = startTime.split(separator: ":").map(String.init)
    let hour = parts.first ?? "1"
    let minute = parts.dropFirst().first ?? "0"
    let cronExpression = {
        switch recurrence {
        case "hourly": return "\(minute) * * * *"
        case "weekly": return "\(minute) \(hour) * * 0"
        case "monthly": return "\(minute) \(hour) 1 * *"
        default: return "\(minute) \(hour) * * *"
        }
    }()
    let target = String(describing: input["target"] as? String ?? "")
    let plan = RuntimeAutoScanPlan(enabled: enabled, recurrence: recurrence, startTime: startTime, cronExpression: cronExpression, target: target)
    if let data = try? encoder.encode(plan), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode auto scan plan\"}")
        exit(1)
    }
case "is-complete-xml":
    guard let xmlPath = decodePath(named: "--xml-path") else {
        fputs("{\"success\":false,\"error\":\"Missing XML path\"}", stdout)
        exit(1)
    }
    let complete = {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: xmlPath)), let xml = String(data: data, encoding: .utf8) else { return false }
        let trimmed = xml.trimmingCharacters(in: .whitespacesAndNewlines)
        return xml.contains("<nmaprun") && trimmed.hasSuffix("</nmaprun>")
    }()
    let payload = RuntimeXMLCompleteness(complete: complete)
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode XML completeness\"}")
        exit(1)
    }
case "compact-text":
    guard let rawText = decodePath(named: "--text") else {
        fputs("{\"success\":false,\"error\":\"Missing text input\"}", stdout)
        exit(1)
    }
    let maxLength = Int(decodePath(named: "--max-length") ?? "4000") ?? 4000
    let text = rawText.replacingOccurrences(of: #"\s+\n"#, with: "\n", options: .regularExpression).trimmingCharacters(in: .whitespacesAndNewlines)
    let compacted = text.count <= maxLength ? text : String(text.suffix(maxLength)).trimmingCharacters(in: .whitespacesAndNewlines)
    let payload = RuntimeTextPayload(text: compacted)
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode compacted text\"}")
        exit(1)
    }
case "report-timestamp":
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone.current
    formatter.dateFormat = "yyyyMMdd_HHmmss"
    let payload = RuntimeTimestampPayload(timestamp: formatter.string(from: Date()))
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode report timestamp\"}")
        exit(1)
    }
case "report-display-timestamp":
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone.current
    formatter.dateFormat = "MMM dd, yyyy, HH:mm:ss zzz"
    let payload = RuntimeTimestampPayload(timestamp: formatter.string(from: Date()))
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode display timestamp\"}")
        exit(1)
    }
case "sanitize-segment":
    guard let rawValue = decodePath(named: "--value") else {
        fputs("{\"success\":false,\"error\":\"Missing value input\"}", stdout)
        exit(1)
    }
    let fallback = decodePath(named: "--fallback") ?? "unknown"
    let payload = RuntimeTextPayload(text: sanitizeSegment(rawValue, fallback: fallback))
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode sanitized segment\"}")
        exit(1)
    }
case "web-targets":
    guard let payloadJSON = decodePath(named: "--payload"), let data = payloadJSON.data(using: .utf8), let input = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        fputs("{\"success\":false,\"error\":\"Missing web target payload\"}", stdout)
        exit(1)
    }
    let hosts = (input["hosts"] as? [[String: Any]]) ?? []
    let webPorts = Set([80, 81, 3000, 443, 5000, 7001, 8000, 8001, 8080, 8081, 8443, 8888, 9000, 9443])
    var targets: [RuntimeWebTarget] = []
    for host in hosts {
        guard let ip = host["ip"] as? String, !ip.isEmpty else { continue }
        let ports = (host["ports"] as? [String]) ?? []
        let versionText = String(describing: host["version"] as? String ?? "").lowercased()
        var serviceByPort: [Int: String] = [:]
        versionText.split(separator: "|").forEach { chunk in
            let trimmed = chunk.trimmingCharacters(in: .whitespacesAndNewlines)
            let parts = trimmed.split(separator: ":", maxSplits: 1).map(String.init)
            if parts.count == 2, let port = Int(parts[0]) {
                serviceByPort[port] = parts[1]
            }
        }
        let selectedPorts = ports.compactMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) }.filter { port in
            let serviceHint = serviceByPort[port] ?? ""
            return webPorts.contains(port) || serviceHint.contains("http") || serviceHint.contains("https")
        }
        for port in selectedPorts {
            let portHint = serviceByPort[port] ?? ""
            let isHttps = [443, 8443, 9443].contains(port) || portHint.contains("ssl") || portHint.contains("https")
            let scheme = isHttps ? "https" : "http"
            let defaultPort = (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
            targets.append(RuntimeWebTarget(ip: ip, port: port, url: "\(scheme)://\(ip)\(defaultPort ? "" : ":\(port)")"))
        }
    }
    let limited = Array(targets.prefix(40))
    if let data = try? encoder.encode(limited), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode web targets\"}")
        exit(1)
    }
case "gowitness-section":
    guard let payloadJSON = decodePath(named: "--payload"), let data = payloadJSON.data(using: .utf8), let input = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
        fputs("{\"success\":false,\"error\":\"Missing gowitness payload\"}", stdout)
        exit(1)
    }
    guard !input.isEmpty else {
        let section = RuntimeGowitnessReportSection(html: "")
        if let data = try? encoder.encode(section), let text = String(data: data, encoding: .utf8) {
            print(text)
        } else {
            print("{\"success\":false,\"error\":\"Failed to encode gowitness section\"}")
            exit(1)
        }
        break
    }
    let cards = input.compactMap { item -> String? in
        let reportSrc = String(describing: item["reportSrc"] as? String ?? "")
        let url = String(describing: item["url"] as? String ?? "")
        let ip = String(describing: item["ip"] as? String ?? "")
        let port = String(describing: item["port"] as? String ?? "")
        guard !reportSrc.isEmpty else { return nil }
        return """
                    <article class=\"gowitness-card\">
                        <a href=\"\(escape(reportSrc))\" target=\"_blank\" rel=\"noopener noreferrer\">
                            <img src=\"\(escape(reportSrc))\" alt=\"Screenshot of \(escape(url))\" />
                        </a>
                        <div>
                            <strong>\(escape(ip)):\(escape(port))</strong>
                            <span>\(escape(url))</span>
                        </div>
                    </article>
        """
    }.joined()
    let html = """
            <section class=\"gowitness-section\">
                <h2>Web Service Screenshots</h2>
                <div class=\"gowitness-grid\">\(cards)
                </div>
            </section>
    """
    let section = RuntimeGowitnessReportSection(html: html)
    if let data = try? encoder.encode(section), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode gowitness section\"}")
        exit(1)
    }
case "drive-day-folder":
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone.current
    formatter.dateFormat = "yyyy-MM-dd"
    let payload = RuntimeTextPayload(text: formatter.string(from: Date()))
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode drive day folder\"}")
        exit(1)
    }
case "customer-profile":
    guard let payloadJSON = decodePath(named: "--payload"), let data = payloadJSON.data(using: .utf8), let input = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        fputs("{\"success\":false,\"error\":\"Missing customer profile payload\"}", stdout)
        exit(1)
    }
    let prefix = String(describing: input["prefix"] as? String ?? "CSP")
    let publicIP = String(describing: input["publicIP"] as? String ?? "unknown_wan")
    let topology = (input["topology"] as? [String: [String]]) ?? [:]
    let fingerprintSource = String(data: (try? JSONSerialization.data(withJSONObject: ["publicIP": publicIP, "topology": topology])) ?? Data(), encoding: .utf8) ?? ""
    let fingerprint = SHA256.hash(data: Data(fingerprintSource.utf8)).compactMap { String(format: "%02x", $0) }.joined().prefix(8)
    let wan = sanitizeSegment(publicIP, fallback: "unknown_wan")
    let sanitizedPrefix = sanitizeSegment(prefix, fallback: "CSP")
    let baseName = "\(sanitizedPrefix)_\(wan)"
    let reportLabel = "\(sanitizedPrefix)_(\(wan))"
    let payload = RuntimeCustomerProfilePayload(
        prefix: sanitizedPrefix,
        publicIP: publicIP,
        wan: wan,
        fingerprint: String(fingerprint),
        baseName: baseName,
        reportLabel: reportLabel,
        folderName: "\(baseName)_\(fingerprint)",
        topology: topology
    )
    if let data = try? encoder.encode(payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode customer profile\"}")
        exit(1)
    }
case "topology-parts":
    guard let payloadJSON = decodePath(named: "--payload"), let data = payloadJSON.data(using: .utf8), let input = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        fputs("{\"success\":false,\"error\":\"Missing topology payload\"}", stdout)
        exit(1)
    }
    let hosts = ((input["hosts"] as? [String]) ?? []).sorted()
    let hops = ((input["hops"] as? [String]) ?? []).sorted()
    let network = String(describing: input["network"] as? String ?? "")
    let payload: [String: Any] = ["hosts": hosts, "hops": hops, "network": network]
    if let data = try? JSONSerialization.data(withJSONObject: payload), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode topology parts\"}")
        exit(1)
    }
case "bootstrap-snapshot":
    let network = await getNetworkSnapshot()
    let topology = (decodeJSONObject(from: decodePath(named: "--topology") ?? "") as? [String: [String]]) ?? [:]
    let prefix = decodePath(named: "--prefix") ?? "CSP"
    let customerTopology = topology
    let fingerprintSource = Data("\(prefix)::\(network.publicIP)::\(topology)".utf8)
    let fingerprint = digestHex(fingerprintSource)
    let customerProfile = RuntimeCustomerProfilePayload(
        prefix: sanitizeSegment(prefix, fallback: "CSP"),
        publicIP: network.publicIP,
        wan: sanitizeSegment(network.publicIP, fallback: "unknown_wan"),
        fingerprint: fingerprint,
        baseName: "\(sanitizeSegment(prefix, fallback: "CSP"))_\(sanitizeSegment(network.publicIP, fallback: "unknown_wan"))",
        reportLabel: "\(sanitizeSegment(prefix, fallback: "CSP"))_(\(sanitizeSegment(network.publicIP, fallback: "unknown_wan")))",
        folderName: "\(sanitizeSegment(prefix, fallback: "CSP"))_\(sanitizeSegment(network.publicIP, fallback: "unknown_wan"))_\(fingerprint)",
        topology: customerTopology
    )
    let googleDrive = (decodeJSONObject(from: decodePath(named: "--google-drive") ?? "") ?? [:]).mapValues(jsonValue)
    let autoScan = (decodeJSONObject(from: decodePath(named: "--auto-scan") ?? "") ?? [:]).mapValues(jsonValue)
    let snapshot = RuntimeInitialDataEnvelope(
        network: network,
        publicIP: network.publicIP,
        customerProfile: runtimeCustomerProfile(from: customerProfile),
        googleDrive: googleDrive,
        autoScan: autoScan
    )
    if let data = try? encoder.encode(snapshot), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode bootstrap snapshot\"}")
        exit(1)
    }
case "network-info":
    let snapshot = await getNetworkSnapshot()
    if let data = try? encoder.encode(snapshot), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"success\":false,\"error\":\"Failed to encode network snapshot\"}")
        exit(1)
    }
case "inject-gowitness":
    guard let reportPath = decodePath(named: "--report-path"), let screenshotsJSON = decodePath(named: "--screenshots"), let data = screenshotsJSON.data(using: .utf8), let screenshots = try? JSONDecoder().decode([RuntimeGowitnessScreenshot].self, from: data) else {
        fputs("{\"success\":false,\"error\":\"Missing gowitness args\"}", stdout)
        exit(1)
    }
    injectGowitnessSection(reportPath: URL(fileURLWithPath: reportPath), screenshots: screenshots)
    print("{\"success\":true}")
default:
    print("{\"success\":false,\"error\":\"Invalid command\"}")
    exit(1)
}
