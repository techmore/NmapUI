import Foundation
import RuntimeContracts

extension RuntimeNmapXMLSummary {
    var hostCount: Int { hosts.count }
    var openPortCount: Int {
        hosts.reduce(0) { total, host in
            total + host.ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }.count
        }
    }
    var criticalCVECount: Int {
        // Preserve the existing dashboard metric semantics: it represents
        // high-impact findings (CVSS 7.0+), while each finding retains its
        // precise critical/high severity in the structured model.
        hosts.reduce(0) { $0 + $1.vulnerabilities.filter { $0.score >= 7.0 }.count }
    }
    var lowCVECount: Int {
        hosts.reduce(0) { $0 + $1.lowCVECount }
    }

    func comparison(to previous: RuntimeNmapXMLSummary) -> RuntimeScanComparison {
        let currentByIP = hosts.reduce(into: [String: RuntimeNmapXMLHostSummary]()) { $0[$1.ip] = $1 }
        let previousByIP = previous.hosts.reduce(into: [String: RuntimeNmapXMLHostSummary]()) { $0[$1.ip] = $1 }
        let currentPorts = Set(hosts.flatMap { $0.ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } })
        let previousPorts = Set(previous.hosts.flatMap { $0.ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } })
        let currentVulnerabilities = Set(hosts.flatMap { host in host.vulnerabilities.map { $0.id + "@" + ($0.port ?? "host") } })
        let previousVulnerabilities = Set(previous.hosts.flatMap { host in host.vulnerabilities.map { $0.id + "@" + ($0.port ?? "host") } })
        let changed = currentByIP.compactMap { ip, host -> String? in
            guard let old = previousByIP[ip] else { return nil }
            return host.ports != old.ports || host.version != old.version || host.os != old.os || host.vulnerabilities != old.vulnerabilities ? ip : nil
        }.sorted()
        return RuntimeScanComparison(
            newHosts: currentByIP.keys.filter { previousByIP[$0] == nil }.sorted(),
            removedHosts: previousByIP.keys.filter { currentByIP[$0] == nil }.sorted(),
            changedHosts: changed,
            newPorts: currentPorts.subtracting(previousPorts).sorted(),
            removedPorts: previousPorts.subtracting(currentPorts).sorted(),
            newVulnerabilities: currentVulnerabilities.subtracting(previousVulnerabilities).sorted(),
            resolvedVulnerabilities: previousVulnerabilities.subtracting(currentVulnerabilities).sorted()
        )
    }
}

enum RuntimeNmapXMLParser {
    static func parse(contentsOf url: URL) -> RuntimeNmapXMLSummary? {
        guard let data = try? Data(contentsOf: url), let xml = String(data: data, encoding: .utf8) else { return nil }
        return parse(xml: xml)
    }

    static func parse(xml: String) -> RuntimeNmapXMLSummary? {
        guard xml.contains("<nmaprun"), xml.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("</nmaprun>") else {
            return nil
        }
        let parserDelegate = Delegate()
        let parser = XMLParser(data: Data(xml.utf8))
        parser.delegate = parserDelegate
        return parser.parse() ? RuntimeNmapXMLSummary(hosts: parserDelegate.hosts) : nil
    }

    private final class Delegate: NSObject, XMLParserDelegate {
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
            } else if elementName == "table" {
                currentHost?.startVulnersTable()
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
    private var vulnerabilities: [RuntimeVulnerabilityFinding] = []
    private var currentPortId = ""
    private var currentPortOpen = false
    private var currentService: [String: String] = [:]
    private var inVulnersScript = false
    private var inVulnersTable = false
    private var currentElemKey = ""
    private var pendingCVSS = ""
    private var pendingCVEId = ""
    private var pendingType = ""
    private var pendingExploit = false

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

    func startVulnersTable() {
        guard inVulnersScript else { return }
        inVulnersTable = true
        pendingCVSS = ""
        pendingCVEId = ""
        pendingType = ""
        pendingExploit = false
    }

    func captureVulnersElement(attributes: [String: String]) {
        guard inVulnersScript, inVulnersTable else { return }
        currentElemKey = attributes["name"] ?? attributes["key"] ?? ""
    }

    func appendCharacters(_ string: String) {
        guard inVulnersScript, inVulnersTable else { return }
        if currentElemKey == "cvss" {
            pendingCVSS += string
        } else if currentElemKey == "id" {
            pendingCVEId += string
        } else if currentElemKey == "type" {
            pendingType += string
        } else if currentElemKey == "is_exploit" {
            pendingExploit = pendingExploit || string.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "true"
        }
    }

    func endElement(_ elementName: String) {
        if elementName == "table", inVulnersTable {
            let normalizedId = pendingCVEId.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            let normalizedScore = pendingCVSS.trimmingCharacters(in: .whitespacesAndNewlines)
            if !normalizedId.isEmpty, !normalizedScore.isEmpty, let score = Double(normalizedScore), normalizedId.hasPrefix("CVE-") {
                let severity = score >= 9.0 ? "critical" : (score >= 7.0 ? "high" : (score >= 4.0 ? "medium" : "low"))
                let sourceType = pendingType.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "cve" : pendingType.trimmingCharacters(in: .whitespacesAndNewlines)
                vulnerabilities.append(RuntimeVulnerabilityFinding(id: normalizedId, score: score, severity: severity, port: currentPortId.isEmpty ? nil : currentPortId, service: currentService["name"], url: "https://vulners.com/\(sourceType)/\(normalizedId)", exploit: pendingExploit))
                if score >= 7.0 {
                    highCVEs.insert("\(normalizedId)(\(score))")
                } else {
                    lowCVEs.insert(normalizedId)
                }
            }
            inVulnersTable = false
            currentElemKey = ""
            pendingCVSS = ""
            pendingCVEId = ""
            pendingType = ""
            pendingExploit = false
        } else if elementName == "script" {
            inVulnersScript = false
            inVulnersTable = false
            currentElemKey = ""
            pendingCVSS = ""
            pendingCVEId = ""
            pendingType = ""
            pendingExploit = false
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
            lowCVECount: lowCVEs.count,
            vulnerabilities: vulnerabilities.sorted { $0.id == $1.id ? $0.score > $1.score : $0.id < $1.id }
        )
    }
}
