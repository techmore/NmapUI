import Foundation
import RuntimeContracts

struct ARPHostIdentity: Sendable {
    let ip: String
    let mac: String
    let vendor: String
}

enum ARPDiscovery {
    static func enrich(_ summary: RuntimeNmapXMLSummary, target: String) async -> RuntimeNmapXMLSummary {
        let localCIDR = RuntimeNetworkState.localNetworkInfo().cidr
        guard !localCIDR.isEmpty, localCIDR != "Unknown", ScanTargetValidator.targetContains(localCIDR: localCIDR, target: target) else {
            return summary
        }
        var identities: [ARPHostIdentity] = localInterfaceIdentity().map { [$0] } ?? []
        guard let executable = ["/opt/homebrew/bin/arp-scan", "/usr/local/bin/arp-scan", "/usr/sbin/arp-scan"]
            .first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            RuntimeDiagnosticsLogger.log("ARP enrichment unavailable: arp-scan is not installed")
            return summary.mergingARP(identities)
        }
        do {
            let result = try await Task.detached(priority: .utility) {
                try ExternalProcessRunner.run(
                    executable: URL(fileURLWithPath: executable),
                    arguments: [localCIDR, "--interface", interfaceName()],
                    timeout: 30,
                    maxOutputBytes: 512 * 1024
                )
            }.value
            guard result.exitCode == 0 else {
                RuntimeDiagnosticsLogger.log("ARP enrichment skipped: arp-scan exited \(result.exitCode) \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
                return summary.mergingARP(identities)
            }
            identities.append(contentsOf: parse(result.stdout))
            RuntimeDiagnosticsLogger.log("ARP enrichment found \(identities.count) host identities")
            return summary.mergingARP(identities)
        } catch {
            RuntimeDiagnosticsLogger.log("ARP enrichment skipped: \(error.localizedDescription)")
            return summary.mergingARP(identities)
        }
    }

    static func parse(_ output: String) -> [ARPHostIdentity] {
        output.split(separator: "\n").compactMap { line in
            let columns = line.split(omittingEmptySubsequences: true, whereSeparator: { $0 == " " || $0 == "\t" })
            guard columns.count >= 2,
                  String(columns[0]).range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil,
                  String(columns[1]).range(of: #"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"#, options: .regularExpression) != nil else { return nil }
            return ARPHostIdentity(ip: String(columns[0]), mac: String(columns[1]).uppercased(), vendor: columns.dropFirst(2).joined(separator: " "))
        }
    }

    private static func interfaceName() -> String {
        let output = RuntimeNetworkState.runProcess("/usr/sbin/route", ["get", "default"], timeout: 2)
        return RuntimeNetworkState.firstCapture(in: output, pattern: #"interface:\s+([A-Za-z0-9_.-]+)"#) ?? "en0"
    }

    private static func localInterfaceIdentity() -> ARPHostIdentity? {
        let network = RuntimeNetworkState.localNetworkInfo()
        guard !network.localIP.isEmpty, network.localIP != "Unknown" else { return nil }
        let interface = interfaceName()
        let output = RuntimeNetworkState.runProcess("/sbin/ifconfig", [interface], timeout: 2)
        guard let mac = RuntimeNetworkState.firstCapture(in: output, pattern: #"ether\s+([0-9A-Fa-f:]{17})"#) else {
            return nil
        }
        return ARPHostIdentity(ip: network.localIP, mac: mac.uppercased(), vendor: "Local interface (\(interface))")
    }
}

private extension RuntimeNmapXMLSummary {
    func mergingARP(_ identities: [ARPHostIdentity]) -> RuntimeNmapXMLSummary {
        let byIP = identities.reduce(into: [String: ARPHostIdentity]()) { result, identity in
            // arp-scan can repeat an address when interfaces or vendor tables
            // race. Keep the last complete row instead of trapping.
            result[identity.ip] = identity
        }
        return RuntimeNmapXMLSummary(hosts: hosts.map { host in
            guard let identity = byIP[host.ip] else { return host }
            return RuntimeNmapXMLHostSummary(
                ip: host.ip,
                mac: host.mac == "" ? identity.mac : host.mac,
                vendor: host.vendor == "" ? identity.vendor : host.vendor,
                hostname: host.hostname,
                os: host.os,
                latency: host.latency,
                ports: host.ports,
                version: host.version,
                highCVEs: host.highCVEs,
                lowCVECount: host.lowCVECount,
                vulnerabilities: host.vulnerabilities
            )
        })
    }
}
