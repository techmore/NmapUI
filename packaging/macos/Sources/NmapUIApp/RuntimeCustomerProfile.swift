import Foundation
import CryptoKit
import RuntimeContracts

extension RuntimeCustomerProfile {
    static func current(prefix: String, networkState: RuntimeNetworkState?, customer: CustomerRecord? = nil) -> RuntimeCustomerProfile {
        let normalizedPrefix = RuntimeReportNaming.sanitizeSegment(prefix, fallback: "CSP")
        let publicIP = RuntimeReportNaming.sanitizeSegment(networkState?.publicIP, fallback: "unknown_wan")
        let customerName = customer.map { RuntimeReportNaming.sanitizeSegment($0.name, fallback: "Customer") }
        let baseName = customerName.map { "\(normalizedPrefix)_\($0)" } ?? "\(normalizedPrefix)_\(publicIP)"
        let reportLabel = customerName ?? "\(normalizedPrefix)_(\(publicIP))"
        let fingerprintSource = [
            normalizedPrefix,
            publicIP,
            networkState?.localIP ?? "",
            networkState?.cidr ?? "",
            networkState?.mask ?? "",
            (networkState?.tracerouteHops ?? []).map { "\($0.hop):\($0.ip)" }.joined(separator: "|")
        ].joined(separator: "::")
        let fingerprint = SHA256.hash(data: Data(fingerprintSource.utf8))
            .prefix(4)
            .map { String(format: "%02x", $0) }
            .joined()
        return RuntimeCustomerProfile(
            customerID: customer?.id.uuidString,
            customerName: customerName,
            prefix: normalizedPrefix,
            publicIP: publicIP,
            fingerprint: fingerprint,
            baseName: baseName,
            reportLabel: reportLabel,
            folderName: customer.map { "\(baseName)_\($0.id.uuidString.prefix(8))" } ?? "\(baseName)_\(fingerprint)"
        )
    }
}
