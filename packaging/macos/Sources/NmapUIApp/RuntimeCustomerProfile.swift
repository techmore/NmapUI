import Foundation
import CryptoKit
import RuntimeContracts

extension RuntimeCustomerProfile {
    static func current(prefix: String, networkState: RuntimeNetworkState?) -> RuntimeCustomerProfile {
        let normalizedPrefix = sanitize(prefix, fallback: "CSP")
        let publicIP = sanitize(networkState?.publicIP ?? "unknown_wan", fallback: "unknown_wan")
        let baseName = "\(normalizedPrefix)_\(publicIP)"
        let reportLabel = "\(normalizedPrefix)_(\(publicIP))"
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
            prefix: normalizedPrefix,
            publicIP: publicIP,
            fingerprint: fingerprint,
            baseName: baseName,
            reportLabel: reportLabel,
            folderName: "\(baseName)_\(fingerprint)"
        )
    }

    private static func sanitize(_ value: String, fallback: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? fallback : trimmed
    }
}
