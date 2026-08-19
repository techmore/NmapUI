import Darwin
import Foundation

enum ScanTargetValidationError: LocalizedError, Equatable {
    case empty
    case invalid(String)
    case tooLarge(Int)
    case confirmationRequired(Int)

    var errorDescription: String? {
        switch self {
        case .empty:
            return "Enter at least one scan target."
        case .invalid(let target):
            return "Invalid scan target: \(target)"
        case .tooLarge(let count):
            return "The scan target contains about \(count) addresses; the maximum is \(ScanTargetValidator.maximumHostCount). Narrow the range or split it into smaller scans."
        case .confirmationRequired(let count):
            return "The scan target contains about \(count) addresses. Confirm a large-range scan before continuing."
        }
    }
}

enum ScanTargetValidator {
    static let maximumHostCount = 65_536
    static let largeRangeConfirmationThreshold = 4_096

    static func validate(_ rawTarget: String, allowLargeRanges: Bool = false) throws -> String {
        let targets = rawTarget
            .split(whereSeparator: { $0 == "," || $0.isWhitespace })
            .map(String.init)
        guard !targets.isEmpty else { throw ScanTargetValidationError.empty }

        var estimatedHosts = 0
        for target in targets {
            guard isSafeTarget(target) else { throw ScanTargetValidationError.invalid(target) }
            if let estimate = ipv4HostEstimate(target) {
                estimatedHosts += estimate
            }
        }

        if estimatedHosts > maximumHostCount {
            throw ScanTargetValidationError.tooLarge(estimatedHosts)
        }
        if estimatedHosts > largeRangeConfirmationThreshold && !allowLargeRanges {
            throw ScanTargetValidationError.confirmationRequired(estimatedHosts)
        }
        return targets.joined(separator: ",")
    }

    /// Used by ARP enrichment to decide whether a target includes the local
    /// interface. This handles supernets instead of requiring an exact CIDR
    /// string match.
    static func targetContains(localCIDR: String, target: String) -> Bool {
        let localParts = localCIDR.split(separator: "/", maxSplits: 1).map(String.init)
        guard let localIP = localParts.first else { return false }
        return target
            .split(whereSeparator: { $0 == "," || $0.isWhitespace })
            .map(String.init)
            .contains { contains(address: localIP, in: $0) }
    }

    private static func isSafeTarget(_ target: String) -> Bool {
        guard !target.isEmpty,
              !target.hasPrefix("-"),
              !target.contains(where: { ";&|><`$\\\"'".contains($0) }) else { return false }

        let addressAndPrefix = target.split(separator: "/", maxSplits: 1).map(String.init)
        guard addressAndPrefix.count <= 2 else { return false }
        if addressAndPrefix.count == 2 {
            guard let prefix = Int(addressAndPrefix[1]), prefix >= 0 else { return false }
            if isIPv4(addressAndPrefix[0]) { guard prefix <= 32 else { return false } }
            else if isIPv6(addressAndPrefix[0]) { guard prefix <= 128 else { return false } }
            else { return false }
            return true
        }

        return isIPv4(target) || isIPv6(target) || target.range(
            of: #"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$"#,
            options: .regularExpression
        ) != nil
    }

    private static func ipv4HostEstimate(_ target: String) -> Int? {
        let parts = target.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, isIPv4(parts[0]), let prefix = Int(parts[1]), (0...32).contains(prefix) else {
            return nil
        }
        let hostBits = 32 - prefix
        if hostBits >= 31 { return maximumHostCount + 1 }
        return min(maximumHostCount + 1, 1 << hostBits)
    }

    private static func isIPv4(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func isIPv6(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    private static func contains(address: String, in rule: String) -> Bool {
        let parts = rule.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, let prefix = Int(parts[1]), isIPv4(parts[0]), isIPv4(address), (0...32).contains(prefix) else {
            return false
        }
        func numeric(_ value: String) -> UInt32 {
            value.split(separator: ".").reduce(0) { ($0 << 8) | UInt32($1)! }
        }
        let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
        return numeric(parts[0]) & mask == numeric(address) & mask
    }
}
