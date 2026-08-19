import Darwin
import Foundation

public enum NmapPrivilegedHelperContract {
    public static let protocolVersion = 4
    public static let machServiceName = "com.techmore.nmapui.nmap-helper"
    public static let authorizedBundleIdentifier = "com.techmore.nmapui"
    public static let privilegedNmapPath = "/Library/PrivilegedHelperTools/com.techmore.nmapui.nmap"
    public static let maximumScanRuntime: TimeInterval = 2 * 60 * 60
    public static let responseGracePeriod: TimeInterval = 30

    public static func isAllowedScanTarget(_ target: String) -> Bool {
        guard !target.isEmpty,
              !target.hasPrefix("-"),
              !target.contains(where: { ";&|><`$\\\"'".contains($0) }) else { return false }

        let parts = target.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count <= 2 else { return false }
        if parts.count == 2 {
            guard let prefix = Int(parts[1]), prefix >= 0 else { return false }
            if isIPv4(parts[0]) { return prefix <= 32 }
            if isIPv6(parts[0]) { return prefix <= 128 }
            return false
        }
        return isIPv4(target) || isIPv6(target) || target.range(
            of: #"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$"#,
            options: .regularExpression
        ) != nil
    }

    private static func isIPv4(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func isIPv6(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }
}

@objc public protocol NmapPrivilegedServiceProtocol: NSObjectProtocol {
    func ping(withReply reply: @escaping (Data) -> Void)
    func run(request: Data, withReply reply: @escaping (Data) -> Void)
    func cancel(request: Data, withReply reply: @escaping (Data) -> Void)
}
