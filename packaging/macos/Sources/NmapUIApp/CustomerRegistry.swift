import Foundation

struct CustomerRecord: Codable, Identifiable, Equatable {
    let id: UUID
    var name: String
    var reportPrefix: String
    var publicIPs: [String]
    var cidrs: [String]
    var notes: String
    let createdAt: Date
    var updatedAt: Date

    init(id: UUID = UUID(), name: String, reportPrefix: String, publicIPs: [String] = [], cidrs: [String] = [], notes: String = "", createdAt: Date = Date(), updatedAt: Date = Date()) {
        self.id = id
        self.name = name
        self.reportPrefix = reportPrefix
        self.publicIPs = publicIPs
        self.cidrs = cidrs
        self.notes = notes
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

struct CustomerRegistry: Codable, Equatable {
    var customers: [CustomerRecord]
    var activeCustomerID: UUID?

    static let empty = CustomerRegistry(customers: [], activeCustomerID: nil)

    static func load(from directory: URL) -> CustomerRegistry {
        let url = directory.appendingPathComponent("customers.json")
        guard FileManager.default.fileExists(atPath: url.path) else { return .empty }
        if let data = try? Data(contentsOf: url), let registry = try? JSONDecoder().decode(CustomerRegistry.self, from: data) {
            return registry
        }
        let backupURL = url.appendingPathExtension("backup")
        if let data = try? Data(contentsOf: backupURL), let registry = try? JSONDecoder().decode(CustomerRegistry.self, from: data) {
            return registry
        }
        RuntimeDiagnosticsLogger.error("Customer registry is corrupt; refusing to replace it with an empty registry")
        return .empty
    }

    func persist(to directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(self)
        let url = directory.appendingPathComponent("customers.json")
        if FileManager.default.fileExists(atPath: url.path) {
            try? FileManager.default.copyItemReplacing(at: url, to: url.appendingPathExtension("backup"))
        }
        try data.write(to: url, options: .atomic)
    }

    func resolvedCustomer(network: RuntimeNetworkState?) -> CustomerResolution {
        if let activeCustomerID, let active = customers.first(where: { $0.id == activeCustomerID }) {
            return .assigned(active, source: .manual)
        }
        guard let network else { return .unassigned }
        let matches = customers.filter { customer in
            customer.publicIPs.contains(network.publicIP)
                || customer.publicIPs.contains(where: { IPv4Matcher.contains(network.publicIP, in: $0) })
                || customer.cidrs.contains(network.cidr)
                || customer.cidrs.contains(where: { IPv4Matcher.contains(network.localIP, in: $0) })
        }
        if matches.count == 1, let match = matches.first { return .assigned(match, source: .automatic) }
        if matches.count > 1 { return .ambiguous(matches) }
        return .unassigned
    }

    func resolvedCustomerForScheduledScan(network: RuntimeNetworkState?) -> CustomerResolution {
        guard let network else { return .unassigned }
        let matches = customers.filter {
            $0.publicIPs.contains(network.publicIP)
                || $0.publicIPs.contains(where: { IPv4Matcher.contains(network.publicIP, in: $0) })
                || $0.cidrs.contains(network.cidr)
                || $0.cidrs.contains(where: { IPv4Matcher.contains(network.localIP, in: $0) })
        }
        if matches.count == 1, let match = matches.first { return .assigned(match, source: .automatic) }
        if matches.count > 1 { return .ambiguous(matches) }
        return .unassigned
    }
}

private enum IPv4Matcher {
    static func contains(_ address: String, in rule: String) -> Bool {
        let parts = rule.split(separator: "/", maxSplits: 1).map(String.init)
        guard let base = ipv4(parts[0]), parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix), let value = ipv4(address) else { return false }
        let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
        return (base & mask) == (value & mask)
    }

    private static func ipv4(_ value: String) -> UInt32? {
        let parts = value.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return nil }
        return parts.reduce(0) { ($0 << 8) | $1 }
    }
}

private extension FileManager {
    func copyItemReplacing(at source: URL, to destination: URL) throws {
        if fileExists(atPath: destination.path) { try removeItem(at: destination) }
        try copyItem(at: source, to: destination)
    }
}

enum CustomerResolution: Equatable {
    enum Source: Equatable { case manual, automatic }
    case assigned(CustomerRecord, source: Source)
    case unassigned
    case ambiguous([CustomerRecord])
}
