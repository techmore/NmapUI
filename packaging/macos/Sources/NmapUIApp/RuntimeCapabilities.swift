import Foundation

struct RuntimeCapabilities: Codable, Sendable {
    let googleDriveHelperAvailable: Bool
    let arpScanAvailable: Bool
    let vulnersAvailable: Bool
    let gowitnessAvailable: Bool
    let privilegedHelperAvailable: Bool

    init(googleDriveHelperAvailable: Bool, arpScanAvailable: Bool = false, vulnersAvailable: Bool = false, gowitnessAvailable: Bool = false, privilegedHelperAvailable: Bool = false) {
        self.googleDriveHelperAvailable = googleDriveHelperAvailable
        self.arpScanAvailable = arpScanAvailable
        self.vulnersAvailable = vulnersAvailable
        self.gowitnessAvailable = gowitnessAvailable
        self.privilegedHelperAvailable = privilegedHelperAvailable
    }

    private enum CodingKeys: String, CodingKey { case googleDriveHelperAvailable, arpScanAvailable, vulnersAvailable, gowitnessAvailable, privilegedHelperAvailable }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            googleDriveHelperAvailable: try container.decodeIfPresent(Bool.self, forKey: .googleDriveHelperAvailable) ?? false,
            arpScanAvailable: try container.decodeIfPresent(Bool.self, forKey: .arpScanAvailable) ?? false,
            vulnersAvailable: try container.decodeIfPresent(Bool.self, forKey: .vulnersAvailable) ?? false,
            gowitnessAvailable: try container.decodeIfPresent(Bool.self, forKey: .gowitnessAvailable) ?? false,
            privilegedHelperAvailable: try container.decodeIfPresent(Bool.self, forKey: .privilegedHelperAvailable) ?? false
        )
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(googleDriveHelperAvailable, forKey: .googleDriveHelperAvailable)
        try container.encode(arpScanAvailable, forKey: .arpScanAvailable)
        try container.encode(vulnersAvailable, forKey: .vulnersAvailable)
        try container.encode(gowitnessAvailable, forKey: .gowitnessAvailable)
        try container.encode(privilegedHelperAvailable, forKey: .privilegedHelperAvailable)
    }

    static func current() -> RuntimeCapabilities {
        let helperPath = RuntimeToolchain.current().googleDriveHelperPath
        let arpScanAvailable = ["/opt/homebrew/bin/arp-scan", "/usr/local/bin/arp-scan", "/usr/sbin/arp-scan"].contains {
            FileManager.default.isExecutableFile(atPath: $0)
        }
        let vulnersAvailable = FileManager.default.fileExists(atPath: RuntimeVulners.scriptPath())
        return RuntimeCapabilities(
            googleDriveHelperAvailable: helperPath.map(FileManager.default.isExecutableFile(atPath:)) ?? false,
            arpScanAvailable: arpScanAvailable,
            vulnersAvailable: vulnersAvailable,
            gowitnessAvailable: GowitnessManager.resolvedBinaryURL() != nil,
            privilegedHelperAvailable: PrivilegeHelperClient.isCurrentHelperReachable
        )
    }
}
