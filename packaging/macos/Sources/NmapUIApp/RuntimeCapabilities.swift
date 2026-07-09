import Foundation

struct RuntimeCapabilities: Codable {
    let googleDriveHelperAvailable: Bool

    static func current() -> RuntimeCapabilities {
        let helperPath = RuntimeToolchain.current().googleDriveHelperPath
        return RuntimeCapabilities(googleDriveHelperAvailable: helperPath.map(FileManager.default.isExecutableFile(atPath:)) ?? false)
    }
}
