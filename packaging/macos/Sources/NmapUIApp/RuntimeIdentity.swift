import Foundation

struct RuntimeIdentity: Codable {
    let app: String
    let name: String
    let version: String

    static let expectedApp = "tm-network-scanner"

    static func localFallback(version: String) -> RuntimeIdentity {
        RuntimeIdentity(app: expectedApp, name: "TM-NMapUI", version: version)
    }
}
