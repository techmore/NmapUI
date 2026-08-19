import Foundation
import CryptoKit

public struct RuntimeCustomerProfile: Codable, Equatable, Sendable {
    public let customerID: String?
    public let customerName: String?
    public let prefix: String
    public let publicIP: String
    public let fingerprint: String
    public let baseName: String
    public let reportLabel: String
    public let folderName: String

    public init(customerID: String? = nil, customerName: String? = nil, prefix: String, publicIP: String, fingerprint: String, baseName: String, reportLabel: String, folderName: String) {
        self.customerID = customerID
        self.customerName = customerName
        self.prefix = prefix
        self.publicIP = publicIP
        self.fingerprint = fingerprint
        self.baseName = baseName
        self.reportLabel = reportLabel
        self.folderName = folderName
    }
}
