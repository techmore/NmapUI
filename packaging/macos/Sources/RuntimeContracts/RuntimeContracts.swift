import Foundation

public struct RuntimeReportDriveFile: Codable, Equatable {
    public let name: String
    public let webViewLink: String
    public let id: String

    public init(name: String, webViewLink: String, id: String) {
        self.name = name
        self.webViewLink = webViewLink
        self.id = id
    }
}

public struct RuntimeReportMetadata: Codable, Equatable {
    public let uploadedAt: String
    public let folderId: String?
    public let dayFolderId: String?
    public let links: [RuntimeReportDriveFile]

    public init(uploadedAt: String, folderId: String?, dayFolderId: String?, links: [RuntimeReportDriveFile]) {
        self.uploadedAt = uploadedAt
        self.folderId = folderId
        self.dayFolderId = dayFolderId
        self.links = links
    }
}

public struct RuntimeReportPayload: Codable, Equatable {
    public let url: String
    public let pdfUrl: String?
    public let name: String
    public let pdfName: String?
    public let xmlName: String
    public let xmlUrl: String?
    public let customerProfile: RuntimeCustomerProfile
    public let driveHtmlUrl: String?
    public let drivePdfUrl: String?

    public init(
        url: String,
        pdfUrl: String?,
        name: String,
        pdfName: String?,
        xmlName: String,
        xmlUrl: String?,
        customerProfile: RuntimeCustomerProfile,
        driveHtmlUrl: String?,
        drivePdfUrl: String?
    ) {
        self.url = url
        self.pdfUrl = pdfUrl
        self.name = name
        self.pdfName = pdfName
        self.xmlName = xmlName
        self.xmlUrl = xmlUrl
        self.customerProfile = customerProfile
        self.driveHtmlUrl = driveHtmlUrl
        self.drivePdfUrl = drivePdfUrl
    }
}

public struct RuntimeReportHistoryEntry: Codable, Equatable {
    public let timestamp: String
    public let target: String
    public let duration: String
    public let hostCount: Int
    public let scanKind: String
    public let status: String?
    public let error: String?
    public let reportUrl: String?
    public let pdfUrl: String?
    public let xmlUrl: String?
    public let customerProfile: RuntimeCustomerProfile?

    public init(
        timestamp: String,
        target: String,
        duration: String,
        hostCount: Int,
        scanKind: String,
        status: String?,
        error: String?,
        reportUrl: String?,
        pdfUrl: String?,
        xmlUrl: String?,
        customerProfile: RuntimeCustomerProfile?
    ) {
        self.timestamp = timestamp
        self.target = target
        self.duration = duration
        self.hostCount = hostCount
        self.scanKind = scanKind
        self.status = status
        self.error = error
        self.reportUrl = reportUrl
        self.pdfUrl = pdfUrl
        self.xmlUrl = xmlUrl
        self.customerProfile = customerProfile
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        timestamp = try container.decodeIfPresent(String.self, forKey: .timestamp) ?? ""
        target = try container.decodeIfPresent(String.self, forKey: .target) ?? ""
        duration = try container.decodeIfPresent(String.self, forKey: .duration) ?? ""
        hostCount = try container.decodeIfPresent(Int.self, forKey: .hostCount) ?? 0
        scanKind = try container.decodeIfPresent(String.self, forKey: .scanKind) ?? "complete"
        status = try container.decodeIfPresent(String.self, forKey: .status)
        error = try container.decodeIfPresent(String.self, forKey: .error)
        reportUrl = try container.decodeIfPresent(String.self, forKey: .reportUrl)
        pdfUrl = try container.decodeIfPresent(String.self, forKey: .pdfUrl)
        xmlUrl = try container.decodeIfPresent(String.self, forKey: .xmlUrl)
        // Older history entries included extra customer fields; ignore decode failures.
        customerProfile = try? container.decodeIfPresent(RuntimeCustomerProfile.self, forKey: .customerProfile) ?? nil
    }
}

public struct RuntimeReportsSnapshot: Codable, Equatable {
    public let generatedAt: String
    public let reports: [RuntimeReportListEntry]

    public init(generatedAt: String, reports: [RuntimeReportListEntry]) {
        self.generatedAt = generatedAt
        self.reports = reports
    }

    public static func make(reports: [RuntimeReportListEntry], generatedAt: Date = Date()) -> RuntimeReportsSnapshot {
        RuntimeReportsSnapshot(
            generatedAt: ISO8601DateFormatter().string(from: generatedAt),
            reports: reports
        )
    }
}

public struct RuntimeReportListEntry: Codable, Equatable {
    public let name: String
    public let folder: String
    public let url: String?
    public let pdfName: String?
    public let pdfUrl: String?
    public let xmlName: String?
    public let xmlUrl: String?
    public let driveHtmlUrl: String?
    public let drivePdfUrl: String?
    public let date: String
    public let duration: String?
    public let hostCount: Int?
    public let status: String?
    public let error: String?

    public init(
        name: String,
        folder: String,
        url: String?,
        pdfName: String?,
        pdfUrl: String?,
        xmlName: String?,
        xmlUrl: String?,
        driveHtmlUrl: String?,
        drivePdfUrl: String?,
        date: String,
        duration: String?,
        hostCount: Int?,
        status: String?,
        error: String?
    ) {
        self.name = name
        self.folder = folder
        self.url = url
        self.pdfName = pdfName
        self.pdfUrl = pdfUrl
        self.xmlName = xmlName
        self.xmlUrl = xmlUrl
        self.driveHtmlUrl = driveHtmlUrl
        self.drivePdfUrl = drivePdfUrl
        self.date = date
        self.duration = duration
        self.hostCount = hostCount
        self.status = status
        self.error = error
    }
}

public struct RuntimeFailedScanEntry: Codable, Equatable {
    public let timestamp: String
    public let scanLabel: String
    public let folder: String
    public let status: String
    public let error: String
    public let hostCount: Int
    public let duration: String

    public init(timestamp: String, scanLabel: String, folder: String, status: String, error: String, hostCount: Int, duration: String) {
        self.timestamp = timestamp
        self.scanLabel = scanLabel
        self.folder = folder
        self.status = status
        self.error = error
        self.hostCount = hostCount
        self.duration = duration
    }
}

public struct RuntimeNmapXMLHostSummary: Codable, Equatable {
    public let ip: String
    public let mac: String
    public let vendor: String
    public let hostname: String
    public let os: String
    public let latency: String
    public let ports: String
    public let version: String
    public let highCVEs: String
    public let lowCVECount: Int

    public init(ip: String, mac: String, vendor: String, hostname: String, os: String, latency: String, ports: String, version: String, highCVEs: String, lowCVECount: Int) {
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.hostname = hostname
        self.os = os
        self.latency = latency
        self.ports = ports
        self.version = version
        self.highCVEs = highCVEs
        self.lowCVECount = lowCVECount
    }
}

public struct RuntimeNmapXMLSummary: Codable, Equatable {
    public let hosts: [RuntimeNmapXMLHostSummary]

    public init(hosts: [RuntimeNmapXMLHostSummary]) {
        self.hosts = hosts
    }
}

public struct RuntimeScanStats: Codable, Equatable {
    public let hostCount: Int
    public let openPortCount: Int
    public let criticalCVECount: Int
    public let lowCVECount: Int

    public init(hostCount: Int, openPortCount: Int, criticalCVECount: Int, lowCVECount: Int) {
        self.hostCount = hostCount
        self.openPortCount = openPortCount
        self.criticalCVECount = criticalCVECount
        self.lowCVECount = lowCVECount
    }
}

public struct RuntimePhase1Discovery: Codable, Equatable {
    public let ip: String
    public let hostname: String

    public init(ip: String, hostname: String) {
        self.ip = ip
        self.hostname = hostname
    }
}

public struct RuntimePhase1ScanResult: Codable, Equatable {
    public let success: Bool
    public let duration: String
    public let hosts: [RuntimePhase1Discovery]
    public let error: String?

    public init(success: Bool, duration: String, hosts: [RuntimePhase1Discovery], error: String?) {
        self.success = success
        self.duration = duration
        self.hosts = hosts
        self.error = error
    }
}

public struct RuntimePhase2ScanResult: Codable, Equatable {
    public let success: Bool
    public let duration: String
    public let summary: RuntimeNmapXMLSummary?
    public let xmlPath: String?
    public let error: String?

    public init(success: Bool, duration: String, summary: RuntimeNmapXMLSummary?, xmlPath: String?, error: String?) {
        self.success = success
        self.duration = duration
        self.summary = summary
        self.xmlPath = xmlPath
        self.error = error
    }
}

public struct RuntimeNetworkSnapshot: Codable, Equatable {
    public let localIP: String
    public let mask: String
    public let cidr: String
    public let publicIP: String

    public init(localIP: String, mask: String, cidr: String, publicIP: String) {
        self.localIP = localIP
        self.mask = mask
        self.cidr = cidr
        self.publicIP = publicIP
    }
}

public enum RuntimeJSONValue: Codable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case object([String: RuntimeJSONValue])
    case array([RuntimeJSONValue])
    case null

    public init?(jsonValue: Any) {
        switch jsonValue {
        case let value as Bool:
            self = .bool(value)
        case let value as String:
            self = .string(value)
        case let value as Int:
            self = .int(value)
        case let value as Double:
            self = .double(value)
        case let value as [String: Any]:
            let mapped = value.compactMapValues { RuntimeJSONValue(jsonValue: $0) }
            self = .object(mapped)
        case let value as [Any]:
            self = .array(value.compactMap(RuntimeJSONValue.init(jsonValue:)))
        case _ as NSNull:
            self = .null
        default:
            return nil
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode([String: RuntimeJSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([RuntimeJSONValue].self) {
            self = .array(value)
        } else {
            self = .null
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .double(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}
