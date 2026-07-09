import Foundation

public enum RuntimeSocketEvent: String, CaseIterable, Codable {
    case syncState = "sync_state"
    case scanStarted = "scan_started"
    case phaseComplete = "phase_complete"
    case phaseStats = "phase_stats"
    case scanComplete = "scan_complete"
    case scanStopped = "scan_stopped"
    case initialData = "initial_data"
    case historyData = "history_data"
    case customerProfile = "customer_profile"
    case googleDriveStatus = "google_drive_status"
    case googleDriveAuthURL = "google_drive_auth_url"
    case reportsData = "reports_data"
    case autoScanConfig = "auto_scan_config"
    case tracerouteHop = "traceroute_hop"
    case discoveryUpdate = "discovery_update"
    case reportReady = "report_ready"
    case reportsRefresh = "reports_refresh"
    case logEntry = "log_entry"
}

public struct RuntimeScanLifecycleEnvelope: Codable, Equatable {
    public let phase: Int
    public let target: String
    public let startTime: String?
    public let scanKind: String

    public init(phase: Int, target: String, startTime: String?, scanKind: String) {
        self.phase = phase
        self.target = target
        self.startTime = startTime
        self.scanKind = scanKind
    }
}

public struct RuntimeScanStoppedEnvelope: Codable, Equatable {
    public init() {}
}

public struct RuntimeSyncStateEnvelope: Codable, Equatable {
    public let version: String
    public let hosts: [RuntimeNmapXMLHostSummary]
    public let isScanning: Bool
    public let phase: Int?
    public let target: String?
    public let startTime: String?
    public let scanKind: String?
    public let hops: [RuntimeJSONValue]
    public let customerProfile: RuntimeCustomerProfile?
    public let autoScan: [String: RuntimeJSONValue]

    public init(
        version: String,
        hosts: [RuntimeNmapXMLHostSummary],
        isScanning: Bool,
        phase: Int?,
        target: String?,
        startTime: String?,
        scanKind: String?,
        hops: [RuntimeJSONValue],
        customerProfile: RuntimeCustomerProfile?,
        autoScan: [String: RuntimeJSONValue]
    ) {
        self.version = version
        self.hosts = hosts
        self.isScanning = isScanning
        self.phase = phase
        self.target = target
        self.startTime = startTime
        self.scanKind = scanKind
        self.hops = hops
        self.customerProfile = customerProfile
        self.autoScan = autoScan
    }
}

public struct RuntimePhaseCompleteEnvelope: Codable, Equatable {
    public let phase: Int
    public let duration: String
    public let hostCount: Int?
    public let openPortCount: Int?
    public let criticalCVECount: Int?
    public let lowCVECount: Int?
    public let screenshotCount: Int?
    public let status: String?

    public init(
        phase: Int,
        duration: String,
        hostCount: Int? = nil,
        openPortCount: Int? = nil,
        criticalCVECount: Int? = nil,
        lowCVECount: Int? = nil,
        screenshotCount: Int? = nil,
        status: String? = nil
    ) {
        self.phase = phase
        self.duration = duration
        self.hostCount = hostCount
        self.openPortCount = openPortCount
        self.criticalCVECount = criticalCVECount
        self.lowCVECount = lowCVECount
        self.screenshotCount = screenshotCount
        self.status = status
    }
}

public struct RuntimePhaseStatsEnvelope: Codable, Equatable {
    public let phase: Int
    public let summary: RuntimeNmapXMLSummary

    public init(phase: Int, summary: RuntimeNmapXMLSummary) {
        self.phase = phase
        self.summary = summary
    }
}

public struct RuntimeDiscoveryUpdateEnvelope: Codable, Equatable {
    public let ip: String
    public let status: String
    public let hostname: String?
    public let vendor: String?

    public init(ip: String, status: String, hostname: String? = nil, vendor: String? = nil) {
        self.ip = ip
        self.status = status
        self.hostname = hostname
        self.vendor = vendor
    }
}

public struct RuntimeTracerouteHopEnvelope: Codable, Equatable {
    public let hop: Int
    public let ip: String

    public init(hop: Int, ip: String) {
        self.hop = hop
        self.ip = ip
    }
}

public struct RuntimeReportReadyEnvelope: Codable, Equatable {
    public let reportUrl: String
    public let pdfUrl: String?
    public let xmlUrl: String?
    public let customerProfile: RuntimeCustomerProfile

    public init(reportUrl: String, pdfUrl: String?, xmlUrl: String?, customerProfile: RuntimeCustomerProfile) {
        self.reportUrl = reportUrl
        self.pdfUrl = pdfUrl
        self.xmlUrl = xmlUrl
        self.customerProfile = customerProfile
    }
}

public struct RuntimeInitialDataEnvelope: Codable, Equatable {
    public let network: RuntimeNetworkSnapshot
    public let publicIP: String
    public let customerProfile: RuntimeCustomerProfile
    public let googleDrive: [String: RuntimeJSONValue]
    public let autoScan: [String: RuntimeJSONValue]

    public init(
        network: RuntimeNetworkSnapshot,
        publicIP: String,
        customerProfile: RuntimeCustomerProfile,
        googleDrive: [String: RuntimeJSONValue],
        autoScan: [String: RuntimeJSONValue]
    ) {
        self.network = network
        self.publicIP = publicIP
        self.customerProfile = customerProfile
        self.googleDrive = googleDrive
        self.autoScan = autoScan
    }
}

public struct RuntimeGoogleDriveStatusEnvelope: Codable, Equatable {
    public let success: Bool
    public let status: String
    public let config: [String: RuntimeJSONValue]

    public init(success: Bool, status: String, config: [String: RuntimeJSONValue]) {
        self.success = success
        self.status = status
        self.config = config
    }
}

public struct RuntimeHistoryDataEnvelope: Codable, Equatable {
    public let history: [RuntimeReportHistoryEntry]

    public init(history: [RuntimeReportHistoryEntry]) {
        self.history = history
    }
}

public struct RuntimeReportsDataEnvelope: Codable, Equatable {
    public let reports: [RuntimeReportListEntry]

    public init(reports: [RuntimeReportListEntry]) {
        self.reports = reports
    }
}

public struct RuntimeAutoScanConfigEnvelope: Codable, Equatable {
    public let enabled: Bool
    public let schedule: String
    public let scheduleLabel: String?
    public let config: [String: RuntimeJSONValue]

    public init(enabled: Bool, schedule: String, scheduleLabel: String?, config: [String: RuntimeJSONValue]) {
        self.enabled = enabled
        self.schedule = schedule
        self.scheduleLabel = scheduleLabel
        self.config = config
    }
}

public struct RuntimeGoogleDriveAuthURLEnvelope: Codable, Equatable {
    public let success: Bool
    public let url: String?
    public let status: String

    public init(success: Bool, url: String?, status: String) {
        self.success = success
        self.url = url
        self.status = status
    }
}

public struct RuntimeLogEntryEnvelope: Codable, Equatable {
    public let level: String
    public let message: String
    public let timestamp: String?

    public init(level: String, message: String, timestamp: String? = nil) {
        self.level = level
        self.message = message
        self.timestamp = timestamp
    }
}

public struct RuntimeBootstrapStateEnvelope: Codable, Equatable {
    public let initialData: RuntimeInitialDataEnvelope?
    public let syncState: RuntimeSyncStateEnvelope?
    public let tracerouteHops: [RuntimeTracerouteHopEnvelope]

    public init(
        initialData: RuntimeInitialDataEnvelope?,
        syncState: RuntimeSyncStateEnvelope?,
        tracerouteHops: [RuntimeTracerouteHopEnvelope]
    ) {
        self.initialData = initialData
        self.syncState = syncState
        self.tracerouteHops = tracerouteHops
    }
}

public struct RuntimeTransportSessionEnvelope: Codable, Equatable {
    public let bootstrapState: RuntimeBootstrapStateEnvelope?
    public let history: RuntimeHistoryDataEnvelope?
    public let reports: RuntimeReportsDataEnvelope?
    public let customerProfile: RuntimeCustomerProfile?
    public let googleDriveStatus: RuntimeGoogleDriveStatusEnvelope?
    public let autoScanConfig: RuntimeAutoScanConfigEnvelope?

    public init(
        bootstrapState: RuntimeBootstrapStateEnvelope?,
        history: RuntimeHistoryDataEnvelope?,
        reports: RuntimeReportsDataEnvelope?,
        customerProfile: RuntimeCustomerProfile?,
        googleDriveStatus: RuntimeGoogleDriveStatusEnvelope?,
        autoScanConfig: RuntimeAutoScanConfigEnvelope?
    ) {
        self.bootstrapState = bootstrapState
        self.history = history
        self.reports = reports
        self.customerProfile = customerProfile
        self.googleDriveStatus = googleDriveStatus
        self.autoScanConfig = autoScanConfig
    }
}

public enum RuntimeEventMessage: Codable, Equatable {
    case scanLifecycle(RuntimeScanLifecycleEnvelope)
    case scanStopped(RuntimeScanStoppedEnvelope)
    case syncState(RuntimeSyncStateEnvelope)
    case phaseComplete(RuntimePhaseCompleteEnvelope)
    case phaseStats(RuntimePhaseStatsEnvelope)
    case discoveryUpdate(RuntimeDiscoveryUpdateEnvelope)
    case tracerouteHop(RuntimeTracerouteHopEnvelope)
    case reportReady(RuntimeReportReadyEnvelope)
    case scanComplete(RuntimePhaseCompleteEnvelope)
    case initialData(RuntimeInitialDataEnvelope)
    case customerProfile(RuntimeCustomerProfile)
    case googleDriveStatus(RuntimeGoogleDriveStatusEnvelope)
    case historyData(RuntimeHistoryDataEnvelope)
    case reportsData(RuntimeReportsDataEnvelope)
    case reportsRefresh(RuntimeReportsDataEnvelope)
    case autoScanConfig(RuntimeAutoScanConfigEnvelope)
    case googleDriveAuthURL(RuntimeGoogleDriveAuthURLEnvelope)
    case logEntry(RuntimeLogEntryEnvelope)

    public var event: RuntimeSocketEvent {
        switch self {
        case .scanLifecycle: return .scanStarted
        case .scanStopped: return .scanStopped
        case .syncState: return .syncState
        case .phaseComplete: return .phaseComplete
        case .phaseStats: return .phaseStats
        case .discoveryUpdate: return .discoveryUpdate
        case .tracerouteHop: return .tracerouteHop
        case .reportReady: return .reportReady
        case .scanComplete: return .scanComplete
        case .initialData: return .initialData
        case .customerProfile: return .customerProfile
        case .googleDriveStatus: return .googleDriveStatus
        case .historyData: return .historyData
        case .reportsData: return .reportsData
        case .reportsRefresh: return .reportsRefresh
        case .autoScanConfig: return .autoScanConfig
        case .googleDriveAuthURL: return .googleDriveAuthURL
        case .logEntry: return .logEntry
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(event.rawValue, forKey: .event)
        switch self {
        case .scanLifecycle(let payload):
            try container.encode(payload, forKey: .payload)
        case .scanStopped(let payload):
            try container.encode(payload, forKey: .payload)
        case .syncState(let payload):
            try container.encode(payload, forKey: .payload)
        case .phaseComplete(let payload):
            try container.encode(payload, forKey: .payload)
        case .phaseStats(let payload):
            try container.encode(payload, forKey: .payload)
        case .discoveryUpdate(let payload):
            try container.encode(payload, forKey: .payload)
        case .tracerouteHop(let payload):
            try container.encode(payload, forKey: .payload)
        case .reportReady(let payload):
            try container.encode(payload, forKey: .payload)
        case .scanComplete(let payload):
            try container.encode(payload, forKey: .payload)
        case .initialData(let payload):
            try container.encode(payload, forKey: .payload)
        case .customerProfile(let payload):
            try container.encode(payload, forKey: .payload)
        case .googleDriveStatus(let payload):
            try container.encode(payload, forKey: .payload)
        case .historyData(let payload):
            try container.encode(payload, forKey: .payload)
        case .reportsData(let payload):
            try container.encode(payload, forKey: .payload)
        case .reportsRefresh(let payload):
            try container.encode(payload, forKey: .payload)
        case .autoScanConfig(let payload):
            try container.encode(payload, forKey: .payload)
        case .googleDriveAuthURL(let payload):
            try container.encode(payload, forKey: .payload)
        case .logEntry(let payload):
            try container.encode(payload, forKey: .payload)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let event = try container.decode(String.self, forKey: .event)
        switch event {
        case RuntimeSocketEvent.scanStarted.rawValue:
            self = .scanLifecycle(try container.decode(RuntimeScanLifecycleEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.syncState.rawValue:
            self = .syncState(try container.decode(RuntimeSyncStateEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.scanStopped.rawValue:
            self = .scanStopped(RuntimeScanStoppedEnvelope())
        case RuntimeSocketEvent.phaseComplete.rawValue:
            self = .phaseComplete(try container.decode(RuntimePhaseCompleteEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.phaseStats.rawValue:
            self = .phaseStats(try container.decode(RuntimePhaseStatsEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.discoveryUpdate.rawValue:
            self = .discoveryUpdate(try container.decode(RuntimeDiscoveryUpdateEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.tracerouteHop.rawValue:
            self = .tracerouteHop(try container.decode(RuntimeTracerouteHopEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.reportReady.rawValue:
            self = .reportReady(try container.decode(RuntimeReportReadyEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.scanComplete.rawValue:
            self = .scanComplete(try container.decode(RuntimePhaseCompleteEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.initialData.rawValue:
            self = .initialData(try container.decode(RuntimeInitialDataEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.customerProfile.rawValue:
            self = .customerProfile(try container.decode(RuntimeCustomerProfile.self, forKey: .payload))
        case RuntimeSocketEvent.googleDriveStatus.rawValue:
            self = .googleDriveStatus(try container.decode(RuntimeGoogleDriveStatusEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.historyData.rawValue:
            self = .historyData(try container.decode(RuntimeHistoryDataEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.reportsData.rawValue:
            self = .reportsData(try container.decode(RuntimeReportsDataEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.reportsRefresh.rawValue:
            self = .reportsRefresh(try container.decode(RuntimeReportsDataEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.autoScanConfig.rawValue:
            self = .autoScanConfig(try container.decode(RuntimeAutoScanConfigEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.googleDriveAuthURL.rawValue:
            self = .googleDriveAuthURL(try container.decode(RuntimeGoogleDriveAuthURLEnvelope.self, forKey: .payload))
        case RuntimeSocketEvent.logEntry.rawValue:
            self = .logEntry(try container.decode(RuntimeLogEntryEnvelope.self, forKey: .payload))
        default:
            throw DecodingError.dataCorruptedError(forKey: .event, in: container, debugDescription: "Unsupported runtime event")
        }
    }

    private enum CodingKeys: String, CodingKey {
        case event
        case payload
    }
}

public struct RuntimeTransportEnvelope: Codable, Equatable {
    public let event: String
    public let payload: RuntimeEventMessage

    public init(event: String, payload: RuntimeEventMessage) {
        self.event = event
        self.payload = payload
    }
}

public enum RuntimeEventEncoder {
    public static func encode(_ message: RuntimeEventMessage) -> RuntimeTransportEnvelope {
        RuntimeTransportEnvelope(event: message.event.rawValue, payload: message)
    }

    public static func encodeJSON(_ message: RuntimeEventMessage) throws -> Data {
        try JSONEncoder().encode(encode(message))
    }

    public static func decodeJSON(_ data: Data) throws -> RuntimeTransportEnvelope {
        try JSONDecoder().decode(RuntimeTransportEnvelope.self, from: data)
    }
}
