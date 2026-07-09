import Foundation

public enum RuntimeClientRequest: String, Codable, CaseIterable {
    case getInitialData = "get_initial_data"
    case startQuickScan = "start_quick_scan"
    case startCompleteScan = "start_complete_scan"
    case startDragnetScan = "start_dragnet_scan"
    case stopScan = "stop_scan"
    case enableAutoScan = "enable_auto_scan"
    case disableAutoScan = "disable_auto_scan"
    case getHistory = "get_history"
    case getCustomerProfile = "get_customer_profile"
    case getGoogleDriveStatus = "get_google_drive_status"
    case saveGoogleDriveCredentials = "save_google_drive_credentials"
    case connectGoogleDrive = "connect_google_drive"
    case disconnectGoogleDrive = "disconnect_google_drive"
    case saveGoogleDriveSettings = "save_google_drive_settings"
    case setCustomerProfilePrefix = "set_customer_profile_prefix"
    case getReports = "get_reports"
    case getPrivilegeHelperStatus = "get_privilege_helper_status"
    case installPrivilegeHelper = "install_privilege_helper"
    case openReport = "open_report"
    case saveAppSettings = "save_app_settings"
}

public struct RuntimeGoogleDriveCredentialsPayload: Codable, Equatable {
    public let credentialsJson: String

    public init(credentialsJson: String) {
        self.credentialsJson = credentialsJson
    }
}

public struct RuntimeAutoScanRequestPayload: Codable, Equatable {
    public let recurrence: String?
    public let startTime: String?
    public let target: String?

    public init(recurrence: String? = nil, startTime: String? = nil, target: String? = nil) {
        self.recurrence = recurrence
        self.startTime = startTime
        self.target = target
    }
}

public struct RuntimeGoogleDriveSettingsPayload: Codable, Equatable {
    public let enabled: Bool
    public let folderId: String?

    public init(enabled: Bool, folderId: String? = nil) {
        self.enabled = enabled
        self.folderId = folderId
    }
}

public struct RuntimeCustomerProfilePrefixPayload: Codable, Equatable {
    public let prefix: String

    public init(prefix: String) {
        self.prefix = prefix
    }
}

public struct RuntimeScanStartPayload: Codable, Equatable {
    public let target: String
    public let customerProfilePrefix: String?
    public let vpnHelper: Bool?

    public init(target: String, customerProfilePrefix: String? = nil, vpnHelper: Bool? = nil) {
        self.target = target
        self.customerProfilePrefix = customerProfilePrefix
        self.vpnHelper = vpnHelper
    }
}

public struct RuntimeClientRequestEnvelope: Codable, Equatable {
    public let event: RuntimeClientRequest
    public let payload: [String: RuntimeJSONValue]

    public init(event: RuntimeClientRequest, payload: [String: RuntimeJSONValue] = [:]) {
        self.event = event
        self.payload = payload
    }
}

public struct RuntimeRequestDispatchResult: Equatable {
    public let events: [RuntimeEventMessage]
    public let scanRequest: RuntimeScanStartPayload?

    public init(events: [RuntimeEventMessage] = [], scanRequest: RuntimeScanStartPayload? = nil) {
        self.events = events
        self.scanRequest = scanRequest
    }
}
