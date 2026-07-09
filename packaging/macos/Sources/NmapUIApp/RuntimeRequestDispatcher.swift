import Foundation
import RuntimeContracts

@MainActor
protocol RuntimeRequestDispatching {
    func dispatch(
        _ request: RuntimeClientRequestEnvelope,
        dataDirectory: URL,
        version: String
    ) -> RuntimeRequestDispatchResult
}

@MainActor
final class RuntimeRequestDispatcher: RuntimeRequestDispatching {
    private let sessionState: AppSessionState

    init(sessionState: AppSessionState) {
        self.sessionState = sessionState
    }

    func dispatch(
        _ request: RuntimeClientRequestEnvelope,
        dataDirectory: URL,
        version: String
    ) -> RuntimeRequestDispatchResult {
        switch request.event {
        case .getInitialData:
            return RuntimeRequestDispatchResult(events: initialDataMessages())
        case .startQuickScan, .startCompleteScan, .startDragnetScan:
            return RuntimeRequestDispatchResult(scanRequest: scanStartPayload(from: request))
        case .getHistory:
            if let history = sessionState.runtimeHistoryDataEnvelope() {
                return RuntimeRequestDispatchResult(events: [.historyData(history)])
            }
            return RuntimeRequestDispatchResult()
        case .getReports:
            if let reports = sessionState.runtimeReportsDataEnvelope() {
                return RuntimeRequestDispatchResult(events: [.reportsData(reports)])
            }
            return RuntimeRequestDispatchResult()
        case .getCustomerProfile:
            if let profile = sessionState.runtimeCustomerProfileSnapshot.profile {
                return RuntimeRequestDispatchResult(events: [.customerProfile(profile)])
            }
            return RuntimeRequestDispatchResult()
        case .getGoogleDriveStatus:
            sessionState.refreshGoogleDriveSnapshot(from: dataDirectory)
            if let googleDrive = sessionState.runtimeGoogleDriveStatusEnvelope() {
                return RuntimeRequestDispatchResult(events: [.googleDriveStatus(googleDrive)])
            }
            return RuntimeRequestDispatchResult()
        case .enableAutoScan:
            let recurrence = stringValue("recurrence", from: request.payload) ?? sessionState.runtimeAutoScanSnapshot.recurrence
            let startTime = stringValue("startTime", from: request.payload) ?? sessionState.runtimeAutoScanSnapshot.startTime
            let target = stringValue("target", from: request.payload) ?? sessionState.runtimeAutoScanSnapshot.target
            sessionState.updateAutoScanConfig(
                enabled: true,
                recurrence: recurrence,
                startTime: startTime,
                target: target,
                dataDirectory: dataDirectory
            )
            // Install privileged helper (interactive once) then schedule unattended runs.
            Task { @MainActor in
                do {
                    try PrivilegeElevationController.ensurePrivilegedHelperReady(interactive: true)
                    AutoScanScheduler.sync(enabled: true, recurrence: recurrence, startTime: startTime)
                } catch {
                    PrivilegeElevationController.presentHelperInstallFailure(error)
                    // Keep config enabled in UI, but unattended runs need the helper.
                    RuntimeDiagnosticsLogger.error("Auto-scan schedule deferred until helper is installed")
                }
            }
            if let autoScan = sessionState.runtimeAutoScanConfigEnvelope() {
                return RuntimeRequestDispatchResult(events: [.autoScanConfig(autoScan)])
            }
            return RuntimeRequestDispatchResult()
        case .disableAutoScan:
            sessionState.updateAutoScanConfig(
                enabled: false,
                recurrence: sessionState.runtimeAutoScanSnapshot.recurrence,
                startTime: sessionState.runtimeAutoScanSnapshot.startTime,
                target: sessionState.runtimeAutoScanSnapshot.target,
                dataDirectory: dataDirectory
            )
            AutoScanScheduler.sync(enabled: false, recurrence: sessionState.runtimeAutoScanSnapshot.recurrence, startTime: sessionState.runtimeAutoScanSnapshot.startTime)
            if let autoScan = sessionState.runtimeAutoScanConfigEnvelope() {
                return RuntimeRequestDispatchResult(events: [.autoScanConfig(autoScan)])
            }
            return RuntimeRequestDispatchResult()
        case .saveGoogleDriveSettings:
            sessionState.updateGoogleDriveSettings(
                enabled: boolValue("enabled", from: request.payload) ?? sessionState.runtimeGoogleDriveSnapshot.enabled,
                folderId: stringValue("folderId", from: request.payload) ?? sessionState.runtimeGoogleDriveSnapshot.folderId,
                dataDirectory: dataDirectory
            )
            if let googleDrive = sessionState.runtimeGoogleDriveStatusEnvelope() {
                return RuntimeRequestDispatchResult(events: [.googleDriveStatus(googleDrive)])
            }
            return RuntimeRequestDispatchResult()
        case .setCustomerProfilePrefix:
            sessionState.updateCustomerProfilePrefix(
                stringValue("prefix", from: request.payload) ?? "CSP",
                networkState: sessionState.runtimeNetworkState,
                dataDirectory: dataDirectory
            )
            if let profile = sessionState.runtimeCustomerProfileSnapshot.profile {
                return RuntimeRequestDispatchResult(events: [.customerProfile(profile)])
            }
            return RuntimeRequestDispatchResult()
        case .stopScan:
            return RuntimeRequestDispatchResult(events: [.scanStopped(RuntimeScanStoppedEnvelope())])
        case .getPrivilegeHelperStatus, .installPrivilegeHelper, .openReport:
            // Handled by the native shell bridge (AppDelegate) for interactive privilege/report actions.
            return RuntimeRequestDispatchResult()
        case .saveGoogleDriveCredentials:
            let credentials = googleDriveCredentialsPayload(from: request)
            RuntimeMetadataStore.persistGoogleDriveCredentials(credentials.credentialsJson, to: dataDirectory)
            if let googleDrive = sessionState.runtimeGoogleDriveStatusEnvelope() {
                return RuntimeRequestDispatchResult(events: [.googleDriveStatus(googleDrive)])
            }
            return RuntimeRequestDispatchResult(events: [.googleDriveStatus(RuntimeGoogleDriveStatusEnvelope(
                success: true,
                status: "Google Drive credentials saved",
                config: ["enabled": .bool(sessionState.runtimeGoogleDriveSnapshot.enabled)]
            ))])
        case .connectGoogleDrive:
            return RuntimeRequestDispatchResult(events: [.googleDriveAuthURL(RuntimeGoogleDriveAuthURLEnvelope(
                success: true,
                url: RuntimeEndpoints.googleDriveOAuthCallbackURL().absoluteString,
                status: "Google Drive auth URL ready"
            ))])
        case .disconnectGoogleDrive:
            if let googleDrive = sessionState.runtimeGoogleDriveStatusEnvelope() {
                return RuntimeRequestDispatchResult(events: [.googleDriveStatus(googleDrive)])
            }
            return RuntimeRequestDispatchResult()
        }
    }

    func scanStartPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeScanStartPayload {
        RuntimeScanStartPayload(
            target: stringValue("target", from: request.payload) ?? "",
            customerProfilePrefix: stringValue("customerProfilePrefix", from: request.payload),
            vpnHelper: boolValue("vpnHelper", from: request.payload)
        )
    }

    func scanCoordinatorRequest(from request: RuntimeClientRequestEnvelope) -> ScanCoordinator.ScanRequest? {
        guard [.startQuickScan, .startCompleteScan, .startDragnetScan].contains(request.event) else {
            return nil
        }
        return scanStartPayload(from: request).makeScanCoordinatorRequest(event: request.event)
    }

    func autoScanPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeAutoScanRequestPayload {
        RuntimeAutoScanRequestPayload(
            recurrence: stringValue("recurrence", from: request.payload),
            startTime: stringValue("startTime", from: request.payload),
            target: stringValue("target", from: request.payload)
        )
    }

    func googleDriveSettingsPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeGoogleDriveSettingsPayload {
        RuntimeGoogleDriveSettingsPayload(
            enabled: boolValue("enabled", from: request.payload) ?? false,
            folderId: stringValue("folderId", from: request.payload)
        )
    }

    func customerProfilePrefixPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeCustomerProfilePrefixPayload {
        RuntimeCustomerProfilePrefixPayload(
            prefix: stringValue("prefix", from: request.payload) ?? "CSP"
        )
    }

    func googleDriveCredentialsPayload(from request: RuntimeClientRequestEnvelope) -> RuntimeGoogleDriveCredentialsPayload {
        RuntimeGoogleDriveCredentialsPayload(
            credentialsJson: stringValue("credentialsJson", from: request.payload) ?? "{}"
        )
    }

    private func initialDataMessages() -> [RuntimeEventMessage] {
        guard let bootstrap = sessionState.runtimeInitialDataEnvelope() else { return [] }
        return [.initialData(bootstrap)]
    }

    private func stringValue(_ key: String, from payload: [String: RuntimeJSONValue]) -> String? {
        guard case .string(let value)? = payload[key] else { return nil }
        return value
    }

    private func boolValue(_ key: String, from payload: [String: RuntimeJSONValue]) -> Bool? {
        guard case .bool(let value)? = payload[key] else { return nil }
        return value
    }
}
