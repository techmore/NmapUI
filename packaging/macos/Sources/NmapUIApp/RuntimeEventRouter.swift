import Foundation
import RuntimeContracts

@MainActor
protocol RuntimeEventRouting {
    func emit(_ message: RuntimeEventMessage)
}

@MainActor
extension RuntimeEventRouting {
    func transportEnvelope(for message: RuntimeEventMessage) -> RuntimeTransportEnvelope {
        RuntimeEventEncoder.encode(message)
    }
}

@MainActor
extension RuntimeEventRouting {
    func emitScanLifecycle(phase: Int, target: String, startTime: String?, scanKind: String) {
        emit(.scanLifecycle(RuntimeScanLifecycleEnvelope(
            phase: phase,
            target: target,
            startTime: startTime,
            scanKind: scanKind
        )))
    }

    func emitPhaseComplete(
        phase: Int,
        duration: String,
        hostCount: Int? = nil,
        openPortCount: Int? = nil,
        criticalCVECount: Int? = nil,
        lowCVECount: Int? = nil,
        screenshotCount: Int? = nil,
        status: String? = nil
    ) {
        emit(.phaseComplete(RuntimePhaseCompleteEnvelope(
            phase: phase,
            duration: duration,
            hostCount: hostCount,
            openPortCount: openPortCount,
            criticalCVECount: criticalCVECount,
            lowCVECount: lowCVECount,
            screenshotCount: screenshotCount,
            status: status
        )))
    }

    func emitPhaseStats(phase: Int, summary: RuntimeNmapXMLSummary) {
        emit(.phaseStats(RuntimePhaseStatsEnvelope(phase: phase, summary: summary)))
    }

    func emitDiscoveryUpdate(ip: String, status: String, hostname: String? = nil, vendor: String? = nil) {
        emit(.discoveryUpdate(RuntimeDiscoveryUpdateEnvelope(ip: ip, status: status, hostname: hostname, vendor: vendor)))
    }

    func emitTracerouteHop(hop: Int, ip: String) {
        emit(.tracerouteHop(RuntimeTracerouteHopEnvelope(hop: hop, ip: ip)))
    }

    func emitReportReady(reportUrl: String, pdfUrl: String?, xmlUrl: String?, customerProfile: RuntimeCustomerProfile) {
        emit(.reportReady(RuntimeReportReadyEnvelope(
            reportUrl: reportUrl,
            pdfUrl: pdfUrl,
            xmlUrl: xmlUrl,
            customerProfile: customerProfile
        )))
    }

    func emitScanComplete(
        phase: Int,
        duration: String,
        hostCount: Int? = nil,
        openPortCount: Int? = nil,
        criticalCVECount: Int? = nil,
        lowCVECount: Int? = nil,
        screenshotCount: Int? = nil,
        status: String? = nil
    ) {
        emit(.scanComplete(RuntimePhaseCompleteEnvelope(
            phase: phase,
            duration: duration,
            hostCount: hostCount,
            openPortCount: openPortCount,
            criticalCVECount: criticalCVECount,
            lowCVECount: lowCVECount,
            screenshotCount: screenshotCount,
            status: status
        )))
    }

    func emitInitialData(
        network: RuntimeNetworkSnapshot,
        publicIP: String,
        customerProfile: RuntimeCustomerProfile,
        googleDrive: [String: RuntimeJSONValue],
        autoScan: [String: RuntimeJSONValue]
    ) {
        emit(.initialData(RuntimeInitialDataEnvelope(
            network: network,
            publicIP: publicIP,
            customerProfile: customerProfile,
            googleDrive: googleDrive,
            autoScan: autoScan
        )))
    }

    func emitGoogleDriveStatus(success: Bool, status: String, config: [String: RuntimeJSONValue]) {
        emit(.googleDriveStatus(RuntimeGoogleDriveStatusEnvelope(success: success, status: status, config: config)))
    }

    func emitHistoryData(_ history: [RuntimeReportHistoryEntry]) {
        emit(.historyData(RuntimeHistoryDataEnvelope(history: history)))
    }

    func emitReportsData(_ reports: [RuntimeReportListEntry]) {
        emit(.reportsData(RuntimeReportsDataEnvelope(reports: reports)))
    }

    func emitReportsRefresh() {
        emit(.reportsRefresh(RuntimeReportsDataEnvelope(reports: [])))
    }

    func emitAutoScanConfig(enabled: Bool, schedule: String, scheduleLabel: String?, config: [String: RuntimeJSONValue]) {
        emit(.autoScanConfig(RuntimeAutoScanConfigEnvelope(
            enabled: enabled,
            schedule: schedule,
            scheduleLabel: scheduleLabel,
            config: config
        )))
    }

    func emitGoogleDriveAuthURL(success: Bool, url: String?, status: String) {
        emit(.googleDriveAuthURL(RuntimeGoogleDriveAuthURLEnvelope(success: success, url: url, status: status)))
    }

    func emitLogEntry(level: String, message: String, timestamp: String? = nil) {
        emit(.logEntry(RuntimeLogEntryEnvelope(level: level, message: message, timestamp: timestamp)))
    }
}

@MainActor
final class RuntimeEventRouter: RuntimeEventRouting {
    private let emitHandler: (RuntimeEventMessage) -> Void

    init(emitHandler: @escaping (RuntimeEventMessage) -> Void = { _ in }) {
        self.emitHandler = emitHandler
    }

    func emit(_ message: RuntimeEventMessage) {
        emitHandler(message)
    }
}

@MainActor
final class RuntimeEventRecorder: RuntimeEventRouting {
    private(set) var messages: [RuntimeEventMessage] = []

    func emit(_ message: RuntimeEventMessage) {
        messages.append(message)
    }
}
