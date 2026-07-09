import Foundation
import RuntimeContracts

@MainActor
final class RuntimeLifecycleEventBridge {
    private let transport: RuntimeEventTransporting
    private let eventPublisher: (String, String) -> Void

    init(transport: RuntimeEventTransporting, eventPublisher: @escaping (String, String) -> Void = { _, _ in }) {
        self.transport = transport
        self.eventPublisher = eventPublisher
    }

    func encodeReportsRefresh() throws -> Data {
        let message = RuntimeEventMessage.reportsRefresh(RuntimeReportsDataEnvelope(reports: []))
        let data = try transport.send(message)
        eventPublisher(message.event.rawValue, String(data: data, encoding: .utf8) ?? "{}")
        return data
    }

    func encodeScanComplete(
        phase: Int,
        duration: String,
        hostCount: Int? = nil,
        openPortCount: Int? = nil,
        criticalCVECount: Int? = nil,
        lowCVECount: Int? = nil,
        screenshotCount: Int? = nil,
        status: String? = nil
    ) throws -> Data {
        let message = RuntimeEventMessage.scanComplete(RuntimePhaseCompleteEnvelope(
            phase: phase,
            duration: duration,
            hostCount: hostCount,
            openPortCount: openPortCount,
            criticalCVECount: criticalCVECount,
            lowCVECount: lowCVECount,
            screenshotCount: screenshotCount,
            status: status
        ))
        let data = try transport.send(message)
        eventPublisher(message.event.rawValue, String(data: data, encoding: .utf8) ?? "{}")
        return data
    }
}
