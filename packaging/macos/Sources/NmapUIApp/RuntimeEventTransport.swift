import Foundation
import RuntimeContracts

@MainActor
protocol RuntimeEventTransporting {
    func send(_ message: RuntimeEventMessage) throws -> Data
}

@MainActor
struct RuntimeJSONEventTransport: RuntimeEventTransporting {
    func send(_ message: RuntimeEventMessage) throws -> Data {
        try RuntimeEventEncoder.encodeJSON(message)
    }
}

@MainActor
final class RuntimeEventTransportRecorder: RuntimeEventTransporting {
    private(set) var sentMessages: [RuntimeEventMessage] = []

    func send(_ message: RuntimeEventMessage) throws -> Data {
        sentMessages.append(message)
        return try RuntimeEventEncoder.encodeJSON(message)
    }
}
