import Foundation
import RuntimeContracts

extension RuntimeScanStats {
    static func make(from summary: RuntimeNmapXMLSummary) -> RuntimeScanStats {
        RuntimeScanStats(
            hostCount: summary.hostCount,
            openPortCount: summary.openPortCount,
            criticalCVECount: summary.criticalCVECount,
            lowCVECount: summary.lowCVECount
        )
    }
}
