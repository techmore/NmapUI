import Foundation
import RuntimeContracts

extension RuntimeScanStartPayload {
    func makeScanCoordinatorRequest(event: RuntimeClientRequest) -> ScanCoordinator.ScanRequest {
        let usePn = event == .startCompleteScan
        let scanKind: ScanCoordinator.ScanKind = event == .startCompleteScan ? .complete : (event == .startDragnetScan ? .dragnet : .quick)
        return ScanCoordinator.ScanRequest(
            target: target,
            usePn: usePn,
            vpnHelper: vpnHelper ?? false,
            scanKind: scanKind,
            allowInteractivePrivilegePrompt: true
        )
    }
}
