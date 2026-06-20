import Foundation
import SwiftUI

@MainActor
final class AppSessionState: ObservableObject {
    @Published var runtimeIsReady = false
    @Published var runtimeStatusText = "Starting..."
    @Published var startupHint = "Preparing native shell..."
    @Published var preloadMessage = "Loading dashboard..."
    @Published var showLoadingStrip = true
}
