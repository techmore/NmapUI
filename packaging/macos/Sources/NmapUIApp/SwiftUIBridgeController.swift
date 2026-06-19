import Foundation

@MainActor
final class SwiftUIBridgeController {
    private let openDataDirectory: () -> Void
    private let savePreferences: () -> Void
    private let resetPreferences: () -> Void

    init(
        openDataDirectory: @escaping () -> Void,
        savePreferences: @escaping () -> Void,
        resetPreferences: @escaping () -> Void
    ) {
        self.openDataDirectory = openDataDirectory
        self.savePreferences = savePreferences
        self.resetPreferences = resetPreferences
    }

    func openDataDirectoryFromSwiftUI() {
        openDataDirectory()
    }

    func savePreferencesFromSwiftUI() {
        savePreferences()
    }

    func resetPreferencesFromSwiftUI() {
        resetPreferences()
    }
}
