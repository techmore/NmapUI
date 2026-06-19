import Foundation

@MainActor
final class PreferencesController {
    private let preferencesStore: PreferencesStore

    init(preferencesStore: PreferencesStore) {
        self.preferencesStore = preferencesStore
    }

    func savePreferences() {
        preferencesStore.save()
    }

    func resetPreferences() {
        preferencesStore.clearPersistedValues()
        preferencesStore.resetToDefaults()
    }
}
