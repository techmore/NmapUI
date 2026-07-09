import Foundation
import ServiceManagement

struct RuntimeSettings: Codable, Equatable {
    static let schemaVersion = 1

    var schemaVersion: Int
    var useDefaultRuntimeCommand: Bool
    var runtimeExecutable: String
    var runtimeArguments: String
    var dataDirectoryPath: String
    var launchAtLoginEnabled: Bool

    init(
        schemaVersion: Int = RuntimeSettings.schemaVersion,
        useDefaultRuntimeCommand: Bool,
        runtimeExecutable: String,
        runtimeArguments: String,
        dataDirectoryPath: String,
        launchAtLoginEnabled: Bool
    ) {
        self.schemaVersion = schemaVersion
        self.useDefaultRuntimeCommand = useDefaultRuntimeCommand
        self.runtimeExecutable = runtimeExecutable
        self.runtimeArguments = runtimeArguments
        self.dataDirectoryPath = dataDirectoryPath
        self.launchAtLoginEnabled = launchAtLoginEnabled
    }

    static func current() -> RuntimeSettings {
        RuntimeSettingsStore.current()
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? RuntimeSettings.schemaVersion
        useDefaultRuntimeCommand = try container.decode(Bool.self, forKey: .useDefaultRuntimeCommand)
        runtimeExecutable = try container.decode(String.self, forKey: .runtimeExecutable)
        runtimeArguments = try container.decode(String.self, forKey: .runtimeArguments)
        dataDirectoryPath = try container.decode(String.self, forKey: .dataDirectoryPath)
        launchAtLoginEnabled = try container.decode(Bool.self, forKey: .launchAtLoginEnabled)
    }

    static func parseRuntimeCommand(_ command: String) -> (executable: String?, arguments: [String]) {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return (nil, [])
        }

        var parts: [String] = []
        var current = ""
        var quote: Character?
        var escaping = false

        for character in trimmed {
            if escaping {
                current.append(character)
                escaping = false
                continue
            }
            if character == "\\" {
                escaping = true
                continue
            }
            if let activeQuote = quote, character == activeQuote {
                quote = nil
                continue
            }
            if quote == nil && (character == "\"" || character == "'") {
                quote = character
                continue
            }
            if quote == nil && character.isWhitespace {
                appendIfNeeded(current: &current, parts: &parts)
                continue
            }
            current.append(character)
        }

        appendIfNeeded(current: &current, parts: &parts)
        guard let executable = parts.first, !executable.isEmpty else {
            return (nil, [])
        }
        return (executable, Array(parts.dropFirst()))
    }

    static func parseArgumentList(_ arguments: String) -> [String] {
        parseRuntimeCommand("placeholder \(arguments)").arguments
    }

    static func appendIfNeeded(current: inout String, parts: inout [String]) {
        guard !current.isEmpty else { return }
        parts.append(current)
        current.removeAll(keepingCapacity: true)
    }

    static func defaultDataDirectoryPath() -> String {
        let fileManager = FileManager.default
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
        return appSupport.appendingPathComponent("NmapUI", isDirectory: true).path
    }

    static func isLaunchAtLoginEnabled() -> Bool {
        guard #available(macOS 13.0, *) else { return false }
        return SMAppService.mainApp.status == .enabled
    }
}

enum RuntimeSettingsStore {
    private static let fileName = "runtime-settings.json"

    static func current() -> RuntimeSettings {
        let dataDirectoryURL = currentDataDirectoryURL()
        if let loaded = load(from: dataDirectoryURL) {
            let normalized = normalize(loaded)
            if normalized != loaded {
                persist(normalized, to: dataDirectoryURL)
            }
            return normalized
        }

        let defaults = UserDefaults.standard
        let environment = ProcessInfo.processInfo.environment
        let useDefaultRuntimeCommand = defaults.object(forKey: PreferencesKeys.useDefaultRuntimeCommand) as? Bool ?? true
        let runtimeExecutable: String
        let runtimeArguments: String
        if useDefaultRuntimeCommand {
            runtimeExecutable = "/usr/bin/true"
            runtimeArguments = ""
        } else if let persistedExecutable = defaults.string(forKey: PreferencesKeys.runtimeExecutable), !persistedExecutable.isEmpty {
            runtimeExecutable = persistedExecutable
            runtimeArguments = defaults.string(forKey: PreferencesKeys.runtimeArguments) ?? ""
        } else if let legacyCommand = defaults.string(forKey: PreferencesKeys.runtimeCommand), !legacyCommand.isEmpty {
            let legacySpec = RuntimeSettings.parseRuntimeCommand(legacyCommand)
            runtimeExecutable = legacySpec.executable ?? "/usr/bin/true"
            runtimeArguments = legacySpec.arguments.joined(separator: " ")
        } else {
            runtimeExecutable = environment["NMAPUI_RUNTIME_EXECUTABLE"] ?? "/usr/bin/true"
            runtimeArguments = environment["NMAPUI_RUNTIME_ARGUMENTS"] ?? ""
        }
        let dataDirectoryPath = defaults.string(forKey: PreferencesKeys.dataDirectory)
            ?? environment["NMAPUI_DATA_DIR"]
            ?? RuntimeSettings.defaultDataDirectoryPath()
        let settings = RuntimeSettings(
            useDefaultRuntimeCommand: useDefaultRuntimeCommand,
            runtimeExecutable: runtimeExecutable,
            runtimeArguments: runtimeArguments,
            dataDirectoryPath: dataDirectoryPath,
            launchAtLoginEnabled: RuntimeSettings.isLaunchAtLoginEnabled()
        )
        let normalized = normalize(settings)
        persist(normalized, to: dataDirectoryURL)
        return normalized
    }

    static func load(from directoryURL: URL) -> RuntimeSettings? {
        let fileURL = directoryURL.appendingPathComponent(fileName)
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        guard let decoded = try? JSONDecoder().decode(RuntimeSettings.self, from: data) else { return nil }
        return normalize(decoded)
    }

    static func currentDataDirectoryURL() -> URL {
        if let persistedDataDir = UserDefaults.standard.string(forKey: PreferencesKeys.dataDirectory), !persistedDataDir.isEmpty {
            return URL(fileURLWithPath: persistedDataDir)
        }
        if let envDataDir = ProcessInfo.processInfo.environment["NMAPUI_DATA_DIR"], !envDataDir.isEmpty {
            return URL(fileURLWithPath: envDataDir)
        }
        return URL(fileURLWithPath: RuntimeSettings.defaultDataDirectoryPath())
    }

    static func currentRuntimeWorkDirectoryURL() -> URL {
        if let envWorkDir = ProcessInfo.processInfo.environment["NMAPUI_RUNTIME_WORKDIR"], !envWorkDir.isEmpty {
            return URL(fileURLWithPath: envWorkDir)
        }
        // Keep scan artifacts under Application Support (user-owned), never the repo root.
        return currentDataDirectoryURL().appendingPathComponent("work", isDirectory: true)
    }

    static func persist(_ settings: RuntimeSettings, to directoryURL: URL) {
        let fileURL = directoryURL.appendingPathComponent(fileName)
        guard let data = try? JSONEncoder().encode(settings) else { return }
        try? FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        try? data.write(to: fileURL, options: [.atomic])
    }

    static func normalize(_ settings: RuntimeSettings) -> RuntimeSettings {
        let trimmedExecutable = settings.runtimeExecutable.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedArguments = settings.runtimeArguments.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedExecutable == "node"
            || trimmedExecutable.hasSuffix("/node")
            || trimmedExecutable.isEmpty
            || trimmedArguments.contains("server.js")
        {
            return RuntimeSettings(
                schemaVersion: settings.schemaVersion,
                useDefaultRuntimeCommand: true,
                runtimeExecutable: "/usr/bin/true",
                runtimeArguments: "",
                dataDirectoryPath: settings.dataDirectoryPath,
                launchAtLoginEnabled: settings.launchAtLoginEnabled
            )
        }
        return settings
    }
}
