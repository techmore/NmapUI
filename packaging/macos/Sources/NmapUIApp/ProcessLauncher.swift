import Foundation
import ServiceManagement

final class ProcessLauncher {
    private let launcherExecutableURL: URL
    private let runtimeExecutable: String
    private let runtimeArguments: [String]
    private let runtimeWorkDir: URL
    private let runtimeDataDir: URL

    init(
        launcherExecutableURL: URL = URL(fileURLWithPath: "/usr/bin/env"),
        settings: RuntimeSettings = RuntimeSettingsStore.load(from: RuntimeSettingsStore.currentDataDirectoryURL())
            ?? RuntimeSettingsStore.current(),
        runtimeWorkDir: URL = RuntimeSettingsStore.currentRuntimeWorkDirectoryURL()
    ) {
        self.launcherExecutableURL = launcherExecutableURL
        self.runtimeExecutable = settings.useDefaultRuntimeCommand ? "/usr/bin/true" : settings.runtimeExecutable
        self.runtimeArguments = settings.useDefaultRuntimeCommand ? [] : RuntimeSettings.parseArgumentList(settings.runtimeArguments)
        self.runtimeDataDir = URL(fileURLWithPath: settings.dataDirectoryPath)
        self.runtimeWorkDir = runtimeWorkDir
    }

    func launchRuntimeIfNeeded() -> Process? {
        let process = Process()
        process.currentDirectoryURL = runtimeWorkDir
        process.executableURL = launcherExecutableURL
        process.arguments = [runtimeExecutable] + runtimeArguments

        process.environment = Self.runtimeEnvironment(
            workDirectory: runtimeWorkDir,
            dataDirectory: runtimeDataDir
        )

        do {
            try process.run()
            return process
        } catch {
            NSLog("Failed to launch runtime: \(error.localizedDescription)")
            return nil
        }
    }

    func stop(runtimeProcess: Process?) {
        guard let runtimeProcess else { return }
        if runtimeProcess.isRunning {
            runtimeProcess.terminate()
        }
    }

    static func isLaunchAtLoginEnabled() -> Bool {
        guard #available(macOS 13.0, *) else { return false }
        return SMAppService.mainApp.status == .enabled
    }

    static func runtimeEnvironment(workDirectory: URL, dataDirectory: URL) -> [String: String] {
        [
            "HOST": RuntimeEndpoints.host,
            "PORT": RuntimeEndpoints.fixedPortString,
            "NMAPUI_PORT": RuntimeEndpoints.fixedPortString,
            "NMAPUI_SWIFT_MANAGED": "1",
            "NMAPUI_RUNTIME_WORKDIR": workDirectory.path,
            "NMAPUI_DATA_DIR": dataDirectory.path,
            "PATH": ProcessInfo.processInfo.environment["PATH"] ?? ""
        ]
    }
}
