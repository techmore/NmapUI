import Cocoa
import Darwin

class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var runtimePort = 9000
    var statusItem: NSStatusItem!
    var pythonProcess: Process?
    var statusPollTimer: Timer?
    var hadActiveJob = false
    var completedIndicatorUntil: Date?

    var appURL: URL {
        URL(string: "http://127.0.0.1:\(runtimePort)")!
    }

    var runtimeStatusURL: URL {
        URL(string: "http://127.0.0.1:\(runtimePort)/api/runtime/status")!
    }

    // Menu items that need dynamic state updates
    var openItem: NSMenuItem!
    var startItem: NSMenuItem!
    var stopItem: NSMenuItem!
    var restartItem: NSMenuItem!

    var isFlaskRunning: Bool {
        pythonProcess?.isRunning == true
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        startFlask()
    }

    func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        updateStatusIcon(state: .starting, detail: "Starting NmapUI")

        let menu = NSMenu()
        menu.delegate = self

        openItem = NSMenuItem(title: "Open NmapUI", action: #selector(openNmapUI(_:)), keyEquivalent: "o")
        openItem.target = self
        menu.addItem(openItem)

        menu.addItem(NSMenuItem.separator())

        startItem = NSMenuItem(title: "Start Flask", action: #selector(startNmapUI(_:)), keyEquivalent: "s")
        startItem.target = self
        menu.addItem(startItem)

        stopItem = NSMenuItem(title: "Stop Flask", action: #selector(stopNmapUI(_:)), keyEquivalent: "")
        stopItem.target = self
        menu.addItem(stopItem)

        restartItem = NSMenuItem(title: "Restart Flask", action: #selector(restartNmapUI(_:)), keyEquivalent: "r")
        restartItem.target = self
        menu.addItem(restartItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quitApp(_:)), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        let uninstallItem = NSMenuItem(title: "Uninstall", action: #selector(uninstallApp(_:)), keyEquivalent: "u")
        uninstallItem.target = self
        menu.addItem(uninstallItem)

        statusItem.menu = menu
    }

    // Update menu item enabled states each time the menu opens
    func menuWillOpen(_ menu: NSMenu) {
        let running = isFlaskRunning
        openItem.isEnabled = true          // always available; will start+wait if needed
        startItem.isEnabled = !running
        stopItem.isEnabled = running
        restartItem.isEnabled = true
    }

    // MARK: - Flask lifecycle

    func isLocalPortInUse(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { close(fd) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.stride)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        let convertResult = withUnsafeMutablePointer(to: &address.sin_addr) {
            inet_pton(AF_INET, "127.0.0.1", $0)
        }
        guard convertResult == 1 else { return true }

        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }
        return result == 0
    }

    func pickAvailableRuntimePort(startingAt startPort: Int = 9000, attempts: Int = 20) -> Int? {
        for candidate in startPort..<(startPort + attempts) {
            if !isLocalPortInUse(candidate) {
                return candidate
            }
        }
        return nil
    }

    func startFlask() {
        guard !isFlaskRunning else { return }

        guard let bundleNS = Bundle.main.bundlePath as NSString? else { return }
        let resourcesPath = bundleNS.appendingPathComponent("Contents/Resources")
        let runScriptPath = (resourcesPath as NSString).appendingPathComponent("run.sh")

        guard FileManager.default.fileExists(atPath: runScriptPath) else {
            print("run.sh not found inside bundle — rebuild with build.sh")
            return
        }

        guard let selectedPort = pickAvailableRuntimePort() else {
            updateStatusIcon(state: .error, detail: "No local runtime port available")
            return
        }
        runtimePort = selectedPort

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [runScriptPath]
        process.currentDirectoryURL = URL(fileURLWithPath: resourcesPath, isDirectory: true)
        var environment = ProcessInfo.processInfo.environment
        environment["NMAPUI_PORT"] = String(runtimePort)
        environment["NMAPUI_ALLOWED_ORIGINS"] = "http://127.0.0.1:\(runtimePort),http://localhost:\(runtimePort)"
        process.environment = environment

        do {
            try process.run()
            pythonProcess = process
            startStatusPolling()
            updateStatusIcon(state: .starting, detail: "Starting NmapUI")
            print("NmapUI started with PID: \(process.processIdentifier)")
        } catch {
            print("Failed to start NmapUI: \(error)")
            updateStatusIcon(state: .error, detail: "Failed to start NmapUI")
        }
    }

    // Kill the tracked process and any stray app.py processes (e.g. from a
    // previous run or if pythonProcess is stale after a crash/restart).
    func stopFlask(wait: Bool = true) {
        stopStatusPolling()
        if let process = pythonProcess, process.isRunning {
            process.terminate()
            if wait { process.waitUntilExit() }
        }
        pythonProcess = nil

        // Belt-and-suspenders: kill any app.py that may still be alive
        let pkill = Process()
        pkill.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        pkill.arguments = ["-f", "app.py"]
        try? pkill.run()
        if wait { pkill.waitUntilExit() }

        print("NmapUI stopped")
        updateStatusIcon(state: .idle, detail: "NmapUI stopped")
    }

    // Poll the selected localhost port until Flask responds (or timeout), then open browser
    func waitForFlaskThenOpen(timeout: TimeInterval = 15) {
        DispatchQueue.global(qos: .userInitiated).async {
            let deadline = Date().addingTimeInterval(timeout)
            var ready = false
            while Date() < deadline {
                var request = URLRequest(url: self.appURL)
                request.timeoutInterval = 1
                let sema = DispatchSemaphore(value: 0)
                URLSession.shared.dataTask(with: request) { _, response, _ in
                    if let http = response as? HTTPURLResponse, http.statusCode < 500 {
                        ready = true
                    }
                    sema.signal()
                }.resume()
                sema.wait()
                if ready { break }
                Thread.sleep(forTimeInterval: 0.5)
            }
            DispatchQueue.main.async {
                NSWorkspace.shared.open(self.appURL)
            }
        }
    }

    // MARK: - Menu actions

    @objc func openNmapUI(_ sender: Any?) {
        if !isFlaskRunning { startFlask() }
        waitForFlaskThenOpen()
    }

    @objc func startNmapUI(_ sender: Any?) {
        startFlask()
    }

    @objc func stopNmapUI(_ sender: Any?) {
        stopFlask()
    }

    @objc func restartNmapUI(_ sender: Any?) {
        stopFlask()
        // Brief pause to let the OS release the port before restarting
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            self.startFlask()
        }
    }

    @objc func quitApp(_ sender: Any?) {
        stopFlask(wait: false)
        NSApp.terminate(nil)
    }

    @objc func uninstallApp(_ sender: Any?) {
        let alert = NSAlert()
        alert.messageText = "Uninstall NmapUI"
        alert.informativeText = "Quit the app and move NmapUI.app to the Trash to uninstall."
        alert.addButton(withTitle: "OK")
        alert.alertStyle = .informational
        alert.runModal()
    }

    func applicationWillTerminate(_ notification: Notification) {
        stopFlask(wait: false)
        statusItem = nil
    }

    enum ActivityIndicatorState {
        case idle
        case starting
        case active(jobTypes: [String])
        case completed
        case error
    }

    struct RuntimeStatus: Decodable {
        struct ActiveJob: Decodable {
            let sid: String?
            let job_type: String?
            let status: String?
            let details: [String: String]?
        }

        let has_active_jobs: Bool
        let active_job_types: [String]
        let active_jobs: [ActiveJob]
    }

    func startStatusPolling() {
        stopStatusPolling()
        statusPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.pollRuntimeStatus()
        }
        if let timer = statusPollTimer {
            RunLoop.main.add(timer, forMode: .common)
        }
        pollRuntimeStatus()
    }

    func stopStatusPolling() {
        statusPollTimer?.invalidate()
        statusPollTimer = nil
        hadActiveJob = false
        completedIndicatorUntil = nil
    }

    func pollRuntimeStatus() {
        guard isFlaskRunning else {
            updateStatusIcon(state: .idle, detail: "NmapUI stopped")
            return
        }

        var request = URLRequest(url: runtimeStatusURL)
        request.timeoutInterval = 1.5

        URLSession.shared.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                if let _ = error {
                    self.updateStatusIcon(state: .starting, detail: "Waiting for local server")
                    return
                }

                guard
                    let http = response as? HTTPURLResponse,
                    http.statusCode == 200,
                    let data = data,
                    let runtimeStatus = try? JSONDecoder().decode(RuntimeStatus.self, from: data)
                else {
                    self.updateStatusIcon(state: .error, detail: "Unable to read runtime status")
                    return
                }

                let now = Date()
                if runtimeStatus.has_active_jobs {
                    self.hadActiveJob = true
                    self.completedIndicatorUntil = nil
                    self.updateStatusIcon(
                        state: .active(jobTypes: runtimeStatus.active_job_types),
                        detail: self.activityDetail(from: runtimeStatus)
                    )
                    return
                }

                if self.hadActiveJob {
                    self.hadActiveJob = false
                    self.completedIndicatorUntil = now.addingTimeInterval(20)
                }

                if let completedUntil = self.completedIndicatorUntil, completedUntil > now {
                    self.updateStatusIcon(state: .completed, detail: "Recent scan or report completed")
                } else {
                    self.completedIndicatorUntil = nil
                    self.updateStatusIcon(state: .idle, detail: "NmapUI idle")
                }
            }
        }.resume()
    }

    func activityDetail(from runtimeStatus: RuntimeStatus) -> String {
        if let job = runtimeStatus.active_jobs.first,
           let message = job.details?["message"],
           !message.isEmpty {
            return message
        }

        if runtimeStatus.active_job_types.isEmpty {
            return "Active work in progress"
        }

        return runtimeStatus.active_job_types
            .map { $0.capitalized }
            .joined(separator: " + ") + " in progress"
    }

    func updateStatusIcon(state: ActivityIndicatorState, detail: String) {
        guard let button = statusItem.button else { return }

        let symbolName: String
        let accessibility: String

        switch state {
        case .idle:
            symbolName = "network"
            accessibility = "NmapUI idle"
        case .starting:
            symbolName = "hourglass"
            accessibility = "NmapUI starting"
        case .active(let jobTypes):
            symbolName = "dot.radiowaves.left.and.right"
            accessibility = "NmapUI active: " + (jobTypes.isEmpty ? "job running" : jobTypes.joined(separator: ", "))
        case .completed:
            symbolName = "checkmark.circle.fill"
            accessibility = "NmapUI recent activity completed"
        case .error:
            symbolName = "exclamationmark.triangle.fill"
            accessibility = "NmapUI status unavailable"
        }

        button.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: accessibility)
        button.toolTip = detail
    }
}

func main() {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    app.run()
}

main()
