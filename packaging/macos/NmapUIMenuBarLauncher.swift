import Cocoa

class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let appURL = URL(string: "http://127.0.0.1:9000")!
    var statusItem: NSStatusItem!
    var pythonProcess: Process?

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
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "network", accessibilityDescription: "NmapUI")
        }

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

    func startFlask() {
        guard !isFlaskRunning else { return }

        guard let bundleNS = Bundle.main.bundlePath as NSString? else { return }
        let resourcesPath = bundleNS.appendingPathComponent("Contents/Resources")
        let runScriptPath = (resourcesPath as NSString).appendingPathComponent("run.sh")

        guard FileManager.default.fileExists(atPath: runScriptPath) else {
            print("run.sh not found inside bundle — rebuild with build.sh")
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [runScriptPath]
        process.currentDirectoryURL = URL(fileURLWithPath: resourcesPath, isDirectory: true)

        do {
            try process.run()
            pythonProcess = process
            print("NmapUI started with PID: \(process.processIdentifier)")
        } catch {
            print("Failed to start NmapUI: \(error)")
        }
    }

    // Kill the tracked process and any stray app.py processes (e.g. from a
    // previous run or if pythonProcess is stale after a crash/restart).
    func stopFlask(wait: Bool = true) {
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
    }

    // Poll localhost:9000 until Flask responds (or timeout), then open browser
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
        alert.informativeText = "Quit the app and move NmapUIMenuBar.app to the Trash to uninstall."
        alert.addButton(withTitle: "OK")
        alert.alertStyle = .informational
        alert.runModal()
    }

    func applicationWillTerminate(_ notification: Notification) {
        stopFlask(wait: false)
        statusItem = nil
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
