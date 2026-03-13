import Cocoa

class AppDelegate: NSObject, NSApplicationDelegate {
    let appURL = URL(string: "http://127.0.0.1:9000")!
    var statusItem: NSStatusItem!
    var pythonProcess: Process?
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        startNmapUIIfNeeded()
        
        // Create menu bar item
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "network", accessibilityDescription: "NmapUI")
            // Create menu
            let menu = NSMenu()
            
            // Open NmapUI menu item
            let openItem = NSMenuItem(title: "Open NmapUI", action: #selector(openNmapUI(_:)), keyEquivalent: "o")
            openItem.target = self
            menu.addItem(openItem)

            let startItem = NSMenuItem(title: "Start NmapUI", action: #selector(startNmapUI(_:)), keyEquivalent: "s")
            startItem.target = self
            menu.addItem(startItem)

            let stopItem = NSMenuItem(title: "Stop NmapUI", action: #selector(stopNmapUI(_:)), keyEquivalent: "")
            stopItem.target = self
            menu.addItem(stopItem)
            
            menu.addItem(NSMenuItem.separator())
            
            // Quit menu item
            let quitItem = NSMenuItem(title: "Quit", action: #selector(quitApp(_:)), keyEquivalent: "q")
            quitItem.target = self
            menu.addItem(quitItem)
            
            // Uninstall menu item
            let uninstallItem = NSMenuItem(title: "Uninstall", action: #selector(uninstallApp(_:)), keyEquivalent: "u")
            uninstallItem.target = self
            menu.addItem(uninstallItem)
            
            button.menu = menu
        }
    }
    
    func startNmapUIIfNeeded() {
        guard pythonProcess?.isRunning != true else {
            return
        }

        if let bundlePath = Bundle.main.bundlePath as NSString? {
            let resourcesPath = bundlePath.appendingPathComponent("Contents/Resources")
            let runScriptPath = (resourcesPath as NSString).appendingPathComponent("run.sh")

            if FileManager.default.fileExists(atPath: runScriptPath) {
                pythonProcess = Process()
                pythonProcess?.executableURL = URL(fileURLWithPath: "/bin/bash")
                pythonProcess?.arguments = [runScriptPath]
                pythonProcess?.currentDirectoryURL = URL(fileURLWithPath: resourcesPath, isDirectory: true)
                
                do {
                    try pythonProcess?.run()
                    if let process = pythonProcess {
                        print("Launched bundled NmapUI with PID: \(process.processIdentifier)")
                    }
                } catch {
                    print("Failed to launch bundled NmapUI: \(error)")
                }
            } else {
                print("Bundled run.sh was not found. Rebuild the wrapper bundle before launching.")
            }
        }
    }
    
    @objc func openNmapUI(_ sender: Any?) {
        startNmapUIIfNeeded()
        NSWorkspace.shared.open(appURL)
    }

    @objc func startNmapUI(_ sender: Any?) {
        startNmapUIIfNeeded()
    }

    @objc func stopNmapUI(_ sender: Any?) {
        if let process = pythonProcess, process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
        pythonProcess = nil
    }
    
    @objc func quitApp(_ sender: Any?) {
        stopNmapUI(sender)
        NSApp.terminate(nil)
    }
    
    @objc func uninstallApp(_ sender: Any?) {
        let alert = NSAlert()
        alert.messageText = "Uninstall NmapUI Wrapper"
        alert.informativeText = "To uninstall, quit the application and move the app bundle to the Trash."
        alert.addButton(withTitle: "OK")
        alert.alertStyle = .informational
        alert.runModal()
    }
    
    func applicationWillTerminate(_ notification: Notification) {
        stopNmapUI(nil)
        statusItem = nil
    }
}

// Main function to run the app
func main() {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)  // Runs as menu bar app
    app.run()
}

// Call main function when this file is executed
main()
