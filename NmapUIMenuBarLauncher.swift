import Cocoa

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var pythonProcess: Process!
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Launch the NmapUI Python application from bundle resources
        launchNmapUI()
        
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
    
    func launchNmapUI() {
        // Find the app.py file in the bundle resources
        if let bundlePath = Bundle.main.bundlePath as NSString? {
            let resourcesPath = bundlePath.appendingPathComponent("Contents/Resources")
            let appPath = (resourcesPath as NSString).appendingPathComponent("app.py")
            
            // Check if app.py exists in bundle
            if FileManager.default.fileExists(atPath: appPath) {
                pythonProcess = Process()
                pythonProcess.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
                pythonProcess.arguments = [appPath]
                
                // Set working directory to resources so it can find templates, etc.
                pythonProcess.currentDirectoryPath = resourcesPath
                
                do {
                    try pythonProcess.run()
                    print("Launched NmapUI with PID: \(pythonProcess.processIdentifier)")
                } catch {
                    print("Failed to launch NmapUI: \(error)")
                }
            } else {
                // Fallback: try to launch from original location (for development)
                let fallbackPath = "/Users/seandolbec/Projects/NmapUI/app.py"
                if FileManager.default.fileExists(atPath: fallbackPath) {
                    pythonProcess = Process()
                    pythonProcess.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
                    pythonProcess.arguments = [fallbackPath]
                    
                    do {
                        try pythonProcess.run()
                        print("Launched NmapUI from fallback location with PID: \(pythonProcess.processIdentifier)")
                    } catch {
                        print("Failed to launch NmapUI from fallback: \(error)")
                    }
                } else {
                    print("Could not find app.py in bundle or fallback location")
                }
            }
        }
    }
    
    @objc func openNmapUI(_ sender: Any?) {
        if let url = URL(string: "http://localhost:9999") {
            NSWorkspace.shared.open(url)
        }
    }
    
    @objc func quitApp(_ sender: Any?) {
        // Terminate the Python process first
        if pythonProcess != nil && pythonProcess.isRunning {
            pythonProcess.terminate()
            pythonProcess.waitUntilExit()
        }
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
        // Clean up - terminate Python process if still running
        if pythonProcess != nil && pythonProcess.isRunning {
            pythonProcess.terminate()
            pythonProcess.waitUntilExit()
        }
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
_ = main()