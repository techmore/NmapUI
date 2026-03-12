import Cocoa

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    
    func applicationDidFinishLaunching(_ notification: Notification) {
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
    
    @objc func openNmapUI(_ sender: Any?) {
        if let url = URL(string: "http://localhost:9999") {
            NSWorkspace.shared.open(url)
        }
    }
    
    @objc func quitApp(_ sender: Any?) {
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
        // Clean up if needed
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