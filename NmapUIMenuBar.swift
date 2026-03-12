import Cocoa
import WebKit

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var popover: NSPopover!
    var webView: WKWebView!
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Create menu bar item
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "network", accessibilityDescription: "NmapUI")
            button.action = #selector(togglePopover(_:))
        }
        
        // Create the web view
        webView = WKWebView()
        if let url = URL(string: "http://localhost:9999") {
            webView.load(URLRequest(url: url))
        }
        
        // Create popover to hold the web view
        popover = NSPopover()
        popover.contentSize = NSSize(width: 400, height: 500)
        popover.behavior = .transient
        
        // Create a view controller to hold our web view
        let viewController = NSViewController()
        let view = NSView()
        viewController.view = view
        
        // Add web view to the view controller's view
        view.addSubview(webView)
        
        // Configure web view to fill the view controller's view
        webView.translatesAutoresizingMaskIntoConstraints = false
        view.addConstraints([
            webView.topAnchor.constraint(equalTo: view.topAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor)
        ])
        
        popover.contentViewController = viewController
    }
    
    @objc func togglePopover(_ sender: Any?) {
        if let button = statusItem.button {
            if popover.isShown {
                popover.performClose(sender)
            } else {
                popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            }
        }
    }
    
    func applicationWillTerminate(_ notification: Notification) {
        // Clean up - safely remove web view from superview
        if webView != nil && webView.superview != nil {
            webView.removeFromSuperview()
        }
        webView = nil
        
        // Clear popover content view controller
        if popover.contentViewController != nil {
            popover.contentViewController = nil
        }
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