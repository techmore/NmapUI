import Cocoa
import WebKit
import Security
import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var popover: NSPopover!
    var webView: WKWebView!
    var httpListener: NWListener?
    var parentServerURL: String = ""
    var apiKey: String = ""
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Load saved configuration
        loadConfiguration()
        
        // Create menu bar item
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "network", accessibilityDescription: "NmapUI")
            button.action = #selector(togglePopover(_:))
            
            // Add menu
            let menu = NSMenu()
            
            // Configure Server menu item
            let configureItem = NSMenuItem(title: "Configure Server...", action: #selector(showConfigWindow(_:)), keyEquivalent: "")
            configureItem.target = self
            menu.addItem(configureItem)
            
            menu.addItem(NSMenuItem.separator())
            
            // Quit menu item
            let quitItem = NSMenuItem(title: "Quit NmapUI Wrapper", action: #selector(quitApp(_:)), keyEquivalent: "q")
            quitItem.target = self
            menu.addItem(quitItem)
            
            button.menu = menu
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
        
        // Start the local HTTP server to receive reports
        startReportServer()
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
    
    @objc func showConfigWindow(_ sender: Any?) {
        let configWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 200),
            styleMask: [.titled, .closable],
            backing: .buffered, defer: false)
        configWindow.center()
        configWindow.setFrameAutosaveName("Configure Server")
        configWindow.title = "Configure Parent Server"
        
        // Use @StateObject to manage the config view state
        let configView = ConfigView { [weak self] in
            self?.saveConfiguration()
            self?.startReportServer() // Restart server with new config
            configWindow.close()
        } parentURL: $parentServerURL, apiKey: $apiKey
        
        let hostingController = NSHostingController(rootView: configView)
        
        configWindow.contentViewController = hostingController
        configWindow.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    
    @objc func quitApp(_ sender: Any?) {
        NSApp.terminate(nil)
    }
    
    func startReportServer() {
        // Stop existing listener if any
        httpListener?.cancel()
        
        // Only start if we have configuration
        guard !parentServerURL.isEmpty && !apiKey.isEmpty else {
            print("Server not configured. Please set parent server URL and API key.")
            return
        }
        
        do {
            // Create listener on localhost:8080
            let parameters = NWParameters.tcp
            parameters.allowLocalEndpointReuse = true
            httpListener = try NWListener(using: parameters, on: NWEndpoint.Port(integerLiteral: 8080))
            
            httpListener?.newConnectionHandler = { [weak self] connection in
                self?.handleReportConnection(connection)
            }
            
            httpListener?.stateUpdateHandler = { [weak self] newState in
                switch newState {
                case .ready:
                    print("Report server started on port 8080")
                case .failed(let error):
                    print("Report server failed: \(error)")
                default:
                    break
                }
            }
            
            httpListener?.start(queue: .main)
        } catch {
            print("Failed to start report server: \(error)")
        }
    }
    
    func handleReportConnection(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, context, isComplete, error in
            if let data = data, !data.isEmpty {
                // Process received report data
                self?.processReceivedReport(data)
            }
            
            if isComplete {
                connection.cancel()
            } else if let error = error {
                print("Connection error: \(error)")
                connection.cancel()
            } else {
                // Continue listening for more data
                self?.handleReportConnection(connection)
            }
        }
    }
    
    func processReceivedReport(_ data: Data) {
        // Forward the report to the parent server
        forwardReportToParent(data)
    }
    
    func forwardReportToParent(_ reportData: Data) {
        guard let url = URL(string: parentServerURL) else {
            print("Invalid parent server URL")
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        request.httpBody = reportData
        
        let task = URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            if let error = error {
                print("Failed to send report to parent server: \(error)")
                return
            }
            
            if let httpResponse = response as? HTTPURLResponse {
                if (200...299).contains(httpResponse.statusCode) {
                    print("Report successfully sent to parent server")
                } else {
                    print("Parent server returned error: \(httpResponse.statusCode)")
                }
            }
        }
        
        task.resume()
    }
    
    func saveConfiguration() {
        // Save to UserDefaults for simplicity (in production, consider more secure storage)
        UserDefaults.standard.set(parentServerURL, forKey: "parentServerURL")
        UserDefaults.standard.set(apiKey, forKey: "apiKey")
        UserDefaults.standard.synchronize()
        
        // Also save API key to Keychain for better security
        if !apiKey.isEmpty {
            saveKeyToKeychain(apiKey, forService: "com.techmore.nmapuimenubar.apiKey")
        }
    }
    
    func loadConfiguration() {
        // Load from UserDefaults
        if let url = UserDefaults.standard.string(forKey: "parentServerURL") {
            parentServerURL = url
        }
        if let key = UserDefaults.standard.string(forKey: "apiKey") {
            apiKey = key
        }
        
        // Try to get API key from Keychain as well (preferred)
        if let keychainKey = getKeyFromKeychain(forService: "com.techmore.nmapuimenubar.apiKey") {
            apiKey = keychainKey
        }
    }
    
    // MARK: - Keychain Functions
    
    func saveKeyToKeychain(_ key: String, forService service: String) -> Bool {
        if let data = key.data(using: .utf8) {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecValueData as String: data
            ]
            
            SecItemDelete(query as CFDictionary)  // Remove any existing item
            let status = SecItemAdd(query as CFDictionary, nil)
            return status == errSecSuccess
        }
        return false
    }
    
    func getKeyFromKeychain(forService service: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess {
            if let data = dataTypeRef as? Data {
                return String(data: data, encoding: .utf8)
            }
        }
        return nil
    }
    
    func applicationWillTerminate(_ notification: Notification) {
        // Clean up
        httpListener?.cancel()
        
        if let viewController = popover.contentViewController {
            viewController.view = nil
        }
        webView = nil
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

// Configuration View
struct ConfigView: View {
    var onSave: () -> Void
    @Binding var parentURL: String
    @Binding var apiKey: String
    
    @State private var showingAlert = false
    @State private var alertMessage = ""
    
    var body: some View {
        VStack(spacing: 20) {
            Text("Parent Server Configuration")
                .font(.headline)
            
            VStack(alignment: .leading, spacing: 8) {
                Text("Server URL")
                    .font(.subheadline)
                TextField("https://your-parent-server.com/api/reports", text: $parentURL)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal)
            }
            
            VStack(alignment: .leading, spacing: 8) {
                Text("API Key")
                    .font(.subheadline)
                SecureField("Enter your API key", text: $apiKey)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal)
            }
            
            Button(action: {
                // Validate inputs
                if parentURL.isEmpty || apiKey.isEmpty {
                    alertMessage = "Please fill in both fields"
                    showingAlert = true
                    return
                }
                
                if !parentURL.hasPrefix("http://") && !parentURL.hasPrefix("https://") {
                    alertMessage = "Server URL must start with http:// or https://"
                    showingAlert = true
                    return
                }
                
                onSave()
            }) {
                Text("Save Configuration")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(parentURL.isEmpty || apiKey.isEmpty)
        }
        .padding()
        .frame(width: 350, height: 200)
        .alert("Configuration Error", isPresented: $showingAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(alertMessage)
        }
    }
}