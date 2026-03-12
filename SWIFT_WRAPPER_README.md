# NmapUI Swift Menu Bar Wrapper

A lightweight macOS menu bar application that launches the NmapUI web interface.

## Features
- Network icon in menu bar
- Click to open NmapUI interface at http://localhost:9999
- Runs as menu bar app (no dock icon)
- Clean memory management

## Files
- `NmapUIMenuBar.swift` - The complete Swift source code

## Building the Application

### Prerequisites
- Xcode command line tools (includes swiftc compiler)
- macOS 13.0 or later

### Build Command
```bash
swiftc \
  -sdk "$(xcrun --show-sdk-path --sdk macosx)" \
  -target arm64-apple-macosx13.0 \
  -framework SwiftUI \
  -framework AppKit \
  -framework WebKit \
  NmapUIMenuBar.swift \
  -o NmapUIMenuBar
```

### Alternative Build Script
Save this as `build.sh` and make it executable (`chmod +x build.sh`):
```bash
#!/bin/bash
SDK_PATH=$(xcrun --show-sdk-path --sdk macosx)
swiftc \
  -sdk "$SDK_PATH" \
  -target arm64-apple-macosx13.0 \
  -framework SwiftUI \
  -framework AppKit \
  -framework WebKit \
  NmapUIMenuBar.swift \
  -o NmapUIMenuBar
```

## Running the Application
```bash
./NmapUIMenuBar &
```

The app will appear as a network icon in your menu bar. Click it to open the NmapUI interface.

## How It Works
1. Creates a menu bar item with a network icon
2. When clicked, shows a popover containing a WKWebView
3. The WKWebView loads http://localhost:9999 (your NmapUI instance)
4. Properly cleans up resources when terminating

## Prerequisites for Use
Your NmapUI application must be running and accessible at http://localhost:9999 before launching the wrapper.

To run NmapUI:
```bash
# If using virtual environment
source venv/bin/activate
python app.py
```

## Next Steps: Adding Server Communication

To add the ability to send reports to a parent server using a key, we would need to:

### 1. Add Secure Key Storage
```swift
import Security

func saveKeyToKeychain(key: String, forService service: String) -> Bool {
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
```

### 2. Add Local HTTP Server to Receive Reports
```swift
import Foundation

class ReportReceiver {
    private var listener: NWListener?
    
    func startListening(onPort port: UInt16 = 8080) {
        do {
            listener = try NWListener(using: .tcp, on: NWEndpoint.Port(integerLiteral: port))
            listener?.newConnectionHandler { [weak self] connection in
                self?.handleConnection(connection)
            }
            listener?.start(queue: .main)
        } catch {
            print("Failed to start listener: \(error)")
        }
    }
    
    private func handleConnection(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, context, isComplete, error in
            if let data = data, !data.isEmpty {
                // Process received report data
                self?.processReportData(data)
            }
            
            if isComplete {
                connection.cancel()
            } else if let error = error {
                print("Connection error: \(error)")
                connection.cancel()
            } else {
                // Continue listening for more data
                self?.handleConnection(connection)
            }
        }
    }
    
    private func processReportData(_ data: Data) {
        // Decode and handle the report
        // Then forward to parent server using stored key
    }
}
```

### 3. Add Server Transmission Functionality
```swift
func sendReportToParentServer(_ reportData: Data, serverURL: String, apiKey: String) {
    guard let url = URL(string: serverURL) else { return }
    
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
    request.httpBody = reportData
    
    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        if let error = error {
            print("Failed to send report: \(error)")
            return
        }
        
        if let httpResponse = response as? HTTPURLResponse {
            print("Report sent successfully. Status: \(httpResponse.statusCode)")
        }
    }
    
    task.resume()
}
```

### 4. Add Configuration UI
Add menu bar options to:
- Set parent server URL
- Enter/store API key securely
- Test connection
- View transmission logs

Would you like me to implement any of these server communication features next? I can provide the complete Swift code with all these additions integrated.