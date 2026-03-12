# NmapUI Swift Wrapper - Setup Instructions

This guide will help you create a macOS Swift application that shows a menu bar icon to launch the NmapUI web interface.

## Step 1: Create the Xcode Project

1. Open Xcode
2. Select "Create a new Xcode project"
3. Choose "App" under macOS tab
4. Click "Next"
5. Configure your project:
   - Product Name: NmapUIWrapper
   - Team: (Your team or None)
   - Organization Identifier: com.techmore (or your own)
   - Interface: SwiftUI
   - Life Cycle: AppKit App Delegate
   - Language: Swift
6. Click "Next" and choose a location to save the project
7. Click "Create"

## Step 2: Replace the Generated Files

Replace the contents of the following files with the code provided below:

### NmapUIWrapperApp.swift (replace the existing file)
```swift
import SwiftUI

@main
struct NmapUIWrapperApp: App {
    var body: some Scene {
        MenuBarExtra("NmapUI", systemImage: "network") {
            ContentView()
                .frame(width: 400, height: 500)
        }
        .menuBarExtraStyle(.window)
    }
}

struct ContentView: View {
    var body: some View {
        VStack {
            Text("NmapUI")
                .font(.title)
                .padding()
            
            WebView(url: URL(string: "http://localhost:9999")!)
                .frame(minWidth: 400, minHeight: 400)
        }
        .frame(width: 400, height: 500)
    }
}

struct WebView: NSViewRepresentable {
    let url: URL
    
    func makeNSView(context: Context) -> WKWebView {
        let webView = WKWebView()
        webView.load(URLRequest(url: url))
        return webView
    }
    
    func updateNSView(_ nsView: WKWebView, context: Context) {
        // Update if needed
    }
}

// Extension for olive color matching NmapUI theme
extension Color {
    static let olive = Color(red: 0.42, green: 0.55, blue: 0.42)
}
```

### Make sure you have these imports at the top of your file:
```swift
import SwiftUI
import WebKit
```

## Step 3: Configure the App for Menu Bar Only

1. Select your project in the project navigator
2. Select your target (NmapUIWrapper)
3. Go to the "General" tab
4. In "Deployment Info", check "Hide application from Dock"
5. Or alternatively, add this to your Info.plist:
   - Key: "Application is agent (UIElement)"
   - Value: YES

## Step 4: Build and Run

1. Click the Run button in Xcode (or press Cmd+R)
2. The app will build and launch
3. You should see a network icon in your menu bar
4. Click the icon to open the NmapUI interface pointing to localhost:9999

## Step 5: Running NmapUI

Make sure your NmapUI application is running and accessible at http://localhost:9999 before launching the wrapper.

To run NmapUI:
```bash
# If using virtual environment
source venv/bin/activate
python app.py
```

## Customization Options

### Changing the Menu Bar Icon
Modify this line in NmapUIWrapperApp.swift:
```swift
MenuBarExtra("NmapUI", systemImage: "network") {
```
Replace "network" with any SF Symbol name (https://sfsymbols.apple.com)

### Changing the Window Size
Modify these lines in ContentView:
```swift
.frame(width: 400, height: 500)
// and
.frame(minWidth: 400, minHeight: 400)
```

### Changing the Target URL
Modify this line in ContentView:
```swift
WebView(url: URL(string: "http://localhost:9999")!)
```
Replace with your desired URL.

## Next Steps for Server Communication

To add the ability to send reports to a parent server using a key:

1. Add secure key storage using Keychain
2. Implement a local HTTP server in the Swift app to receive reports from the web interface
3. Add configuration UI in the menu bar for server settings
4. Implement secure transmission to the parent server

Would you like me to provide the implementation for any of these server communication features?