import Foundation
import SwiftUI
import WebKit
import AppKit

struct NativeShellView: View {
    let url: URL
    @ObservedObject var sessionState: AppSessionState
    let onOpenBrowser: () -> Void
    @State private var refreshNonce = UUID()
    @State private var selectedTab: NativeTab = .dashboard
    private let oliveTheme = OliveTheme()

    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                NativeShellHeader(
                    statusText: sessionState.runtimeStatusText,
                    startupHint: sessionState.startupHint,
                    currentDateTime: Self.currentDateTimeString(),
                    theme: oliveTheme,
                    onOpenBrowser: onOpenBrowser,
                    onRefresh: {
                        refreshNonce = UUID()
                    }
                )
                NativeTabBar(selectedTab: $selectedTab, theme: oliveTheme)
                WebPortalView(url: url, refreshNonce: refreshNonce)
                    .onChange(of: selectedTab) { newValue in
                        WebPortalViewCoordinatorBridge.shared.selectTab(newValue)
                    }
                    .onAppear {
                        WebPortalViewCoordinatorBridge.shared.selectTab(selectedTab)
                    }
                if sessionState.showLoadingStrip {
                    NativeLoadingStrip(preloadMessage: sessionState.preloadMessage)
                }
            }
        }
        .frame(minWidth: 1100, minHeight: 760)
        .background(oliveTheme.windowBackground)
        .onAppear {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first?.makeKeyAndOrderFront(nil)
        }
    }

    private static func currentDateTimeString() -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: Date())
    }
}

private struct OliveTheme {
    let olive950 = Color(red: 0.10, green: 0.12, blue: 0.07)
    let olive900 = Color(red: 0.13, green: 0.15, blue: 0.10)
    let olive800 = Color(red: 0.20, green: 0.22, blue: 0.14)
    let olive700 = Color(red: 0.28, green: 0.31, blue: 0.18)
    let olive500 = Color(red: 0.44, green: 0.46, blue: 0.26)
    let olive300 = Color(red: 0.69, green: 0.70, blue: 0.55)
    let olive200 = Color(red: 0.83, green: 0.84, blue: 0.72)
    let olive100 = Color(red: 0.92, green: 0.92, blue: 0.86)
    let olive50 = Color(red: 0.97, green: 0.97, blue: 0.94)
    let windowBackground = LinearGradient(
        colors: [Color(red: 0.98, green: 0.98, blue: 0.96), Color(red: 0.94, green: 0.94, blue: 0.89)],
        startPoint: .top,
        endPoint: .bottom
    )
}

fileprivate enum NativeTab: String, CaseIterable, Identifiable {
    case dashboard
    case history
    case reports
    case customers
    case logs
    case settings

    var id: String { rawValue }

    var title: String {
        rawValue.capitalized
    }

    var symbolName: String {
        switch self {
        case .dashboard: return "rectangle.3.group"
        case .history: return "clock.arrow.circlepath"
        case .reports: return "doc.richtext"
        case .customers: return "person.3"
        case .logs: return "text.bubble"
        case .settings: return "gearshape"
        }
    }
}

private struct NativeTabBar: View {
    @Binding var selectedTab: NativeTab
    let theme: OliveTheme

    var body: some View {
        HStack(spacing: 8) {
            ForEach(NativeTab.allCases) { tab in
                Button {
                    selectedTab = tab
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: tab.symbolName)
                            .font(.system(size: 12, weight: .semibold))
                        Text(tab.title)
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .padding(.horizontal, 10)
                }
                .buttonStyle(.plain)
                .background(
                    ZStack {
                        if selectedTab == tab {
                            RoundedRectangle(cornerRadius: 999, style: .continuous)
                                .fill(theme.olive700)
                                .shadow(color: theme.olive300.opacity(0.35), radius: 2, x: 0, y: 1)
                        } else {
                            RoundedRectangle(cornerRadius: 999, style: .continuous)
                                .fill(theme.olive50)
                        }
                    }
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 999, style: .continuous)
                        .stroke(selectedTab == tab ? theme.olive900.opacity(0.45) : theme.olive200, lineWidth: 1)
                )
                .foregroundStyle(selectedTab == tab ? Color.white : theme.olive700)
                .contentShape(RoundedRectangle(cornerRadius: 999, style: .continuous))
                .overlay(alignment: .bottom) {
                    if selectedTab == tab {
                        RoundedRectangle(cornerRadius: 999, style: .continuous)
                            .fill(theme.olive300)
                            .frame(height: 2)
                            .padding(.horizontal, 22)
                            .offset(y: 6)
                    }
                }
                .accessibilityLabel(tab.title)
                .accessibilityAddTraits(selectedTab == tab ? [.isSelected] : [])
                .animation(.easeInOut(duration: 0.16), value: selectedTab)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 2)
                .padding(.horizontal, 1)
                .overlay(alignment: .bottom) {
                    if selectedTab == tab {
                        Capsule()
                            .fill(theme.olive300)
                            .frame(height: 2)
                            .padding(.horizontal, 18)
                            .offset(y: 6)
                    }
                }
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(theme.olive50)
                .shadow(color: theme.olive200.opacity(0.35), radius: 2, x: 0, y: 1)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(theme.olive200, lineWidth: 1)
        )
        .overlay(alignment: .bottom) {
            Divider().overlay(theme.olive200)
        }
    }
}

private struct NativeShellHeader: View {
    let statusText: String
    let startupHint: String
    let currentDateTime: String
    let theme: OliveTheme
    let onOpenBrowser: () -> Void
    let onRefresh: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 18) {
            HStack(alignment: .center, spacing: 16) {
                HeaderLogo(theme: theme)

                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text("TM-NMAPUI")
                            .font(.system(size: 30, weight: .regular, design: .serif))
                            .italic()
                            .foregroundStyle(theme.olive900)

                        Text("v2026.5.2.15.58")
                            .font(.footnote.weight(.medium))
                            .foregroundStyle(theme.olive700)

                        Button {
                            NSWorkspace.shared.open(URL(string: "https://github.com/techmore/NmapUI")!)
                        } label: {
                            Image(systemName: "link")
                                .font(.system(size: 11, weight: .semibold))
                                .padding(6)
                                .background(theme.olive100)
                                .clipShape(Circle())
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(theme.olive700)
                    }
                    Text(startupHint)
                        .font(.caption)
                        .foregroundStyle(theme.olive700)
                }
            }

            Spacer()

            Text(currentDateTime)
                .font(.system(.headline, design: .serif))
                .foregroundStyle(theme.olive900)

            VStack(alignment: .trailing, spacing: 8) {
                Label(statusText, systemImage: statusText == "Ready" ? "checkmark.circle.fill" : "dot.radiowaves.left.and.right")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(theme.olive700)

                HStack(spacing: 10) {
                    Button(action: onRefresh) {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .tint(theme.olive700)

                    Button(action: onOpenBrowser) {
                        Label("Open in Browser", systemImage: "safari")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(theme.olive700)
                }
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 14)
        .background(theme.olive100)
        .overlay(alignment: .bottom) {
            Divider().overlay(theme.olive200)
        }
    }
}

private struct HeaderLogo: View {
    let theme: OliveTheme

    var body: some View {
        Image(nsImage: Self.logoImage() ?? Self.fallbackImage())
            .resizable()
            .frame(width: 44, height: 44)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(theme.olive200, lineWidth: 1)
            )
    }

    private static func logoImage() -> NSImage? {
        let bundle = Bundle.module
        if let url = bundle.url(forResource: "techmore", withExtension: "png"),
           let image = NSImage(contentsOf: url) {
            return image
        }
        return nil
    }

    private static func fallbackImage() -> NSImage {
        let image = NSImage(size: .init(width: 44, height: 44))
        image.lockFocus()
        NSColor.systemGray.setFill()
        NSBezierPath(rect: .init(x: 0, y: 0, width: 44, height: 44)).fill()
        image.unlockFocus()
        return image
    }
}

private struct NativeLoadingStrip: View {
    let preloadMessage: String

    var body: some View {
        HStack(spacing: 10) {
            ProgressView()
                .controlSize(.small)
            Text(preloadMessage)
                .font(.callout)
                .foregroundStyle(Color(red: 0.28, green: 0.31, blue: 0.18))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
        .background(Color(red: 0.96, green: 0.96, blue: 0.92))
        .overlay(alignment: .top) {
            Divider().overlay(Color(red: 0.83, green: 0.84, blue: 0.72))
        }
    }
}

struct WebPortalView: NSViewRepresentable {
    let url: URL
    let refreshNonce: UUID

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.setValue(false, forKey: "drawsBackground")
        webView.navigationDelegate = context.coordinator
        webView.allowsMagnification = true
        if #available(macOS 13.3, *) {
            webView.isInspectable = true
        }
        WebPortalViewCoordinatorBridge.shared.register(webView: webView)
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        if context.coordinator.lastRefreshNonce != refreshNonce {
            context.coordinator.lastRefreshNonce = refreshNonce
            webView.load(URLRequest(url: url))
            return
        }
        if context.coordinator.didFinishFirstLoad == false || webView.url == nil {
            webView.load(URLRequest(url: url))
            return
        }
        if webView.url != url {
            webView.load(URLRequest(url: url))
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var didFinishFirstLoad = false
        var lastRefreshNonce = UUID()

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            didFinishFirstLoad = true
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            didFinishFirstLoad = false
        }
    }
}

@MainActor
final class WebPortalViewCoordinatorBridge {
    static let shared = WebPortalViewCoordinatorBridge()

    private weak var webView: WKWebView?

    func register(webView: WKWebView) {
        self.webView = webView
    }

    fileprivate func selectTab(_ tab: NativeTab) {
        guard let webView else { return }
        let script = "if (window.switchAppTab) { window.switchAppTab('\(tab.rawValue)', { broadcast: true, persist: true }); }"
        webView.evaluateJavaScript(script, completionHandler: nil)
    }
}
