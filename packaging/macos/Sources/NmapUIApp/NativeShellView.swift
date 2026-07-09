import Foundation
import SwiftUI
import WebKit
import AppKit
import RuntimeContracts

/// Native window host for the perfected HTML product UI.
///
/// The HTML dashboard (index.html + static/) is the canonical UX. This shell:
/// - presents that UI full-bleed in WKWebView (no competing native chrome)
/// - bridges scan/runtime events via webkit message handlers
/// - keeps a thin loading strip only during startup
struct NativeShellView: View {
    let url: URL
    @ObservedObject var sessionState: AppSessionState
    let onOpenBrowser: () -> Void
    let onQuickScan: () -> Void
    let onStartScan: (String, String, Bool) -> Void
    @State private var refreshNonce = UUID()

    private let oliveBackground = Color(red: 0.92, green: 0.92, blue: 0.86)

    var body: some View {
        ZStack(alignment: .top) {
            WebPortalView(url: url, refreshNonce: refreshNonce)
                .ignoresSafeArea(edges: .bottom)

            if sessionState.showLoadingStrip {
                NativeLoadingStrip(
                    preloadMessage: sessionState.preloadMessage,
                    helperReady: PrivilegeHelperClient.isHelperReachable,
                    runtimeStatus: sessionState.runtimeStatusText
                )
                .transition(.move(edge: .top).combined(with: .opacity))
            }
        }
        .frame(minWidth: 1100, minHeight: 760)
        .background(oliveBackground)
        .toolbar {
            ToolbarItemGroup(placement: .automatic) {
                Button {
                    refreshNonce = UUID()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .help("Reload dashboard")

                Button(action: onOpenBrowser) {
                    Label("Browser", systemImage: "safari")
                }
                .help("Open dashboard in the default browser")

                if sessionState.runtimeScanSession.isScanning {
                    Button {
                        if let appDelegate = NSApp.delegate as? AppDelegate {
                            appDelegate.stopSwiftManagedScan()
                        }
                    } label: {
                        Label("Stop", systemImage: "stop.fill")
                    }
                    .help("Stop the active scan")
                }
            }
        }
        .onAppear {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first?.makeKeyAndOrderFront(nil)
        }
        .onChange(of: sessionState.runtimeIsReady) { isReady in
            if isReady {
                refreshNonce = UUID()
            }
        }
    }
}

private struct NativeLoadingStrip: View {
    let preloadMessage: String
    let helperReady: Bool
    let runtimeStatus: String

    var body: some View {
        HStack(spacing: 12) {
            ProgressView()
                .controlSize(.small)
            VStack(alignment: .leading, spacing: 2) {
                Text(preloadMessage)
                    .font(.system(size: 12, weight: .medium))
                Text(helperReady ? "Privileged scanner helper ready" : "Scanner helper installs on first full scan (one admin prompt)")
                    .font(.system(size: 11))
                    .foregroundStyle(Color(red: 0.44, green: 0.46, blue: 0.26))
            }
            Spacer()
            Text(runtimeStatus)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color(red: 0.28, green: 0.31, blue: 0.18))
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .background(Color(red: 0.97, green: 0.97, blue: 0.94).opacity(0.96))
        .overlay(alignment: .bottom) {
            Divider().overlay(Color(red: 0.83, green: 0.84, blue: 0.72))
        }
    }
}

struct WebPortalView: NSViewRepresentable {
    let url: URL
    let refreshNonce: UUID

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let userContentController = WKUserContentController()
        userContentController.add(context.coordinator, name: "nmapuiRuntime")
        userContentController.add(context.coordinator, name: "nmapuiRequest")
        // Mark native runtime early so the page uses the socket shim instead of Socket.IO CDN.
        let bootstrap = WKUserScript(
            source: "window.__NMAPUI_NATIVE_RUNTIME__ = true;",
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        userContentController.addUserScript(bootstrap)
        configuration.userContentController = userContentController
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.setValue(false, forKey: "drawsBackground")
        webView.navigationDelegate = context.coordinator
        webView.allowsMagnification = true
        if #available(macOS 13.3, *) {
            webView.isInspectable = true
        }
        WebPortalViewCoordinatorBridge.shared.register(webView: webView)
        loadDashboard(in: webView)
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        if context.coordinator.lastRefreshNonce != refreshNonce {
            context.coordinator.lastRefreshNonce = refreshNonce
            loadDashboard(in: webView)
            return
        }
        if context.coordinator.didFinishFirstLoad == false || webView.url == nil {
            loadDashboard(in: webView)
            return
        }
        if webView.url != url {
            loadDashboard(in: webView)
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        var didFinishFirstLoad = false
        var lastRefreshNonce = UUID()

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            didFinishFirstLoad = true
            guard let appDelegate = NSApp.delegate as? AppDelegate else { return }
            Task { @MainActor in
                appDelegate.emitCurrentRuntimeSnapshotToWebView()
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            didFinishFirstLoad = false
        }

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard let appDelegate = NSApp.delegate as? AppDelegate else { return }
            switch message.name {
            case "nmapuiRuntime":
                guard let body = message.body as? [String: Any] else { return }
                guard let action = body["action"] as? String else { return }
                RuntimeDiagnosticsLogger.log("Received native runtime action=\(action)")
                let target = (body["target"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let usePn = body["usePn"] as? Bool ?? false
                let vpnHelper = body["vpnHelper"] as? Bool ?? false
                let scanKind = body["scanKind"] as? String ?? "quick"

                Task { @MainActor in
                    switch action {
                    case "start_quick_scan", "start_complete_scan", "start_dragnet_scan":
                        _ = await appDelegate.startSwiftManagedScan(
                            target: target,
                            usePn: usePn,
                            vpnHelper: vpnHelper,
                            scanKind: scanKind
                        )
                    case "stop_scan":
                        appDelegate.stopSwiftManagedScan()
                    default:
                        break
                    }
                }
            case "nmapuiRequest":
                guard let body = message.body as? [String: Any] else { return }
                guard let eventName = body["event"] as? String else { return }
                let payload = body["payload"] as? [String: Any] ?? [:]
                guard let requestEvent = RuntimeClientRequest(rawValue: eventName) else { return }
                let request = RuntimeClientRequestEnvelope(
                    event: requestEvent,
                    payload: payload.toRuntimeJSONValueMap()
                )

                Task { @MainActor in
                    switch requestEvent {
                    case .getPrivilegeHelperStatus:
                        appDelegate.emitPrivilegeHelperStatus()
                        return
                    case .installPrivilegeHelper:
                        appDelegate.installPrivilegeHelperFromSettings()
                        return
                    case .openReport:
                        let path = (payload["path"] as? String)
                            ?? (payload["url"] as? String)
                            ?? ""
                        if !path.isEmpty {
                            appDelegate.openReportPath(path)
                        }
                        return
                    case .connectGoogleDrive:
                        appDelegate.connectGoogleDriveFromSettings()
                        return
                    case .disconnectGoogleDrive:
                        appDelegate.disconnectGoogleDriveFromSettings()
                        return
                    case .saveAppSettings:
                        appDelegate.saveAppSettingsFromWeb(payload)
                        return
                    case .stopScan:
                        appDelegate.stopSwiftManagedScan()
                        return
                    default:
                        break
                    }

                    let dispatcher = RuntimeRequestDispatcher(sessionState: appDelegate.sessionState)
                    let result = dispatcher.dispatch(
                        request,
                        dataDirectory: RuntimeSettingsStore.currentDataDirectoryURL(),
                        version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
                    )
                    for event in result.events {
                        appDelegate.sessionState.eventRouter.emit(event)
                    }
                    if let scanRequest = dispatcher.scanCoordinatorRequest(from: request) {
                        _ = await appDelegate.startSwiftManagedScan(
                            target: scanRequest.target,
                            usePn: scanRequest.usePn,
                            vpnHelper: scanRequest.vpnHelper,
                            scanKind: {
                                switch scanRequest.scanKind {
                                case .complete: return "complete"
                                case .dragnet: return "dragnet"
                                case .quick: return "quick"
                                }
                            }()
                        )
                    }
                }
            default:
                break
            }
        }

        @MainActor
        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void
        ) {
            guard navigationAction.navigationType == .linkActivated,
                  let url = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }

            // Open report artifacts and external links outside the dashboard document.
            if url.isFileURL {
                NSWorkspace.shared.open(url)
                decisionHandler(.cancel)
                return
            }
            if url.path.hasPrefix("/reports/") || url.absoluteString.contains("/reports/") {
                if let appDelegate = NSApp.delegate as? AppDelegate {
                    appDelegate.openReportPath(url.path.hasPrefix("/reports/") ? url.path : url.absoluteString)
                }
                decisionHandler(.cancel)
                return
            }
            if ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
                NSWorkspace.shared.open(url)
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }
    }

    private func loadDashboard(in webView: WKWebView) {
        let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        if url.isFileURL {
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        } else {
            webView.load(request)
        }
        scheduleSnapshotEmission()
    }

    private func scheduleSnapshotEmission() {
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 750_000_000)
            WebPortalViewCoordinatorBridge.shared.installNativeScanHandlers()
            guard let appDelegate = NSApp.delegate as? AppDelegate else { return }
            appDelegate.emitCurrentRuntimeSnapshotToWebView()
        }
    }
}

private extension Dictionary where Key == String, Value == Any {
    func toRuntimeJSONValueMap() -> [String: RuntimeJSONValue] {
        reduce(into: [:]) { result, entry in
            switch entry.value {
            case let value as String:
                result[entry.key] = .string(value)
            case let value as Bool:
                result[entry.key] = .bool(value)
            case let value as Int:
                result[entry.key] = .int(value)
            case let value as Double:
                result[entry.key] = .double(value)
            case let value as [String: Any]:
                result[entry.key] = .object(value.toRuntimeJSONValueMap())
            case let value as [Any]:
                result[entry.key] = .array(value.compactMap { item in
                    switch item {
                    case let nested as String: return .string(nested)
                    case let nested as Bool: return .bool(nested)
                    case let nested as Int: return .int(nested)
                    case let nested as Double: return .double(nested)
                    default: return nil
                    }
                })
            default:
                break
            }
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

    func emitRuntimeEvent(event: String, payloadJSON: String) {
        guard let webView else { return }
        let script = """
        (() => {
            const eventName = \(Self.jsStringLiteral(event));
            const envelope = \(payloadJSON);
            const payload = envelope && typeof envelope === 'object' && Object.prototype.hasOwnProperty.call(envelope, 'payload')
                ? envelope.payload
                : envelope;
            const socketPayload = eventName === 'initial_data' && payload?.network
                ? {
                    ...payload.network,
                    publicIP: payload.publicIP || payload.network.publicIP,
                    customerProfile: payload.customerProfile,
                    googleDrive: payload.googleDrive,
                    autoScan: payload.autoScan
                }
                : payload;
            if (window.__nmapuiHandleNativeRuntimeEvent) {
                window.__nmapuiHandleNativeRuntimeEvent(eventName, envelope);
            }
            if (window.socket && typeof window.socket.__receive === 'function') {
                window.socket.__receive(eventName, socketPayload || {});
            }
        })();
        """
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    func applyNetworkSnapshot(_ networkState: RuntimeNetworkState) {
        installNativeScanHandlers()
        guard let webView else { return }
        let hopsJSON = Self.hopsJSON(networkState.tracerouteHops)
        let script = """
        (() => {
            const setText = (id, value) => {
                const element = document.getElementById(id);
                if (element) element.textContent = value || '--';
            };
            const localIP = \(Self.jsStringLiteral(networkState.localIP));
            const mask = \(Self.jsStringLiteral(networkState.mask));
            const cidr = \(Self.jsStringLiteral(networkState.cidr));
            const publicIP = \(Self.jsStringLiteral(networkState.publicIP));
            const hops = \(hopsJSON);

            setText('local-ip-value', localIP);
            setText('subnet-mask-value', mask);
            setText('cidr-value', cidr);
            setText('public-ip-value', publicIP);

            const targetInput = document.getElementById('scan-target');
            if (targetInput && (!targetInput.value || targetInput.value === '192.168.1.0/24' || targetInput.value === 'Unknown')) {
                targetInput.value = cidr;
            }

            ['start-scan-btn', 'generate-report-btn', 'dragnet-scan-btn'].forEach(id => {
                const button = document.getElementById(id);
                if (!button) return;
                button.disabled = false;
                button.removeAttribute('disabled');
                button.classList.remove('opacity-50', 'opacity-90', 'ring-4', 'ring-white/50');
                button.querySelector('.scan-button-pulse')?.classList.add('hidden');
            });
            document.getElementById('quick-scan-indicator')?.classList.add('hidden');
            document.getElementById('deep-scan-indicator')?.classList.add('hidden');
            setText('scan-console-status', 'Ready to scan');

            const routePath = document.getElementById('route-path');
            if (routePath) {
                routePath.replaceChildren();
                const isPrivateIP = (ip) => {
                    const parts = String(ip).split('.').map(Number);
                    return parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
                };
                hops.forEach((hop, index) => {
                    if (index > 0) {
                        const arrow = document.createElement('span');
                        arrow.className = 'text-olive-300 mx-1';
                        arrow.textContent = '->';
                        routePath.appendChild(arrow);
                    }
                    const chip = document.createElement('span');
                    const privateHop = isPrivateIP(hop.ip);
                    chip.id = `hop-${hop.hop}`;
                    chip.className = `px-2 py-1 rounded-lg text-[10px] font-mono font-bold border ${privateHop ? 'bg-amber-100 text-amber-700 border-amber-200' : 'bg-emerald-100 text-emerald-700 border-emerald-200'} shadow-sm`;
                    chip.textContent = `${hop.hop}: ${hop.ip}`;
                    routePath.appendChild(chip);
                });
                if (!hops.length) {
                    const empty = document.createElement('span');
                    empty.className = 'italic text-olive-400';
                    empty.textContent = 'Collecting topology...';
                    routePath.appendChild(empty);
                }
                const privateCount = hops.filter(hop => isPrivateIP(hop.ip)).length;
                setText('total-hops', String(hops.length));
                setText('private-hops', String(privateCount));
                setText('public-hops', String(Math.max(0, hops.length - privateCount)));
                setText('exit-ip', hops.length ? hops[hops.length - 1].ip : '--');
            }
            window.__nmapuiNetworkSnapshotApplied = { localIP, mask, cidr, publicIP, hopCount: hops.length };
        })();
        """
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    func installNativeScanHandlers() {
        guard let webView else { return }
        RuntimeDiagnosticsLogger.log("Installing native scan handlers")
        let script = """
        (() => {
            if (!window.webkit?.messageHandlers?.nmapuiRuntime?.postMessage) return;
            window.__nmapuiNativeScanHandlersInstalledAt = new Date().toISOString();
            window.__NMAPUI_NATIVE_RUNTIME__ = true;

            const targetValue = () => document.getElementById('scan-target')?.value?.trim() || '';
            const vpnHelperValue = () => !!document.getElementById('vpn-helper-toggle')?.checked;
            const postAction = (action, scanKind, options = {}) => {
                const target = targetValue();
                window.webkit.messageHandlers.nmapuiRuntime.postMessage({
                    action,
                    target,
                    usePn: !!options.usePn,
                    vpnHelper: !!options.vpnHelper,
                    scanKind
                });
                const status = document.getElementById('scan-console-status');
                if (status) status.textContent = `Starting ${scanKind} scan for ${target || 'current target'}...`;
            };
            const bind = (id, handler) => {
                const button = document.getElementById(id);
                if (!button || button.dataset.nmapuiBound === '1') return;
                button.dataset.nmapuiBound = '1';
                button.addEventListener('click', event => {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    handler();
                }, true);
            };

            bind('start-scan-btn', () => postAction('start_quick_scan', 'quick'));
            bind('generate-report-btn', () => postAction('start_complete_scan', 'complete', { vpnHelper: vpnHelperValue() }));
            bind('dragnet-scan-btn', () => postAction('start_dragnet_scan', 'dragnet', { vpnHelper: vpnHelperValue() }));
            bind('stop-scan-btn', () => {
                window.webkit.messageHandlers.nmapuiRuntime.postMessage({ action: 'stop_scan' });
            });
        })();
        """
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    private static func hopsJSON(_ hops: [RuntimeTracerouteHop]) -> String {
        let payload = hops.map { ["hop": $0.hop, "ip": $0.ip] as [String: Any] }
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let json = String(data: data, encoding: .utf8) else {
            return "[]"
        }
        return json
    }

    private static func jsStringLiteral(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "'", with: "\\'")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
        return "'\(escaped)'"
    }
}
