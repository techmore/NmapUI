function createNativeSocketShim() {
    const listeners = new Map();
    const emitNative = (event, payload = {}) => {
        if (window.webkit?.messageHandlers?.nmapuiRequest?.postMessage) {
            window.webkit.messageHandlers.nmapuiRequest.postMessage({ event, payload });
            return true;
        }
        return false;
    };
    return {
        connected: true,
        id: 'native-runtime',
        on(event, handler) {
            const existing = listeners.get(event) || [];
            existing.push(handler);
            listeners.set(event, existing);
        },
        once(event, handler) {
            const wrapped = (payload) => {
                this.off(event, wrapped);
                handler(payload);
            };
            this.on(event, wrapped);
        },
        off(event, handler) {
            if (!listeners.has(event)) return;
            listeners.set(event, (listeners.get(event) || []).filter(item => item !== handler));
        },
        emit(event, payload = {}) {
            return emitNative(event, payload);
        },
        __receive(event, payload) {
            (listeners.get(event) || []).forEach(handler => {
                try { handler(payload); } catch (error) { console.warn(`Native socket handler failed for ${event}`, error); }
            });
        },
        connect() {
            (listeners.get('connect') || []).forEach(handler => {
                try { handler(); } catch (error) { console.warn('Native socket connect handler failed', error); }
            });
        }
    };
}

const useNativeRuntime = !!window.__NMAPUI_NATIVE_RUNTIME__ || !!window.webkit?.messageHandlers?.nmapuiRequest;
var socket = useNativeRuntime ? createNativeSocketShim() : io.connect(`http://${document.domain}:${location.port}`);
window.socket = socket;
if (!useNativeRuntime) {
    socket.on('connect', () => console.log('Socket.IO connected'));
} else {
    queueMicrotask(() => socket.connect());
}

document.addEventListener('DOMContentLoaded', () => {
    if (typeof initializeScanRuntime === 'function') {
        initializeScanRuntime(socket);
    }
    if (typeof initializeDiscoveryUI === 'function') {
        initializeDiscoveryUI(socket);
    }
    if (typeof TableSorter === 'function') {
        window.tableSorter = new TableSorter('discovery-table');
    }
    if (typeof initializeSiteChrome === 'function') {
        initializeSiteChrome();
    }
    if (typeof initializeUpdateModal === 'function') {
        initializeUpdateModal(socket, {
            showReportStatus: window.showReportStatus
        });
    }
    if (typeof initializeAutoUpdateBanner === 'function') {
        initializeAutoUpdateBanner(socket);
    }
    if (typeof initializeLayoutRuntime === 'function') {
        initializeLayoutRuntime();
    }
    if (typeof initializeReportsTab === 'function') {
        initializeReportsTab();
    }
    if (typeof initializeSettingsTab === 'function') {
        initializeSettingsTab(socket);
    }
    if (typeof initializeAutoScanUI === 'function') {
        initializeAutoScanUI(socket, {
            getClientJobs: window.getClientJobs,
            getLastScanTarget: window.getLastScanTarget
        });
    }
    if (typeof initializeReportGenerationUI === 'function') {
        initializeReportGenerationUI(socket, {
            getClientJobs: window.getClientJobs
        });
    }
    if (typeof initializeCustomerUI === 'function') {
        initializeCustomerUI(socket);
    }
    if (typeof initializeAuditLog === 'function') {
        initializeAuditLog();
    }

    const reloadLastScanBtn = document.getElementById('reload-last-scan-btn');
    if (reloadLastScanBtn) {
        reloadLastScanBtn.addEventListener('click', function() {
            if (typeof loadHostsFromStorage === 'function' && !loadHostsFromStorage()) {
                if (window.currentMatchedCustomerId && window.currentMatchedCustomerId !== 'unknown') {
                    socket.emit('resume_from_last_scan', {
                        customer_id: window.currentMatchedCustomerId,
                        max_days: 30
                    });
                }
            }
        });
    }
});
