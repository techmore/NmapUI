var socket = io.connect(`http://${document.domain}:${location.port}`);
window.socket = socket;
socket.on('connect', () => console.log('Socket.IO connected'));

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
