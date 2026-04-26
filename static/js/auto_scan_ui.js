function initializeAutoScanUI(socket) {
    const autoScanToggle = document.getElementById('auto-scan-toggle');
    const autoScanModal = document.getElementById('auto-scan-modal');
    const recurrenceInput = document.getElementById('auto-recurrence');
    const startTimeInput = document.getElementById('auto-start-time');
    if (!autoScanToggle || !autoScanModal) return;

    window.currentAutoScanConfig = window.currentAutoScanConfig || {};

    function applyAutoScanConfig(config = {}) {
        window.currentAutoScanConfig = config || {};
        autoScanToggle.checked = !!config.enabled;
        if (recurrenceInput) recurrenceInput.value = config.recurrence || 'daily';
        if (startTimeInput) startTimeInput.value = config.startTime || '01:00';
    }
    
    autoScanToggle.addEventListener('change', () => {
        if (autoScanToggle.checked) {
            autoScanModal.classList.remove('hidden');
        } else {
            socket.emit('disable_auto_scan');
        }
    });

    socket.on('sync_state', (state = {}) => applyAutoScanConfig(state.autoScan));
    socket.on('initial_data', (data = {}) => applyAutoScanConfig(data.autoScan));
    socket.on('auto_scan_config', applyAutoScanConfig);
}

function saveAutoScanTimes() {
    const recurrence = document.getElementById('auto-recurrence').value;
    const startTime = document.getElementById('auto-start-time').value;
    const target = document.getElementById('scan-target').value;

    window.socket.emit('enable_auto_scan', { recurrence, startTime, target });
    document.getElementById('auto-scan-modal').classList.add('hidden');
}

function saveAndRunScan() {
    saveAutoScanTimes();
    const target = document.getElementById('scan-target').value;
    window.socket.emit('start_complete_scan', { target, scanKind: 'complete' });
}

function hideAutoScanTimeModal() {
    document.getElementById('auto-scan-modal').classList.add('hidden');
    document.getElementById('auto-scan-toggle').checked = !!window.currentAutoScanConfig?.enabled;
}
