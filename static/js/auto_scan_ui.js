let autoScanEnabled = false;
let autoScanStartTime = '01:00';
let autoScanEndTime = '06:00';
let autoScanSocket = null;
let getClientJobs = null;
let getLastScanTarget = null;

function showAutoScanTimeModal() {
    const modal = document.getElementById('auto-scan-modal');
    modal.classList.remove('hidden');

    document.getElementById('auto-start-time').value = autoScanStartTime;
    document.getElementById('auto-end-time').value = autoScanEndTime;
}

function hideAutoScanTimeModal() {
    document.getElementById('auto-scan-modal').classList.add('hidden');
}

function updateAutoScanWindow(startTime, endTime, visible) {
    const windowEl = document.getElementById('auto-scan-window');
    if (windowEl && startTime && endTime) {
        windowEl.textContent = `${startTime} to ${endTime}`;
    }

    const timesDiv = document.getElementById('auto-scan-times');
    if (timesDiv) {
        timesDiv.classList.toggle('hidden', !visible);
    }
}

function saveAutoScanTimes() {
    const startTime = document.getElementById('auto-start-time').value;
    const endTime = document.getElementById('auto-end-time').value;

    if (!startTime || !endTime) {
        showReportStatus('Please select both start and end times', 'error');
        return;
    }

    autoScanStartTime = startTime;
    autoScanEndTime = endTime;
    updateAutoScanWindow(startTime, endTime, true);

    autoScanSocket.emit('update_auto_scan', {
        enabled: true,
        start_time: startTime,
        end_time: endTime
    });

    hideAutoScanTimeModal();
    showReportStatus(`Automatic scanning enabled: ${startTime} to ${endTime}`, 'success');
}

function saveAndRunScan() {
    const jobs = getClientJobs();
    if (jobs.report.status === 'running') {
        showReportStatus('A report job is already running', 'error');
        return;
    }

    const startTime = document.getElementById('auto-start-time').value;
    const endTime = document.getElementById('auto-end-time').value;

    if (!startTime || !endTime) {
        showReportStatus('Please select both start and end times', 'error');
        return;
    }

    hideAutoScanTimeModal();

    autoScanStartTime = startTime;
    autoScanEndTime = endTime;
    updateAutoScanWindow(startTime, endTime, true);

    autoScanSocket.emit('update_auto_scan', {
        enabled: true,
        start_time: startTime,
        end_time: endTime
    });

    hideAutoScanTimeModal();
    showReportStatus(`Automatic scanning enabled: ${startTime} to ${endTime}`, 'success');

    const target = document.getElementById('scan-target').value || getLastScanTarget() || '127.0.0.1';
    const customerOption = document.getElementById('current-customer').selectedOptions[0];
    let customerName = 'Auto Scan';

    if (customerOption) {
        customerName = customerOption.text.split(' (')[0];
    }

    console.log('About to emit generate_report with target:', target, 'customer:', customerName);
    console.log('Socket connected:', autoScanSocket.connected);
    showReportStatus(`Starting scan of ${target}...`, 'info');

    autoScanSocket.emit('generate_report', {
        target: target,
        customer_name: customerName
    });
    console.log('generate_report emitted');
}

function initializeAutoScanUI(socket, deps) {
    autoScanSocket = socket;
    getClientJobs = deps.getClientJobs;
    getLastScanTarget = deps.getLastScanTarget;

    document.getElementById('auto-scan-toggle').addEventListener('change', function() {
        autoScanEnabled = this.checked;

        if (autoScanEnabled) {
            showAutoScanTimeModal();
        } else {
            updateAutoScanWindow(autoScanStartTime, autoScanEndTime, false);
            autoScanSocket.emit('update_auto_scan', { enabled: false });
            showReportStatus('Automatic scanning disabled', 'info');
        }
    });

    socket.on('auto_scan_status', function(status) {
        autoScanEnabled = status.enabled || false;
        document.getElementById('auto-scan-toggle').checked = autoScanEnabled;

        if (status.start_time && status.end_time) {
            autoScanStartTime = status.start_time;
            autoScanEndTime = status.end_time;
            updateAutoScanWindow(status.start_time, status.end_time, true);
        } else {
            updateAutoScanWindow(autoScanStartTime, autoScanEndTime, false);
        }
    });

    socket.on('auto_scan_error', function(data) {
        showReportStatus(`Automatic scan error: ${data.error}`, 'error');
    });
}

window.showAutoScanTimeModal = showAutoScanTimeModal;
window.hideAutoScanTimeModal = hideAutoScanTimeModal;
window.saveAutoScanTimes = saveAutoScanTimes;
window.saveAndRunScan = saveAndRunScan;
window.initializeAutoScanUI = initializeAutoScanUI;
