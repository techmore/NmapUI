let lastScanTarget = '';
let lastScanResults = {};
let reportTimerInterval = null;
let reportStartTime = 0;
let reportSocket = null;
let reportGetClientJobs = () => ({ report: { status: 'idle' } });
let reportGenerationInitialized = false;
let reportActionPending = false;

function resetReportVisualState() {
    reportActionPending = false;
    setReportButtonsPulsing(false);
    if (typeof window.removeReportProgressCard === 'function') {
        window.removeReportProgressCard();
    }
    stopReportTimer();
}

function startReportTimer(startedAt = null) {
    const container = document.getElementById('scan-timer-container');
    const display = document.getElementById('scan-timer');
    const feedbackBox = document.getElementById('feedback-container');

    container.classList.remove('hidden');
    feedbackBox.classList.add('card-pulsing');
    const startedAtMillis = startedAt ? Date.parse(startedAt) : Number.NaN;
    reportStartTime = Number.isNaN(startedAtMillis) ? Date.now() : startedAtMillis;

    const renderElapsed = () => {
        const elapsed = Math.max(Math.floor((Date.now() - reportStartTime) / 1000), 0);
        const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const secs = (elapsed % 60).toString().padStart(2, '0');
        display.textContent = `${mins}:${secs}`;
    };

    if (reportTimerInterval) clearInterval(reportTimerInterval);
    renderElapsed();

    reportTimerInterval = setInterval(() => {
        renderElapsed();
    }, 1000);
}

function stopReportTimer() {
    const feedbackBox = document.getElementById('feedback-container');
    const timerContainer = document.getElementById('scan-timer-container');

    if (reportTimerInterval) {
        clearInterval(reportTimerInterval);
        reportTimerInterval = null;
    }

    feedbackBox.classList.remove('card-pulsing');

    setTimeout(() => {
        timerContainer.classList.add('hidden');
        feedbackBox.innerHTML = '';
        feedbackBox.parentElement.classList.add('hidden');
    }, 5000);
}

function setLastScanTarget(target) {
    lastScanTarget = target;
}

function getLastScanTarget() {
    return lastScanTarget;
}

function updateLastScanResults(key, data) {
    lastScanResults[key] = data;
}

function setReportButtonsPulsing(active, chunked = false) {
    const completeButton = document.getElementById('generate-report-btn');
    const chunkedButton = document.getElementById('chunked-scan-btn');
    if (completeButton) {
        completeButton.classList.toggle('card-pulsing', active && !chunked);
    }
    if (chunkedButton) {
        chunkedButton.classList.toggle('card-pulsing', active && chunked);
    }
}

function syncReportJobVisualState(job) {
    const isRunning = job?.status === 'running' || job?.status === 'cancelling';
    const chunked = !!job?.details?.chunked;
    if (!isRunning) {
        resetReportVisualState();
        return;
    }

    reportActionPending = true;
    setReportButtonsPulsing(true, chunked);
    startReportTimer(job?.started_at || null);
}

function getReportRequestContext() {
    const target = document.getElementById('scan-target').value || lastScanTarget;
    const customerOption = document.getElementById('current-customer').selectedOptions[0];
    let customerName = 'Unknown';

    if (customerOption) {
        customerName = customerOption.textContent.split(' (')[0];
    }

    return { target, customerName };
}

function initializeReportGenerationUI(socket, deps) {
    if (reportGenerationInitialized) {
        return;
    }
    reportGenerationInitialized = true;
    reportSocket = socket;
    reportGetClientJobs = deps?.getClientJobs || window.getClientJobs || reportGetClientJobs;

    socket.on('scan_results', function(data) {
        updateLastScanResults('quickScan', data);
    });

    socket.on('deep_scan_results', function(data) {
        updateLastScanResults('deepScan', data);
    });

    socket.on('arp_results', function(data) {
        updateLastScanResults('arpScan', data);
    });

    socket.on('client_state_snapshot', function(data) {
        const target = data?.last_scan_target;
        if (!target) {
            return;
        }
        setLastScanTarget(target);
        const targetInput = document.getElementById('scan-target');
        if (targetInput && !targetInput.value) {
            targetInput.value = target;
        }
    });

    socket.on('job_status', function(data) {
        if (data?.job_type !== 'report') {
            return;
        }
        syncReportJobVisualState(data);
    });

    socket.on('report_complete', function() {
        resetReportVisualState();
    });

    socket.on('report_error', function() {
        resetReportVisualState();
    });

    document.getElementById('generate-report-btn').addEventListener('click', function() {
        if (reportActionPending || reportGetClientJobs().report.status === 'running') {
            return;
        }

        const { target, customerName } = getReportRequestContext();
        if (!target) {
            showReportStatus('Please enter a target or run a scan first', 'error');
            return;
        }

        reportActionPending = true;
        setReportButtonsPulsing(true, false);
        startReportTimer();

        reportSocket.emit('generate_report', {
            target: target,
            customer_name: customerName,
            scan_results: lastScanResults,
            chunked: false
        });
    });

    document.getElementById('chunked-scan-btn')?.addEventListener('click', function() {
        if (reportActionPending || reportGetClientJobs().report.status === 'running') {
            return;
        }

        const { target, customerName } = getReportRequestContext();
        if (!target) {
            showReportStatus('Please enter a target or run a scan first', 'error');
            return;
        }

        reportActionPending = true;
        setReportButtonsPulsing(true, true);
        startReportTimer();

        reportSocket.emit('generate_report', {
            target: target,
            customer_name: customerName,
            scan_results: lastScanResults,
            chunked: true
        });
    });

    document.getElementById('start-scan-btn').addEventListener('click', function() {
        setLastScanTarget(document.getElementById('scan-target').value);
    });
}

window.startReportTimer = startReportTimer;
window.stopReportTimer = stopReportTimer;
window.setLastScanTarget = setLastScanTarget;
window.getLastScanTarget = getLastScanTarget;
window.updateLastScanResults = updateLastScanResults;
window.syncReportJobVisualState = syncReportJobVisualState;
window.initializeReportGenerationUI = initializeReportGenerationUI;
