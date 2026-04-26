function initializeAutoScanUI(socket) {
    const autoScanToggle = document.getElementById('auto-scan-toggle');
    const autoScanModal = document.getElementById('auto-scan-modal');
    
    autoScanToggle.addEventListener('change', () => {
        if (autoScanToggle.checked) {
            autoScanModal.classList.remove('hidden');
        } else {
            socket.emit('disable_auto_scan');
        }
    });
}

function saveAutoScanTimes() {
    const startTime = document.getElementById('auto-start-time').value;
    const endTime = document.getElementById('auto-end-time').value;
    const target = document.getElementById('scan-target').value;

    window.socket.emit('enable_auto_scan', { startTime, endTime, target });
    document.getElementById('auto-scan-modal').classList.add('hidden');
    alert('Auto-scan enabled daily between ' + startTime + ' and ' + endTime);
}

function hideAutoScanTimeModal() {
    document.getElementById('auto-scan-modal').classList.add('hidden');
    document.getElementById('auto-scan-toggle').checked = false;
}
