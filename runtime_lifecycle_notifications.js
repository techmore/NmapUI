function createRuntimeLifecycleNotifications(io) {
    function emitReportsRefresh() {
        io.emit('reports_refresh');
    }

    function emitScanComplete(payload) {
        io.emit('scan_complete', payload);
    }

    return {
        emitReportsRefresh,
        emitScanComplete,
    };
}

module.exports = {
    createRuntimeLifecycleNotifications,
};
