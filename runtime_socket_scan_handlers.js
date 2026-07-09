function registerScanHandlers(socket, deps) {
    socket.on('start_quick_scan', (data) => deps.startChainedScan(socket, data.target, false, { customerProfilePrefix: data.customerProfilePrefix || '' }));
    socket.on('start_complete_scan', (data) => deps.startChainedScan(socket, data.target, true, { vpnHelper: !!data.vpnHelper, customerProfilePrefix: data.customerProfilePrefix || '' }));
    socket.on('start_dragnet_scan', (data) => {
        if (deps.discoveredHosts().length === 0) { deps.logEvent(socket, 'error', 'No hosts discovered in Phase 1.'); return; }
        deps.scanRuntimeState.setActive(socket, {
            phase: 3,
            target: deps.discoveredHosts().map(h => h.ip).join(', '),
            scanKind: 'dragnet'
        });
        const orchestration = deps.runRuntimeReportHelper([
            'scan-orchestrate',
            '--target', deps.discoveredHosts().map(h => h.ip).join('\n'),
            '--scan-kind', 'dragnet'
        ]);
        if (orchestration?.phase2?.summary) {
            deps.setDiscoveredHosts(deps.discoveredHosts().map(host => {
                const parsed = orchestration.phase2.summary.hosts.find(item => item.ip === host.ip);
                return parsed ? { ...host, ...parsed } : host;
            }));
            deps.io.emit('phase_stats', { phase: 3, ...orchestration.phase2.summary });
            deps.generateReportFromXml(socket, deps.workDir, orchestration.phase2.duration || '0.00', 'dragnet', () => {
                deps.io.emit('scan_complete', { phase: 3, duration: orchestration.phase2.duration || '0.00', ...deps.getScanStats(), status: 'complete' });
                deps.scanRuntimeState.clear(socket);
            });
            return;
        }
        deps.logEvent(socket, 'error', 'Swift dragnet scan failed and Node fallback is disabled in Swift-managed mode.');
    });
    socket.on('stop_scan', () => {
        deps.scanRuntimeState.clear(socket);
        socket.emit('scan_stopped');
    });
}

module.exports = {
    registerScanHandlers,
};
