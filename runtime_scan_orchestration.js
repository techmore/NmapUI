function startChainedScan(deps, socket, target, usePn = false, options = {}) {
    const scanKind = usePn ? 'complete' : 'quick';
    if (options.customerProfilePrefix) {
        deps.saveCustomerProfileConfig({ ...deps.customerProfileConfig(), prefix: options.customerProfilePrefix });
        const profile = deps.getCustomerFingerprintProfile();
        deps.logEvent(socket, 'settings', `Customer profile selected for scan: ${profile.prefix}.`);
        deps.io.emit('customer_profile', profile);
    }
    const orchestration = deps.runRuntimeReportHelper([
        'scan-orchestrate',
        '--target', String(target || ''),
        '--use-pn', usePn ? '1' : '0',
        '--vpn-helper', options.vpnHelper ? '1' : '0',
        '--scan-kind', scanKind
    ]);
    const normalized = deps.normalizeTargetInput(target);
    const targets = normalized.targets;
    if (targets.length === 0) {
        deps.logEvent(socket, 'error', 'No scan target provided.');
        return;
    }
    deps.scanRuntimeState.setActive(socket, {
        phase: 1,
        target: orchestration?.targetLabel || normalized.targetLabel,
        scanKind
    });
    if (orchestration?.phase1?.hosts) {
        deps.setDiscoveredHosts(orchestration.phase1.hosts.map(host => ({
            ip: host.ip,
            status: 'up',
            hostname: host.hostname || ''
        })).filter(host => host.ip));
        deps.io.emit('phase_complete', { phase: 1, duration: orchestration.phase1.duration || '0.00', ...deps.getScanStats() });
        if (orchestration.phase2?.summary) {
            deps.scanRuntimeState.setPhase(socket, 3);
            const summary = orchestration.phase2.summary;
            deps.setDiscoveredHosts(deps.discoveredHosts().map(host => {
                const parsed = summary.hosts.find(item => item.ip === host.ip);
                return parsed ? { ...host, ...parsed } : host;
            }));
            deps.io.emit('phase_stats', { phase: 2, ...summary });
            deps.generateReportFromXml(socket, deps.workDir, orchestration.phase2.duration || '0.00', scanKind, () => {
                deps.io.emit('scan_complete', { phase: 3, duration: orchestration.phase2.duration || '0.00', ...deps.getScanStats() });
                deps.scanRuntimeState.clear(socket);
            });
            return;
        }
        deps.logEvent(socket, 'error', 'Swift scan orchestration completed phase 1 but phase 2 summary was unavailable.');
        deps.scanRuntimeState.clear(socket);
        return;
    }
    deps.scanRuntimeState.clear(socket);
    deps.logEvent(socket, 'error', 'Swift phase 1 scan failed and Node fallback is disabled in Swift-managed mode.');
}

function runTraceroute(deps) {
    if (deps.isTracerouteRunning()) return;
    deps.setTracerouteRunning(true);
    const helperResult = deps.runRuntimeReportHelper(['traceroute']);
    if (!helperResult) {
        deps.setCachedHops([]);
        deps.setTracerouteRunning(false);
        return;
    }
    const hops = Array.isArray(helperResult?.tracerouteHops) ? helperResult.tracerouteHops : [];
    deps.setCachedHops(hops);
    hops.forEach(hop => {
        deps.io.emit('traceroute_hop', { hop: hop.hop, ip: hop.ip });
    });
    deps.setTracerouteRunning(false);
}

module.exports = {
    startChainedScan,
    runTraceroute,
};
