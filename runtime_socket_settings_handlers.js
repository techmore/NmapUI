function registerSettingsHandlers(socket, deps) {
    socket.on('enable_auto_scan', (data = {}) => {
        const autoScan = deps.saveAutoScanConfig({
            enabled: true,
            recurrence: ['hourly', 'daily', 'weekly', 'monthly'].includes(data.recurrence) ? data.recurrence : 'daily',
            startTime: data.startTime || '01:00',
            target: data.target || deps.cachedNetworkInfo()?.cidr || '192.168.1.0/24'
        });
        deps.logEvent(socket, 'settings', `Auto-monitor enabled: ${autoScan.recurrence} at ${autoScan.startTime} for ${autoScan.target}.`);
        deps.io.emit('auto_scan_config', autoScan);
    });
    socket.on('disable_auto_scan', () => {
        const autoScan = deps.saveAutoScanConfig({ enabled: false });
        deps.logEvent(socket, 'settings', 'Auto-monitor disabled.');
        deps.io.emit('auto_scan_config', autoScan);
    });
    socket.on('set_customer_profile_prefix', (data = {}) => {
        deps.saveCustomerProfileConfig({ ...deps.customerProfileConfig(), prefix: data.prefix || 'CSP' });
        const profile = deps.getRuntimeBootstrapSnapshot().customerProfile;
        deps.logEvent(socket, 'settings', `Customer fingerprint prefix set to ${profile.prefix}.`);
        deps.io.emit('customer_profile', profile);
    });
}

module.exports = {
    registerSettingsHandlers,
};
