function registerDataHandlers(socket, deps) {
    socket.on('get_history', () => socket.emit('history_data', deps.loadJSON(deps.historyPath, [])));
    socket.on('get_customer_profile', () => socket.emit('customer_profile', deps.getRuntimeBootstrapSnapshot().customerProfile));
    socket.on('get_google_drive_status', async () => {
        if (!deps.requireGoogleDriveHelper(socket)) return;
        const status = await deps.runGoogleDriveHelper(['status'], deps.dataDir);
        if (status.connected && !deps.getGoogleDriveConfig().enabled) {
            deps.saveGoogleDriveConfig({ enabled: true });
            deps.logEvent(socket, 'settings', 'Google Drive connection found; sync enabled on server.');
        }
        socket.emit('google_drive_status', { ...status, config: deps.getGoogleDriveConfig() });
    });
    socket.on('save_google_drive_credentials', async (data = {}) => {
        if (!deps.requireGoogleDriveHelper(socket)) return;
        const result = await deps.runGoogleDriveHelper(['save-credentials'], deps.dataDir, data.credentialsJson || '');
        const googleDrive = result.success ? deps.saveGoogleDriveConfig({ enabled: true }) : deps.getGoogleDriveConfig();
        if (result.success) deps.logEvent(socket, 'settings', 'Google Drive credentials imported and sync enabled.');
        socket.emit('google_drive_status', { ...result, config: googleDrive });
    });
    socket.on('connect_google_drive', async () => {
        if (!deps.requireGoogleDriveHelper(socket)) {
            socket.emit('google_drive_auth_url', {
                success: false,
                error: 'Google Drive helper unavailable'
            });
            return;
        }
        const result = await deps.runGoogleDriveHelper(['auth-url', '--redirect-uri', deps.getGoogleDriveRedirectUri()], deps.dataDir);
        socket.emit('google_drive_auth_url', result);
    });
    socket.on('disconnect_google_drive', async () => {
        if (!deps.requireGoogleDriveHelper(socket)) {
            const googleDrive = deps.saveGoogleDriveConfig({ enabled: false });
            deps.emitGoogleDriveHelperUnavailable(socket, { config: googleDrive });
            return;
        }
        const result = await deps.runGoogleDriveHelper(['disconnect'], deps.dataDir);
        const googleDrive = deps.saveGoogleDriveConfig({ enabled: false });
        if (result.success) deps.logEvent(socket, 'settings', 'Google Drive disconnected and sync disabled.');
        socket.emit('google_drive_status', { ...result, config: googleDrive });
    });
    socket.on('save_google_drive_settings', (data = {}) => {
        const googleDrive = deps.saveGoogleDriveConfig({
            enabled: !!data.enabled,
            folderId: data.folderId || ''
        });
        socket.emit('google_drive_status', { success: true, status: 'Google Drive settings saved', config: googleDrive });
    });
    socket.on('get_reports', () => {
        socket.emit('reports_data', deps.buildReportsSnapshot().reports);
    });
}

module.exports = {
    registerDataHandlers,
};
