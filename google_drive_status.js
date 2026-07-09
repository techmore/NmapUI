function googleDriveHelperUnavailableStatus(getGoogleDriveConfig, payload = {}) {
    return {
        success: false,
        connected: false,
        configured: false,
        status: 'Google Drive helper unavailable',
        config: getGoogleDriveConfig(),
        ...payload
    };
}

function emitGoogleDriveHelperUnavailable(socket, getGoogleDriveConfig, payload = {}) {
    socket.emit('google_drive_status', googleDriveHelperUnavailableStatus(getGoogleDriveConfig, payload));
}

function requireGoogleDriveHelper(socket, loadRuntimeCapabilities, getGoogleDriveConfig, payload = {}) {
    if (loadRuntimeCapabilities().googleDriveHelperAvailable) {
        return true;
    }
    emitGoogleDriveHelperUnavailable(socket, getGoogleDriveConfig, payload);
    return false;
}

module.exports = {
    googleDriveHelperUnavailableStatus,
    emitGoogleDriveHelperUnavailable,
    requireGoogleDriveHelper,
};
