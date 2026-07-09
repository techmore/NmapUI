const assert = require('assert');
const {
    googleDriveHelperUnavailableStatus,
    emitGoogleDriveHelperUnavailable,
    requireGoogleDriveHelper,
} = require('../google_drive_status');

const emitted = [];
const socket = { emit: (event, payload) => emitted.push({ event, payload }) };
const getGoogleDriveConfig = () => ({ enabled: true, folderId: 'abc123' });
const loadRuntimeCapabilities = () => ({ googleDriveHelperAvailable: false });
const loadRuntimeCapabilitiesAvailable = () => ({ googleDriveHelperAvailable: true });

const unavailable = googleDriveHelperUnavailableStatus(getGoogleDriveConfig, { extra: 'value' });
assert.deepStrictEqual(unavailable, {
    success: false,
    connected: false,
    configured: false,
    status: 'Google Drive helper unavailable',
    config: { enabled: true, folderId: 'abc123' },
    extra: 'value'
});

emitGoogleDriveHelperUnavailable(socket, getGoogleDriveConfig, { extra: 'value' });
assert.deepStrictEqual(emitted[0], {
    event: 'google_drive_status',
    payload: unavailable
});

assert.strictEqual(requireGoogleDriveHelper(socket, loadRuntimeCapabilities, getGoogleDriveConfig), false);
assert.deepStrictEqual(emitted[1], {
    event: 'google_drive_status',
    payload: {
        success: false,
        connected: false,
        configured: false,
        status: 'Google Drive helper unavailable',
        config: { enabled: true, folderId: 'abc123' }
    }
});

assert.strictEqual(requireGoogleDriveHelper(socket, loadRuntimeCapabilitiesAvailable, getGoogleDriveConfig), true);
assert.strictEqual(emitted.length, 2);

console.log('google_drive_helper_unavailable self-test passed');
