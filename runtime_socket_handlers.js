function registerSocketHandlers(socket, deps) {
    require('./runtime_socket_bootstrap_handlers').registerBootstrapHandlers(socket, deps);
    require('./runtime_socket_scan_handlers').registerScanHandlers(socket, deps);
    require('./runtime_socket_settings_handlers').registerSettingsHandlers(socket, deps);
    require('./runtime_socket_data_handlers').registerDataHandlers(socket, deps);
}

module.exports = {
    registerSocketHandlers
};
