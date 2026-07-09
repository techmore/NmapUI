function registerBootstrapHandlers(socket, deps) {
    socket.on('get_initial_data', async () => {
        const runtimeState = deps.getRuntimeBootstrapSnapshot();
        const network = runtimeState.network && Object.keys(runtimeState.network).length > 0 ? runtimeState.network : await deps.getNetworkInfo();
        const publicIP = runtimeState.publicIP || await deps.getPublicIP();
        socket.emit('initial_data', { ...network, publicIP, customerProfile: runtimeState.customerProfile, googleDrive: runtimeState.googleDrive, autoScan: runtimeState.autoScan });
        if (deps.cachedHops.length === 0 && !deps.isTracerouteRunning()) deps.runTraceroute();
        deps.cachedHops.forEach(hop => socket.emit('traceroute_hop', hop));
    });
}

module.exports = {
    registerBootstrapHandlers,
};
