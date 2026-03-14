from flask import request
from flask_socketio import emit


def register_runtime_info_handlers(socketio, deps):
    calculate_cidr = deps["calculate_cidr"]
    get_client_state = deps["get_client_state"]
    get_default_interface_cached = deps["get_default_interface_cached"]
    get_report_counts = deps["get_report_counts"]
    logger = deps["logger"]
    netifaces = deps["netifaces"]
    requests = deps["requests"]
    run_traceroute = deps["run_traceroute"]

    @socketio.on("get_history_counts")
    def get_history_counts_event():
        emit("history_counts", get_report_counts())

    @socketio.on("get_network_key")
    def get_network_key_event():
        client_network_key = get_client_state(request.sid)["network_key"]
        if client_network_key.get("total_hops", 0) == 0:
            logger.info("Network key empty for %s, running traceroute...", request.sid)
            client_network_key = run_traceroute("1.1.1.1", sid=request.sid)

        logger.info(
            "Sending network_key to client: %s hops",
            client_network_key.get("total_hops", 0),
        )
        emit("network_key", client_network_key)

    @socketio.on("get_local_ip")
    def get_local_ip():
        try:
            interface = get_default_interface_cached()
            local_ip, subnet_mask = (
                netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["addr"],
                netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["netmask"],
            )
            public_ip, cidr = (
                requests.get("https://api.ipify.org").text,
                calculate_cidr(local_ip, subnet_mask),
            )
            emit(
                "local_ip",
                {
                    "local_ip": local_ip,
                    "subnet_mask": subnet_mask,
                    "public_ip": public_ip,
                    "cidr": cidr,
                    "interface": interface,
                },
            )
        except Exception as e:
            logger.error(f"Failed to get local IP: {e}")
            emit("scan_error", f"Failed to get local IP: {str(e)}")
