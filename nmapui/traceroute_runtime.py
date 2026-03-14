from nmapui.traceroute import run_traceroute as run_traceroute_for_state


def build_traceroute_deps(
    *,
    emit_to_client,
    safe_emit,
    get_client_state,
    socketio_sleep,
    logger,
    is_private_ip,
    requests,
    set_network_key_state,
    get_customer_fingerprinter,
    merge_customer_metadata,
    set_current_customer_state,
    get_current_customer_state,
):
    return {
        "emit_to_client": emit_to_client,
        "safe_emit": safe_emit,
        "get_client_state": get_client_state,
        "socketio_sleep": socketio_sleep,
        "logger": logger,
        "is_private_ip": is_private_ip,
        "requests": requests,
        "set_network_key_state": set_network_key_state,
        "get_customer_fingerprinter": get_customer_fingerprinter,
        "merge_customer_metadata": merge_customer_metadata,
        "set_current_customer_state": set_current_customer_state,
        "get_current_customer_state": get_current_customer_state,
    }


def run_traceroute(*, target="1.1.1.1", sid=None, deps):
    return run_traceroute_for_state(target, sid=sid, deps=deps)
