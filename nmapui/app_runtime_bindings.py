from nmapui.app_state_runtime import (
    get_report_counts as get_report_counts_runtime,
    load_current_assignment as load_current_assignment_runtime,
    save_current_assignment as save_current_assignment_runtime,
    save_customers_config as save_customers_config_runtime,
)
from nmapui.traceroute_runtime import (
    build_traceroute_deps,
    run_traceroute as run_traceroute_runtime,
)


def build_state_bindings(
    *,
    current_assignment_file,
    current_customer,
    scans_dir,
    normalize_current_assignment_document,
    normalize_scan_metadata_document,
    load_json_document,
    save_json_document,
    save_yaml_document,
    get_customer_fingerprinter,
    merge_customer_metadata,
    client_state_registry,
    get_current_customer_state,
    logger,
):
    def get_report_counts():
        return get_report_counts_runtime(
            scans_dir=scans_dir,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
        )

    def save_customers_config():
        save_customers_config_runtime(
            get_customer_fingerprinter=get_customer_fingerprinter,
            save_yaml_document=save_yaml_document,
            logger=logger,
        )

    def save_current_assignment(sid=None):
        save_current_assignment_runtime(
            current_assignment_file=current_assignment_file,
            get_current_customer_state=get_current_customer_state,
            save_json_document=save_json_document,
            logger=logger,
            sid=sid,
        )

    def load_current_assignment():
        return load_current_assignment_runtime(
            current_assignment_file=current_assignment_file,
            current_customer=current_customer,
            normalize_current_assignment_document=normalize_current_assignment_document,
            load_json_document=load_json_document,
            get_customer_fingerprinter=get_customer_fingerprinter,
            merge_customer_metadata=merge_customer_metadata,
            client_state_registry=client_state_registry,
            logger=logger,
        )

    return {
        "get_report_counts": get_report_counts,
        "save_customers_config": save_customers_config,
        "save_current_assignment": save_current_assignment,
        "load_current_assignment": load_current_assignment,
    }


def build_traceroute_bindings(
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
    def traceroute_deps():
        return build_traceroute_deps(
            emit_to_client=emit_to_client,
            safe_emit=safe_emit,
            get_client_state=get_client_state,
            socketio_sleep=socketio_sleep,
            logger=logger,
            is_private_ip=is_private_ip,
            requests=requests,
            set_network_key_state=set_network_key_state,
            get_customer_fingerprinter=get_customer_fingerprinter,
            merge_customer_metadata=merge_customer_metadata,
            set_current_customer_state=set_current_customer_state,
            get_current_customer_state=get_current_customer_state,
        )

    def run_traceroute(target="1.1.1.1", sid=None):
        return run_traceroute_runtime(target=target, sid=sid, deps=traceroute_deps())

    return {
        "traceroute_deps": traceroute_deps,
        "run_traceroute": run_traceroute,
    }
