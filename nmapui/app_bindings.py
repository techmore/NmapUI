from nmapui.app_client_state_runtime import (
    get_client_state as get_client_state_runtime,
    get_current_customer_state as get_current_customer_state_runtime,
    release_client_state as release_client_state_runtime,
    set_current_customer_state as set_current_customer_state_runtime,
    set_last_scan_target_state as set_last_scan_target_state_runtime,
    set_network_key_state as set_network_key_state_runtime,
)
from nmapui.app_events_runtime import (
    emit_job_status as emit_job_status_runtime,
    emit_to_client as emit_to_client_runtime,
    ensure_job_not_cancelled as ensure_job_not_cancelled_runtime,
    run_cancellable_command as run_cancellable_command_runtime,
    update_job_progress as update_job_progress_runtime,
)


def build_event_helpers(*, socketio, job_registry):
    def emit_to_client(sid, event, data=None):
        return emit_to_client_runtime(socketio=socketio, sid=sid, event=event, data=data)

    def emit_job_status(sid, job_type):
        return emit_job_status_runtime(
            socketio=socketio,
            job_registry=job_registry,
            sid=sid,
            job_type=job_type,
        )

    def update_job_progress(
        sid,
        job_type,
        phase,
        message=None,
        progress=None,
        details=None,
    ):
        return update_job_progress_runtime(
            socketio=socketio,
            job_registry=job_registry,
            sid=sid,
            job_type=job_type,
            phase=phase,
            message=message,
            progress=progress,
            details=details,
        )

    def ensure_job_not_cancelled(sid, job_type):
        return ensure_job_not_cancelled_runtime(
            job_registry=job_registry,
            sid=sid,
            job_type=job_type,
        )

    def run_cancellable_command(cmd, sid=None, job_type=None, timeout=None):
        return run_cancellable_command_runtime(
            job_registry=job_registry,
            cmd=cmd,
            sid=sid,
            job_type=job_type,
            timeout=timeout,
        )

    return {
        "emit_to_client": emit_to_client,
        "emit_job_status": emit_job_status,
        "update_job_progress": update_job_progress,
        "ensure_job_not_cancelled": ensure_job_not_cancelled,
        "run_cancellable_command": run_cancellable_command,
    }


def build_client_state_helpers(
    *,
    client_state_registry,
    get_current_customer,
    get_network_key,
    get_last_scan_target,
    set_default_customer,
    set_default_network_key,
    set_default_last_scan_target,
    runtime_store=None,
):
    def persist_snapshot(key, payload):
        if runtime_store is None:
            return
        runtime_store.upsert_runtime_snapshot(key, payload)

    def get_client_state(*, sid=None):
        return get_client_state_runtime(
            sid=sid,
            client_state_registry=client_state_registry,
            current_customer=get_current_customer(),
            network_key=get_network_key(),
            last_scan_target=get_last_scan_target(),
        )

    def get_current_customer_state(sid=None):
        return get_current_customer_state_runtime(
            sid=sid,
            get_client_state=get_client_state,
        )

    def set_current_customer_state(value, sid=None):
        result = set_current_customer_state_runtime(
            value=value,
            sid=sid,
            client_state_registry=client_state_registry,
            set_default_customer=set_default_customer,
            sync_default_state=(
                (lambda customer: (set_default_customer(customer), client_state_registry.set_default_customer(customer)))
                if sid is not None
                else None
            ),
        )
        persist_snapshot("current_customer", result)
        return result

    def set_network_key_state(value, sid=None):
        result = set_network_key_state_runtime(
            value=value,
            sid=sid,
            client_state_registry=client_state_registry,
            set_default_network_key=set_default_network_key,
            sync_default_state=(
                (lambda key: (set_default_network_key(key), client_state_registry.set_default_network_key(key)))
                if sid is not None
                else None
            ),
        )
        persist_snapshot("network_key", result)
        return result

    def set_last_scan_target_state(value, sid=None):
        result = set_last_scan_target_state_runtime(
            value=value,
            sid=sid,
            client_state_registry=client_state_registry,
            set_default_last_scan_target=set_default_last_scan_target,
            sync_default_state=(
                (lambda target: (set_default_last_scan_target(target), client_state_registry.set_default_last_scan_target(target)))
                if sid is not None
                else None
            ),
        )
        persist_snapshot("last_scan_target", {"value": result})
        return result

    def release_client_state(sid):
        return release_client_state_runtime(
            sid=sid,
            client_state_registry=client_state_registry,
        )

    return {
        "get_client_state": get_client_state,
        "get_current_customer_state": get_current_customer_state,
        "set_current_customer_state": set_current_customer_state,
        "set_network_key_state": set_network_key_state,
        "set_last_scan_target_state": set_last_scan_target_state,
        "release_client_state": release_client_state,
    }
