import ipaddress

from nmapui.workflow_context import build_scan_workflow_context
from nmapui.workflows import (
    start_deep_scan as workflow_start_deep_scan,
    start_scan_task as workflow_start_scan_task,
)


def make_broadcast_emit(*, owner_sid, broadcaster, emit_to_client, job_type="scan", runtime_store=None):
    """Fan events out to all subscribed tabs while recording replay state."""

    def _emit(sid, event, data=None):
        broadcaster.record(owner_sid, event, data, job_type=job_type)
        if runtime_store is not None:
            runtime_store.append_job_event(
                job_id=f"{owner_sid}:{job_type}",
                owner_sid=owner_sid,
                job_type=job_type,
                event_name=event,
                payload=data,
            )
        for sub_sid in broadcaster.get_subscribers(owner_sid, job_type=job_type):
            emit_to_client(sub_sid, event, data)

    return _emit


def start_scan_task(
    *,
    sid,
    target,
    broadcaster,
    emit_to_client,
    get_client_state,
    ensure_job_not_cancelled,
    idle_state_manager,
    update_job_progress,
    socketio_sleep,
    run_cancellable_command,
    run_arp_scan,
    identify_gateway_firewall_targets,
    job_registry,
    emit_job_status,
    logger,
    settings_state,
    vulners_script,
    runtime_store=None,
):
    context = build_scan_workflow_context(
        {
            "get_client_state": get_client_state,
            "ensure_job_not_cancelled": ensure_job_not_cancelled,
            "idle_state_manager": idle_state_manager,
            "update_job_progress": update_job_progress,
            "emit_to_client": make_broadcast_emit(
                owner_sid=sid,
                broadcaster=broadcaster,
                emit_to_client=emit_to_client,
                job_type="scan",
                runtime_store=runtime_store,
            ),
            "socketio_sleep": socketio_sleep,
            "run_cancellable_command": run_cancellable_command,
            "run_arp_scan": run_arp_scan,
            "identify_gateway_firewall_targets": identify_gateway_firewall_targets,
            "start_deep_scan": workflow_start_deep_scan,
            "job_registry": job_registry,
            "emit_job_status": emit_job_status,
            "logger": logger,
            "settings_state": settings_state,
            "vulners_script": vulners_script,
            "ip_sort_key": ipaddress.IPv4Address,
            "on_job_end": lambda: broadcaster.end_job(sid, job_type="scan"),
        }
    )
    return workflow_start_scan_task(context, sid, target)
