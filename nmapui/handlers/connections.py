from flask import request


def _load_persisted_source_state(runtime_store):
    if runtime_store is None:
        return None

    current_customer = runtime_store.get_runtime_snapshot("current_customer")
    network_key = runtime_store.get_runtime_snapshot("network_key")
    last_scan_target = runtime_store.get_runtime_snapshot("last_scan_target")

    if current_customer is None and network_key is None and last_scan_target is None:
        return None

    return {
        "current_customer": current_customer
        or {"id": "unknown", "name": "Unknown Network", "confidence": 0.0},
        "network_key": network_key
        or {
            "target": "1.1.1.1",
            "total_hops": 0,
            "private_hops": [],
            "public_hops": [],
            "exit_ip": None,
        },
        "last_scan_target": last_scan_target,
    }


def register_connection_handlers(socketio, deps):
    auto_scan_config = deps.get("auto_scan_config")
    broadcaster = deps["broadcaster"]
    emit_to_client = deps["emit_to_client"]
    get_client_state = deps["get_client_state"]
    job_registry = deps["job_registry"]
    logger = deps["logger"]
    runtime_store = deps.get("runtime_store")
    set_current_customer_state = deps["set_current_customer_state"]
    set_last_scan_target_state = deps["set_last_scan_target_state"]
    set_network_key_state = deps["set_network_key_state"]

    @socketio.on("connect")
    def on_connect(auth=None):
        new_sid = request.sid
        active_job_type = None
        owner_sid = broadcaster.find_active_owner("scan")
        if owner_sid is not None:
            active_job_type = "scan"
        else:
            owner_sid = broadcaster.find_active_owner("report")
            if owner_sid is not None:
                active_job_type = "report"
        if owner_sid:
            source_state = get_client_state(sid=owner_sid)
        else:
            source_state = _load_persisted_source_state(runtime_store) or get_client_state()

        set_current_customer_state(value=source_state["current_customer"], sid=new_sid)
        set_network_key_state(value=source_state["network_key"], sid=new_sid)
        set_last_scan_target_state(
            value=source_state.get("last_scan_target"),
            sid=new_sid,
        )

        emit_to_client(new_sid, "customer_info", source_state["current_customer"])
        emit_to_client(new_sid, "network_key", source_state["network_key"])
        emit_to_client(
            new_sid,
            "client_state_snapshot",
            {"last_scan_target": source_state.get("last_scan_target")},
        )
        if auto_scan_config is not None:
            emit_to_client(new_sid, "auto_scan_status", auto_scan_config)

        if owner_sid is None:
            return

        job = job_registry.get(owner_sid, active_job_type)
        if not job or job.get("status") not in ("running", "cancelling"):
            broadcaster.end_job(owner_sid, job_type=active_job_type)
            return

        replay_buffer = broadcaster.get_replay_buffer(owner_sid, job_type=active_job_type)
        logger.info(
            "New tab %s joining active %s owned by %s — replaying %d events",
            new_sid,
            active_job_type,
            owner_sid,
            len(replay_buffer),
        )

        broadcaster.subscribe(owner_sid, new_sid, job_type=active_job_type)
        emit_to_client(new_sid, "job_status", {**job, "job_type": active_job_type})

        for event, data in replay_buffer:
            emit_to_client(new_sid, event, data)
