from flask import request


def register_connection_handlers(socketio, deps):
    auto_scan_config = deps.get("auto_scan_config")
    broadcaster = deps["broadcaster"]
    emit_to_client = deps["emit_to_client"]
    get_client_state = deps["get_client_state"]
    job_registry = deps["job_registry"]
    logger = deps["logger"]
    set_current_customer_state = deps["set_current_customer_state"]
    set_last_scan_target_state = deps["set_last_scan_target_state"]
    set_network_key_state = deps["set_network_key_state"]

    @socketio.on("connect")
    def on_connect():
        new_sid = request.sid
        owner_sid = broadcaster.find_active_owner()
        source_state = get_client_state(sid=owner_sid) if owner_sid else get_client_state()

        set_current_customer_state(source_state["current_customer"], sid=new_sid)
        set_network_key_state(source_state["network_key"], sid=new_sid)
        set_last_scan_target_state(source_state.get("last_scan_target"), sid=new_sid)

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

        job = job_registry.get(owner_sid, "scan")
        if not job or job.get("status") not in ("running", "cancelling"):
            broadcaster.end_job(owner_sid)
            return

        replay_buffer = broadcaster.get_replay_buffer(owner_sid)
        logger.info(
            "New tab %s joining active scan owned by %s — replaying %d events",
            new_sid,
            owner_sid,
            len(replay_buffer),
        )

        broadcaster.subscribe(owner_sid, new_sid)
        emit_to_client(new_sid, "job_status", {**job, "job_type": "scan"})

        for event, data in replay_buffer:
            emit_to_client(new_sid, event, data)
