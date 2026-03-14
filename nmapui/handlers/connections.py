from flask import request


def register_connection_handlers(socketio, deps):
    broadcaster = deps["broadcaster"]
    emit_to_client = deps["emit_to_client"]
    job_registry = deps["job_registry"]
    logger = deps["logger"]

    @socketio.on("connect")
    def on_connect():
        new_sid = request.sid
        owner_sid = broadcaster.find_active_owner()
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
