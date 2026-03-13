from flask_socketio import emit


def safe_emit(event, data=None):
    """Emit a Socket.IO event only if in a request context."""
    try:
        if data is None:
            emit(event)
        else:
            emit(event, data)
    except RuntimeError:
        pass


def emit_to_client(socketio, sid: str, event: str, data=None):
    """Emit a Socket.IO event to a single connected client."""
    if data is None:
        socketio.emit(event, to=sid)
    else:
        socketio.emit(event, data, to=sid)


def emit_job_status(socketio, job_registry, sid: str, job_type: str):
    """Publish the current status for a client job."""
    payload = job_registry.get(sid, job_type) or {"status": "idle", "details": {}}
    payload["job_type"] = job_type
    emit_to_client(socketio, sid, "job_status", payload)


def update_job_progress(
    socketio,
    job_registry,
    sid: str,
    job_type: str,
    phase: str,
    message=None,
    progress=None,
    details=None,
):
    """Update the current phase/progress for a client job and publish it."""
    payload = {"phase": phase}
    if message is not None:
        payload["message"] = message
    if progress is not None:
        payload["progress"] = progress
    if details:
        payload.update(details)

    job_registry.update(sid, job_type, details=payload)
    emit_job_status(socketio, job_registry, sid, job_type)
