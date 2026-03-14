import base64
import os
from functools import wraps

from flask import jsonify, request
from flask_socketio import emit


AUTH_USERNAME = os.environ.get("NMAPUI_USERNAME", "admin")
AUTH_PASSWORD = os.environ.get("NMAPUI_PASSWORD", "nmapui123")


def check_auth(username, password):
    """Validate credentials."""
    return username == AUTH_USERNAME and password == AUTH_PASSWORD


def require_auth(f):
    """Decorator to require HTTP Basic Auth for Flask routes."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


def require_socket_auth():
    """Decorator to require HTTP Basic Auth context for Socket.IO events."""

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            auth = request.authorization
            if not auth:
                header = request.headers.get("Authorization", "")
                if header.startswith("Basic "):
                    try:
                        decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
                        username, password = decoded.split(":", 1)
                        if check_auth(username, password):
                            return f(*args, **kwargs)
                    except Exception:
                        pass
                emit("auth_error", {"error": "Unauthorized"})
                return None

            if not check_auth(auth.username, auth.password):
                emit("auth_error", {"error": "Unauthorized"})
                return None
            return f(*args, **kwargs)

        return wrapped

    return decorator
