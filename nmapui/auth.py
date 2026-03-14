import base64
import os
from functools import wraps

from flask import jsonify, request
from flask_socketio import emit


DEFAULT_AUTH_USERNAME = "admin"
DEFAULT_AUTH_PASSWORD = "nmapui123"


def get_auth_credentials():
    return (
        os.environ.get("NMAPUI_USERNAME", DEFAULT_AUTH_USERNAME),
        os.environ.get("NMAPUI_PASSWORD", DEFAULT_AUTH_PASSWORD),
    )


def default_credentials_allowed():
    return os.environ.get("NMAPUI_ALLOW_DEFAULT_CREDENTIALS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def auth_uses_insecure_defaults():
    username, password = get_auth_credentials()
    return (
        username == DEFAULT_AUTH_USERNAME
        and password == DEFAULT_AUTH_PASSWORD
        and not default_credentials_allowed()
    )


def check_auth(username, password):
    """Validate credentials."""
    if auth_uses_insecure_defaults():
        return False

    expected_username, expected_password = get_auth_credentials()
    return username == expected_username and password == expected_password


def require_auth(f):
    """Decorator to require HTTP Basic Auth for Flask routes."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            if auth_uses_insecure_defaults():
                return jsonify({"error": "Authentication is not configured securely"}), 503
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
                if auth_uses_insecure_defaults():
                    emit("auth_error", {"error": "Authentication is not configured securely"})
                    return None
                emit("auth_error", {"error": "Unauthorized"})
                return None

            if not check_auth(auth.username, auth.password):
                if auth_uses_insecure_defaults():
                    emit("auth_error", {"error": "Authentication is not configured securely"})
                    return None
                emit("auth_error", {"error": "Unauthorized"})
                return None
            return f(*args, **kwargs)

        return wrapped

    return decorator
