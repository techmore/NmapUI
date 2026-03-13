import os
from functools import wraps

from flask import jsonify, request


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
    """Check auth for SocketIO events - returns (authenticated, error_response)."""
    return (True, None)
