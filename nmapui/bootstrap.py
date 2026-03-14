from datetime import datetime
import os

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO

from .runtime import env_flag


def get_allowed_origins():
    """Return the explicit CORS allowlist for HTTP and Socket.IO."""
    configured = os.environ.get("NMAPUI_ALLOWED_ORIGINS", "").strip()
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return [
        "http://127.0.0.1:9000",
        "http://localhost:9000",
    ]


def build_runtime_options(argv):
    """Build server runtime options from argv and environment."""
    return {
        "quick_mode": "--quick" in argv or "-q" in argv,
        "host": os.environ.get("NMAPUI_HOST", "127.0.0.1"),
        "port": int(os.environ.get("NMAPUI_PORT", "9000")),
        "debug": env_flag("NMAPUI_DEBUG", default=False),
    }


def create_web_app(import_name):
    """Create the Flask app and Socket.IO server with the default CORS policy."""
    allowed_origins = get_allowed_origins()
    app = Flask(import_name)
    socketio = SocketIO(app, cors_allowed_origins=allowed_origins)
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})
    return app, socketio


def begin_startup_state(startup_state, *, quick):
    """Reset startup-state tracking for a new startup attempt."""
    startup_state["startup_complete"] = False
    startup_state["dependency_checks_skipped"] = bool(quick)
    startup_state["dependencies_ok"] = False
    startup_state["traceroute_initialized"] = False
    startup_state["last_started_at"] = datetime.now().isoformat()
    startup_state["errors"] = []
    return startup_state


def complete_startup_state(startup_state, *, traceroute_initialized):
    """Mark startup as fully initialized."""
    startup_state["traceroute_initialized"] = bool(traceroute_initialized)
    startup_state["startup_complete"] = True
    return startup_state


def run_socketio_server(socketio, app, runtime_options):
    """Run the Socket.IO server using the normalized runtime options."""
    socketio.run(
        app,
        host=runtime_options["host"],
        port=runtime_options["port"],
        debug=runtime_options["debug"],
        allow_unsafe_werkzeug=runtime_options["debug"],
    )
