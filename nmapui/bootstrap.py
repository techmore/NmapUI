from datetime import datetime
import os

from .runtime import env_flag


def build_runtime_options(argv):
    """Build server runtime options from argv and environment."""
    return {
        "quick_mode": "--quick" in argv or "-q" in argv,
        "host": os.environ.get("NMAPUI_HOST", "127.0.0.1"),
        "port": int(os.environ.get("NMAPUI_PORT", "9000")),
        "debug": env_flag("NMAPUI_DEBUG", default=False),
    }


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
