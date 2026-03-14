from nmapui.bootstrap import (
    begin_startup_state,
    build_runtime_options,
    complete_startup_state,
)


def test_build_runtime_options_uses_env_and_argv(monkeypatch):
    monkeypatch.setenv("NMAPUI_HOST", "0.0.0.0")
    monkeypatch.setenv("NMAPUI_PORT", "9100")
    monkeypatch.setenv("NMAPUI_DEBUG", "true")

    options = build_runtime_options(["app.py", "--quick"])

    assert options == {
        "quick_mode": True,
        "host": "0.0.0.0",
        "port": 9100,
        "debug": True,
    }


def test_begin_startup_state_resets_transient_fields():
    state = {
        "startup_complete": True,
        "dependency_checks_skipped": False,
        "dependencies_ok": True,
        "traceroute_initialized": True,
        "last_started_at": None,
        "errors": ["old error"],
    }

    begin_startup_state(state, quick=True)

    assert state["startup_complete"] is False
    assert state["dependency_checks_skipped"] is True
    assert state["dependencies_ok"] is False
    assert state["traceroute_initialized"] is False
    assert state["errors"] == []
    assert state["last_started_at"] is not None


def test_complete_startup_state_marks_startup_complete():
    state = {
        "startup_complete": False,
        "dependency_checks_skipped": False,
        "dependencies_ok": True,
        "traceroute_initialized": False,
        "last_started_at": None,
        "errors": [],
    }

    complete_startup_state(state, traceroute_initialized=True)

    assert state["startup_complete"] is True
    assert state["traceroute_initialized"] is True
