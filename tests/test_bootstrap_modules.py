from nmapui.bootstrap import (
    begin_startup_state,
    build_runtime_options,
    create_web_app,
    complete_startup_state,
    run_socketio_server,
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


def test_create_web_app_initializes_flask_and_socketio():
    created = {}

    class FlaskStub:
        def __init__(self, import_name):
            created["import_name"] = import_name

    class SocketIOStub:
        def __init__(self, app, cors_allowed_origins):
            created["socketio_app"] = app
            created["cors_allowed_origins"] = cors_allowed_origins

    def cors_stub(app, resources):
        created["cors_app"] = app
        created["cors_resources"] = resources

    import nmapui.bootstrap as bootstrap

    original_flask = bootstrap.Flask
    original_socketio = bootstrap.SocketIO
    original_cors = bootstrap.CORS
    bootstrap.Flask = FlaskStub
    bootstrap.SocketIO = SocketIOStub
    bootstrap.CORS = cors_stub
    try:
        app, socketio = create_web_app("nmapui.app")
    finally:
        bootstrap.Flask = original_flask
        bootstrap.SocketIO = original_socketio
        bootstrap.CORS = original_cors

    assert created["import_name"] == "nmapui.app"
    assert created["socketio_app"] is app
    assert socketio is not None
    assert created["cors_allowed_origins"] == "*"
    assert created["cors_app"] is app
    assert created["cors_resources"] == {r"/api/*": {"origins": "*"}}


def test_run_socketio_server_uses_normalized_runtime_options():
    calls = {}

    class SocketIOStub:
        def run(self, app, host, port, debug, allow_unsafe_werkzeug):
            calls["app"] = app
            calls["host"] = host
            calls["port"] = port
            calls["debug"] = debug
            calls["allow_unsafe_werkzeug"] = allow_unsafe_werkzeug

    app = object()
    runtime_options = {
        "host": "127.0.0.1",
        "port": 9000,
        "debug": False,
    }

    run_socketio_server(SocketIOStub(), app, runtime_options)

    assert calls == {
        "app": app,
        "host": "127.0.0.1",
        "port": 9000,
        "debug": False,
        "allow_unsafe_werkzeug": False,
    }
