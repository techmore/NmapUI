import logging

from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.updates import register_update_handlers
from nmapui.idle_state import IdleStateManager
import nmapui.runtime as runtime


def test_check_for_updates_selects_mac_installer_asset(monkeypatch):
    runtime.APP_VERSION = None
    monkeypatch.delenv("NMAPUI_DISABLE_UPDATE_CHECKS", raising=False)
    monkeypatch.setattr(runtime, "get_app_version", lambda: "v2026.1.1.00_00")
    monkeypatch.setattr(runtime.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(runtime.sys, "platform", "darwin")

    class ResponseStub:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "tag_name": "v2026.1.9.12_53",
                "html_url": "https://github.com/techmore/NmapUI/releases/tag/v2026.1.9.12_53",
                "body": "release notes",
                "assets": [
                    {"name": "NmapUI.pkg", "browser_download_url": "https://example.com/NmapUI.pkg"},
                    {"name": "NmapUI.dmg", "browser_download_url": "https://example.com/NmapUI.dmg"},
                ],
            }

    monkeypatch.setattr(runtime.requests, "get", lambda url, timeout=10: ResponseStub())

    result = runtime.check_for_updates()

    assert result["available"] is True
    assert result["current_version"] == "v2026.1.1.00_00"
    assert result["latest_version"] == "v2026.1.9.12_53"
    assert result["asset_name"] == "NmapUI.dmg"
    assert result["download_url"] == "https://example.com/NmapUI.dmg"
    assert result["install_method"] == "manual_download"


def test_check_for_updates_reports_current_version_when_no_update(monkeypatch):
    runtime.APP_VERSION = None
    monkeypatch.delenv("NMAPUI_DISABLE_UPDATE_CHECKS", raising=False)
    monkeypatch.setattr(runtime, "get_app_version", lambda: "v2026.1.9.12_53")

    class ResponseStub:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "tag_name": "v2026.1.9.12_53",
                "html_url": "https://github.com/techmore/NmapUI/releases/tag/v2026.1.9.12_53",
                "body": "release notes",
                "assets": [],
            }

    monkeypatch.setattr(runtime.requests, "get", lambda url, timeout=10: ResponseStub())

    result = runtime.check_for_updates()

    assert result == {
        "available": False,
        "current_version": "v2026.1.9.12_53",
        "latest_version": "v2026.1.9.12_53",
        "release_url": "https://github.com/techmore/NmapUI/releases/tag/v2026.1.9.12_53",
    }


def test_check_for_updates_returns_disabled_payload_without_github(monkeypatch):
    runtime.APP_VERSION = None
    monkeypatch.setenv("NMAPUI_DISABLE_UPDATE_CHECKS", "true")
    monkeypatch.setattr(runtime, "get_app_version", lambda: "v2026.1.1.00_00")
    called = []

    def fail_get(url, timeout=10):
        called.append(url)
        raise AssertionError("should not call GitHub")

    monkeypatch.setattr(runtime.requests, "get", fail_get)
    result = runtime.check_for_updates()
    assert result["available"] is False
    assert result["update_checks_disabled"] is True
    assert result["current_version"] == "v2026.1.1.00_00"
    assert called == []


def test_idle_state_manager_skips_banner_when_update_checks_disabled():
    calls = []

    def safe_emit(event, data=None):
        calls.append((event, data))

    def check_for_updates():
        return {"available": True, "latest_version": "v2.0.0"}

    idle = IdleStateManager(
        safe_emit=safe_emit,
        check_for_updates=check_for_updates,
        logger=logging.getLogger("test_idle"),
        update_checks_enabled=False,
    )
    idle.set_update_available(True, {"available": True})
    assert not any(c[0] == "show_auto_update_banner" for c in calls)


def test_perform_app_update_emits_manual_install_messages(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.delenv("NMAPUI_DISABLE_UPDATE_CHECKS", raising=False)
    monkeypatch.delenv("NMAPUI_SKIP_OPEN", raising=False)
    monkeypatch.delenv("NMAPUI_HEADLESS", raising=False)

    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    opened_urls = []

    class IdleStateStub:
        def set_update_available(self, available, update_info=None):
            return None

        def cancel_countdown(self):
            return None

        def start_countdown(self):
            return None

    register_update_handlers(
        socketio,
        {
            "check_for_updates": lambda: {
                "available": True,
                "latest_version": "v2026.1.9.12_53",
                "asset_name": "NmapUI.dmg",
                "download_url": "https://example.com/NmapUI.dmg",
                "release_url": "https://github.com/techmore/NmapUI/releases/tag/v2026.1.9.12_53",
            },
            "idle_state_manager": IdleStateStub(),
            "logger": app.logger,
        },
    )

    import nmapui.handlers.updates as updates_module

    monkeypatch.setattr(
        updates_module.webbrowser,
        "open",
        lambda url: opened_urls.append(url) or True,
    )

    token_client = app.test_client()
    import base64
    token = base64.b64encode(b"scanner:secret-pass").decode()
    client = socketio.test_client(app, flask_test_client=token_client, headers={"Authorization": f"Basic {token}"})
    client.emit("perform_app_update")
    received = client.get_received()

    assert opened_urls == ["https://example.com/NmapUI.dmg"]
    assert any(
        event["name"] == "update_status"
        and event["args"] == [{"message": "Opening installer download for NmapUI.dmg..."}]
        for event in received
    )
    assert any(
        event["name"] == "update_complete"
        and event["args"] == [{
            "message": "Installer page opened. Finish the update manually and relaunch NmapUI.",
            "manual_install": True,
            "download_url": "https://example.com/NmapUI.dmg",
        }]
        for event in received
    )


def test_perform_app_update_skips_browser_when_skip_open(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.setenv("NMAPUI_SKIP_OPEN", "1")
    monkeypatch.delenv("NMAPUI_DISABLE_UPDATE_CHECKS", raising=False)

    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    opened_urls = []

    class IdleStateStub:
        def set_update_available(self, available, update_info=None):
            return None

        def cancel_countdown(self):
            return None

        def start_countdown(self):
            return None

    register_update_handlers(
        socketio,
        {
            "check_for_updates": lambda: {
                "available": True,
                "latest_version": "v2026.1.9.12_53",
                "asset_name": "NmapUI.dmg",
                "download_url": "https://example.com/NmapUI.dmg",
                "release_url": "https://github.com/techmore/NmapUI/releases/tag/v2026.1.9.12_53",
            },
            "idle_state_manager": IdleStateStub(),
            "logger": app.logger,
        },
    )

    import nmapui.handlers.updates as updates_module

    monkeypatch.setattr(
        updates_module.webbrowser,
        "open",
        lambda url: opened_urls.append(url) or True,
    )

    token_client = app.test_client()
    import base64

    token = base64.b64encode(b"scanner:secret-pass").decode()
    client = socketio.test_client(app, flask_test_client=token_client, headers={"Authorization": f"Basic {token}"})
    client.emit("perform_app_update")
    received = client.get_received()

    assert opened_urls == []
    assert any(
        event["name"] == "update_complete"
        and event["args"][0].get("skipped_open") is True
        for event in received
    )


def test_perform_app_update_noop_when_updates_disabled(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.setenv("NMAPUI_DISABLE_UPDATE_CHECKS", "true")

    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)

    class IdleStateStub:
        def set_update_available(self, available, update_info=None):
            return None

        def cancel_countdown(self):
            return None

        def start_countdown(self):
            return None

    register_update_handlers(
        socketio,
        {
            "check_for_updates": lambda: {"available": True},
            "idle_state_manager": IdleStateStub(),
            "logger": app.logger,
        },
    )

    import nmapui.handlers.updates as updates_module

    opened_urls = []
    monkeypatch.setattr(
        updates_module.webbrowser,
        "open",
        lambda url: opened_urls.append(url) or True,
    )

    token_client = app.test_client()
    import base64

    token = base64.b64encode(b"scanner:secret-pass").decode()
    client = socketio.test_client(app, flask_test_client=token_client, headers={"Authorization": f"Basic {token}"})
    client.emit("perform_app_update")
    received = client.get_received()

    assert opened_urls == []
    assert any(
        event["name"] == "update_complete"
        and event["args"][0].get("update_checks_disabled") is True
        for event in received
    )
