from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_main_template_no_longer_uses_legacy_socket_events():
    html = (ROOT / "templates" / "index.html").read_text()

    for legacy_event in (
        "socket.on('scan_start'",
        "socket.on('scan_complete'",
        "socket.on('customer_lookup_results'",
        "socket.on('auto_scan_executed'",
        "socket.on('start_report_generation'",
    ):
        assert legacy_event not in html


def test_pyinstaller_spec_includes_runtime_assets():
    spec = (ROOT / "nmapui.spec").read_text()

    assert "config" in spec
    assert "VERSION" in spec
    assert "nmap-modern.xsl" in spec


def test_deploy_script_uses_portable_python_timeout_smoke_test():
    deploy_script = (ROOT / "deploy.sh").read_text()

    assert "subprocess.run" in deploy_script
    assert "timeout 10s" not in deploy_script
