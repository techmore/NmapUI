from pathlib import Path
import subprocess


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


def test_wrapper_contract_uses_single_supported_launcher():
    build_script = (ROOT / "build.sh").read_text()

    assert 'PACKAGING_DIR="$ROOT_DIR/packaging/macos"' in build_script
    assert 'SRC="$PACKAGING_DIR/NmapUIMenuBarLauncher.swift"' in build_script
    assert not (ROOT / "NmapUIMenuBar.swift").exists()
    assert not (ROOT / "NmapUIMenuBarSimple.swift").exists()
    assert not (ROOT / "NmapUIMenuBarWithServer.swift").exists()
    assert (ROOT / "packaging" / "macos" / "NmapUIMenuBarLauncher.swift").exists()


def test_wrapper_docs_reference_current_local_port():
    for doc_name in ("packaging/macos/README.md", "packaging/macos/SETUP.md"):
        source = (ROOT / doc_name).read_text()
        assert "127.0.0.1:9000" in source
        assert "localhost:9999" not in source


def test_pyinstaller_spec_includes_runtime_assets():
    spec = (ROOT / "packaging" / "pyinstaller" / "nmapui.spec").read_text()

    assert "config" in spec
    assert "VERSION" in spec
    assert "nmap-modern.xsl" in spec
    assert "nmap-pdf-olive-legacy.xsl" in spec


def test_runtime_uses_separate_web_and_pdf_stylesheets():
    paths_source = (ROOT / "nmapui" / "paths.py").read_text()

    assert 'XSL_STYLESHEET = BASE_DIR / "nmap-modern.xsl"' in paths_source
    assert 'XSL_STYLESHEET_PDF = BASE_DIR / "nmap-pdf-olive-legacy.xsl"' in paths_source


def test_deploy_script_uses_portable_python_timeout_smoke_test():
    deploy_script = (ROOT / "deploy.sh").read_text()

    assert "subprocess.run" in deploy_script
    assert "timeout 10s" not in deploy_script


def test_repository_layout_guide_exists():
    guide = (ROOT / "docs" / "guides" / "REPOSITORY_LAYOUT.md").read_text()

    assert "packaging/macos/" in guide
    assert "packaging/pyinstaller/" in guide
    assert "docs/notes/" in guide


def test_auto_scan_config_has_tracked_example_only():
    assert (ROOT / "config" / "auto_scan_config.example.json").exists()

    gitignore = (ROOT / ".gitignore").read_text()
    assert "auto_scan_config.json" in gitignore


def test_runtime_manifest_does_not_include_removed_browser_stack():
    requirements = (ROOT / "requirements.txt").read_text()
    install_script = (ROOT / "install.sh").read_text()

    for removed_dependency in ("selenium==", "reportlab==", "Pillow=="):
        assert removed_dependency not in requirements

    assert "chromedriver-autoinstaller" not in install_script
    assert "Chrome/ChromeDriver for Selenium" not in install_script


def test_release_paths_prefer_dot_venv():
    deploy_script = (ROOT / "deploy.sh").read_text()
    building_guide = (ROOT / "BUILDING.md").read_text()
    testing_guide = (ROOT / "docs" / "guides" / "TESTING_GUIDE.md").read_text()
    release_checklist = (
        ROOT / "docs" / "guides" / "RELEASE_CHECKLIST.md"
    ).read_text()

    assert 'if [ -f ".venv/bin/activate" ]' in deploy_script
    assert "source .venv/bin/activate" in building_guide
    assert "source .venv/bin/activate" in testing_guide
    assert "source .venv/bin/activate" in release_checklist


def test_app_exposes_explicit_run_server_entrypoint():
    app_source = subprocess.check_output(
        ["git", "show", ":app.py"],
        cwd=ROOT,
        text=True,
    )

    assert "def run_server(argv=None):" in app_source
    assert 'if __name__ == "__main__":\n    run_server()' in app_source


def test_app_runtime_uses_bootstrap_origin_and_server_policy():
    app_source = subprocess.check_output(
        ["git", "show", ":app.py"],
        cwd=ROOT,
        text=True,
    )

    assert 'allowed_origins = get_allowed_origins()' in app_source
    assert 'SocketIO(app, cors_allowed_origins=allowed_origins)' in app_source
    assert 'CORS(app, resources={r"/api/*": {"origins": allowed_origins}})' in app_source
    assert "runtime_options = build_runtime_options(argv or sys.argv)" in app_source
    assert "run_socketio_server(socketio, app, runtime_options)" in app_source
    assert 'cors_allowed_origins="*"' not in app_source


def test_app_delegates_state_persistence_to_shared_module():
    app_source = (ROOT / "app.py").read_text()

    assert "nmapui.state" in app_source
    assert "get_report_counts as get_report_counts_impl" in app_source
    assert "load_current_assignment as load_current_assignment_impl" in app_source
    assert "save_current_assignment as save_current_assignment_impl" in app_source
    assert "save_customers_config as save_customers_config_impl" in app_source
    assert "return get_report_counts_impl(" in app_source
    assert "save_current_assignment_impl(" in app_source
    assert "save_customers_config_impl(" in app_source
    assert "current_customer = load_current_assignment_impl(" in app_source


def test_app_delegates_runtime_info_events_to_handler_module():
    app_source = (ROOT / "app.py").read_text()

    assert "from nmapui.handlers.runtime_info import register_runtime_info_handlers" in app_source
    assert "register_runtime_info_handlers(" in app_source
    assert '@socketio.on("get_history_counts")' not in app_source
    assert '@socketio.on("get_network_key")' not in app_source
    assert '@socketio.on("get_local_ip")' not in app_source


def test_app_delegates_startup_checks_to_shared_module():
    app_source = (ROOT / "app.py").read_text()

    assert "from nmapui.startup import create_startup_state" in app_source
    assert "from nmapui.startup_checks import run_startup_checks" in app_source
    assert "from nmapui.tooling import ToolVersionRegistry" in app_source
    assert "tool_versions = ToolVersionRegistry()" in app_source
    assert "startup_state = create_startup_state()" in app_source
    assert "run_startup_checks(" in app_source
    assert 'versions["nmap"] = check_nmap()' not in app_source
    assert 'versions["vulners"] = version_result.stdout.strip()' not in app_source
    assert 'versions["arp_scan"] = version' not in app_source


def test_app_delegates_core_routes_to_handler_module():
    app_source = (ROOT / "app.py").read_text()

    assert "from nmapui.handlers.routes import register_core_routes" in app_source
    assert "register_core_routes(" in app_source
    assert '@app.route("/")' not in app_source
    assert '@app.route("/api/health")' not in app_source
    assert '@app.route("/api/health/live")' not in app_source
    assert '@app.route("/api/health/ready")' not in app_source


def test_app_delegates_networking_helpers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()

    assert "from nmapui.networking import (" in app_source
    assert "calculate_cidr as calculate_cidr_impl" in app_source
    assert "get_default_interface as get_default_interface_impl" in app_source
    assert "return get_default_interface_impl(ni, logger)" in app_source
    assert "return calculate_cidr_impl(ip, subnet_mask)" in app_source
    assert "return identify_gateway_firewall_targets_for_key(hosts, network_key)" in app_source


def test_app_delegates_scan_job_handlers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()

    assert "from nmapui.handlers.scan_jobs import register_scan_job_handlers" in app_source
    assert "register_scan_job_handlers(" in app_source
    assert '@socketio.on("start_scan")' not in app_source
    assert '@socketio.on("generate_report")' not in app_source


def test_template_unifies_scan_result_listeners_and_normalizes_feedback():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    scan_runtime_module = (ROOT / "static" / "js" / "scan_runtime.js").read_text()
    discovery_module = (ROOT / "static" / "js" / "discovery_ui.js").read_text()

    assert template.count("initializeDiscoveryUI(socket);") == 1
    assert "socket.on('scan_results'" in discovery_module
    assert "socket.on('deep_scan_results'" in discovery_module
    assert "socket.on('arp_results'" in discovery_module
    assert "function normalizeFeedbackMessage(msg)" in scan_runtime_module
    assert "const message = normalizeFeedbackMessage(msg);" in scan_runtime_module


def test_template_uses_dom_helpers_for_update_and_route_rendering():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    update_module = (ROOT / "static" / "js" / "update_modal.js").read_text()
    discovery_module = (ROOT / "static" / "js" / "discovery_ui.js").read_text()

    assert "function setUpdateReleaseNotes(data)" in update_module
    assert "function appendUpdateLogLine(message, isError = false)" in update_module
    assert "function renderRoutePath(data)" in discovery_module
    assert "notesDiv.innerHTML =" not in template
    assert "log.innerHTML +=" not in template


def test_frontend_modules_do_not_require_duplicate_globals_or_missing_init_deps():
    report_generation_module = (
        ROOT / "static" / "js" / "report_generation_ui.js"
    ).read_text()
    auto_scan_module = (ROOT / "static" / "js" / "auto_scan_ui.js").read_text()
    update_modal_module = (ROOT / "static" / "js" / "update_modal.js").read_text()

    assert "let getClientJobs = null;" not in report_generation_module
    assert "let reportGetClientJobs =" in report_generation_module
    assert "reportGetClientJobs = deps?.getClientJobs || window.getClientJobs || reportGetClientJobs;" in report_generation_module
    assert "let getClientJobs = null;" not in auto_scan_module
    assert "let autoScanGetClientJobs =" in auto_scan_module
    assert "autoScanGetClientJobs = deps?.getClientJobs || window.getClientJobs || autoScanGetClientJobs;" in auto_scan_module
    assert "function initializeUpdateModal(socket, deps = {})" in update_modal_module
    assert "const showReportStatus =" in update_modal_module
    assert "document.getElementById('chunked-scan-btn')?.addEventListener('click'" in report_generation_module
    assert "socket.on('scan_results'" in report_generation_module


def test_template_does_not_keep_inline_report_generation_block():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )

    assert "document.getElementById('generate-report-btn').addEventListener('click'" not in template
    assert "function startReportTimer()" not in template
    assert "function stopReportTimer()" not in template


def test_pdf_generation_prefers_browser_renderer_before_wkhtml():
    reporting_source = (ROOT / "nmapui" / "reporting.py").read_text()

    assert 'feedback("Trying browser-quality PDF rendering with Playwright")' in reporting_source
    assert reporting_source.index("from playwright.async_api import async_playwright") < reporting_source.index('wkhtml = shutil.which("wkhtmltopdf")')


def test_template_uses_dom_helpers_for_scan_result_rendering():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    discovery_module = (ROOT / "static" / "js" / "discovery_ui.js").read_text()

    assert "function renderCveArrayCell(cell, cveArray)" in discovery_module
    assert "function appendServiceInfoLine(cell, line)" in discovery_module
    assert "function renderDelimitedCell(cell, items, options = {})" in discovery_module
    assert "cell.innerHTML = items.map" not in template
    assert "data.cve_array.forEach(cve => cell.innerHTML +=" not in template
    assert "row.cells[4].innerHTML +=" not in template


def test_template_uses_dom_helpers_for_asset_modal_and_history_rendering():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    asset_module = (ROOT / "static" / "js" / "asset_details_modal.js").read_text()
    layout_module = (ROOT / "static" / "js" / "layout_runtime.js").read_text()

    assert "function renderAssetServices(asset)" in asset_module
    assert "function renderAssetVulnerabilities(asset)" in asset_module
    assert "function renderHistoryState(message, isError = false)" in layout_module
    assert "function renderHistoryList(scans)" in layout_module
    assert "serviceDiv.innerHTML =" not in template
    assert "cveDiv.innerHTML =" not in template
    assert "historyList.innerHTML = scans.map" not in template
