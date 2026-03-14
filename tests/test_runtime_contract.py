from pathlib import Path
import subprocess
import sys


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


def test_main_template_no_longer_duplicates_extracted_socket_runtime_handlers():
    html = (ROOT / "templates" / "index.html").read_text()

    for duplicated_handler in (
        "socket.on('local_ip', data => {",
        "socket.on('network_key', data => {",
        "socket.on('customers_list', data => {",
        "socket.on('customer_info', data => {",
        "socket.on('versions', data => {",
        "socket.on('history_counts', data => {",
    ):
        assert duplicated_handler not in html


def test_wrapper_contract_uses_single_supported_launcher():
    build_script = (ROOT / "build.sh").read_text()

    assert 'PACKAGING_DIR="$ROOT_DIR/packaging/macos"' in build_script
    assert 'SRC="$PACKAGING_DIR/NmapUIMenuBarLauncher.swift"' in build_script
    assert not (ROOT / "NmapUIMenuBar.swift").exists()
    assert not (ROOT / "NmapUIMenuBarSimple.swift").exists()
    assert not (ROOT / "NmapUIMenuBarWithServer.swift").exists()
    assert (ROOT / "packaging" / "macos" / "NmapUIMenuBarLauncher.swift").exists()
    assert "export NMAPUI_ALLOW_UNSAFE_WERKZEUG=true" in build_script
    assert "export NMAPUI_TRUST_LOCAL_UI=true" in build_script


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
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert 'XSL_STYLESHEET = BASE_DIR / "nmap-modern.xsl"' in paths_source
    assert 'XSL_STYLESHEET_PDF = BASE_DIR / "nmap-pdf-olive-legacy.xsl"' in paths_source
    assert '"web_stylesheet": web_stylesheet' in app_composition_source
    assert '"pdf_stylesheet": pdf_stylesheet' in app_composition_source


def test_pdf_stylesheet_stays_print_first_while_web_stylesheet_stays_interactive():
    pdf_stylesheet = (ROOT / "nmap-pdf-olive-legacy.xsl").read_text()
    web_stylesheet = (ROOT / "nmap-modern.xsl").read_text()

    assert "cdn.datatables.net" not in pdf_stylesheet
    assert "code.jquery.com" not in pdf_stylesheet
    assert "$('#table-services').DataTable" not in pdf_stylesheet
    assert "@media print" in pdf_stylesheet
    assert "cdn.datatables.net" in web_stylesheet
    assert "$('#table-services').DataTable" in web_stylesheet


def test_deploy_script_uses_portable_python_timeout_smoke_test():
    deploy_script = (ROOT / "deploy.sh").read_text()

    assert "subprocess.run" in deploy_script
    assert "timeout 10s" not in deploy_script


def test_repository_layout_guide_exists():
    guide = (ROOT / "docs" / "guides" / "REPOSITORY_LAYOUT.md").read_text()

    assert "packaging/macos/" in guide
    assert "packaging/pyinstaller/" in guide
    assert "docs/notes/" in guide


def test_frontend_layout_guide_and_page_shell_exist():
    template = (ROOT / "templates" / "index.html").read_text()
    guide = (ROOT / "docs" / "guides" / "FRONTEND_LAYOUT_GUIDE.md").read_text()

    assert ".page-shell {" in template
    assert ".results-band {" in template
    assert ".modal-overlay {" in template
    assert ".modal-panel {" in template
    assert ".form-control {" in template
    assert ".form-control-md {" in template
    assert ".form-control-sm {" in template
    assert ".icon-button {" in template
    assert ".action-button {" in template
    assert ".action-button-primary {" in template
    assert ".action-button-secondary {" in template
    assert ".action-button-compact {" in template
    assert template.count('class="page-shell"') >= 2
    assert 'class="results-band"' in template
    assert 'class="table-fixed min-w-[2400px]"' in template
    assert template.count("modal-overlay") >= 6
    assert template.count("modal-panel") >= 6
    assert template.count("form-control form-control-md") >= 10
    assert template.count("form-control form-control-sm") >= 2
    assert template.count("icon-button") >= 6
    assert template.count("action-button action-button-primary") >= 5
    assert template.count("action-button action-button-secondary") >= 2
    assert "action-button action-button-primary action-button-compact" in template
    assert "Do not repeat `mx-auto max-w-7xl px-4 sm:px-6 lg:px-8` inline. Use `page-shell`." in guide
    assert "For oversized tables, keep `page-shell` outside and put `overflow-x-auto` on the inner band." in guide
    assert "For modals, keep `modal-overlay` and `modal-panel` shared" in guide
    assert "For standard inputs and selects, prefer `form-control` plus a size class" in guide
    assert "For modal close buttons, use `icon-button` instead of repeating text-color hover stacks." in guide
    assert "For modal/footer action buttons, use `action-button` with an intent variant" in guide
    assert "For smaller action rows such as history filters, add a shared size helper" in guide
    assert "/Users/techmore/projects/NmapUI/templates/index.html" in guide


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


def test_app_module_imports_successfully():
    result = subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr or result.stdout


def test_app_startup_checks_quick_mode_executes_successfully():
    result = subprocess.run(
        [sys.executable, "-c", "import app; app.startup_checks(quick=True)"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr or result.stdout


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
    app_state_runtime_source = (ROOT / "nmapui" / "app_state_runtime.py").read_text()

    assert "from nmapui.app_state_runtime import (" in app_source
    assert "get_report_counts as get_report_counts_runtime" in app_source
    assert "load_current_assignment as load_current_assignment_runtime" in app_source
    assert "save_current_assignment as save_current_assignment_runtime" in app_source
    assert "save_customers_config as save_customers_config_runtime" in app_source
    assert "return get_report_counts_runtime(" in app_source
    assert "save_current_assignment_runtime(" in app_source
    assert "save_customers_config_runtime(" in app_source
    assert "current_customer = load_current_assignment_runtime(" in app_source
    assert "return get_report_counts_impl(" in app_state_runtime_source


def test_app_delegates_client_state_wrappers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_client_state_runtime_source = (
        ROOT / "nmapui" / "app_client_state_runtime.py"
    ).read_text()
    app_bindings_source = (ROOT / "nmapui" / "app_bindings.py").read_text()

    assert "from nmapui.app_bindings import build_client_state_helpers, build_event_helpers" in app_source
    assert 'client_state_helpers = build_client_state_helpers(' in app_source
    assert 'get_client_state = client_state_helpers["get_client_state"]' in app_source
    assert 'get_current_customer_state = client_state_helpers["get_current_customer_state"]' in app_source
    assert 'set_current_customer_state = client_state_helpers["set_current_customer_state"]' in app_source
    assert 'set_network_key_state = client_state_helpers["set_network_key_state"]' in app_source
    assert 'set_last_scan_target_state = client_state_helpers["set_last_scan_target_state"]' in app_source
    assert 'release_client_state = client_state_helpers["release_client_state"]' in app_source
    assert "if sid is not None:" not in app_source
    assert "set_default_customer=lambda customer:" in app_source
    assert "set_default_network_key=lambda key:" in app_source
    assert "set_default_last_scan_target=lambda target:" in app_source
    assert "def build_client_state_helpers(" in app_bindings_source
    assert "client_state_registry.release(sid)" in app_client_state_runtime_source
    assert "if sid is not None and sync_default_state is not None:" in app_client_state_runtime_source


def test_app_delegates_event_and_job_wrappers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_events_runtime_source = (ROOT / "nmapui" / "app_events_runtime.py").read_text()
    app_bindings_source = (ROOT / "nmapui" / "app_bindings.py").read_text()

    assert "from nmapui.app_bindings import build_client_state_helpers, build_event_helpers" in app_source
    assert 'event_helpers = build_event_helpers(' in app_source
    assert 'emit_to_client = event_helpers["emit_to_client"]' in app_source
    assert 'emit_job_status = event_helpers["emit_job_status"]' in app_source
    assert 'update_job_progress = event_helpers["update_job_progress"]' in app_source
    assert 'ensure_job_not_cancelled = event_helpers["ensure_job_not_cancelled"]' in app_source
    assert 'run_cancellable_command = event_helpers["run_cancellable_command"]' in app_source
    assert "safe_emit as safe_emit_runtime" in app_source
    assert "def build_event_helpers(" in app_bindings_source
    assert "return nmapui_emit_to_client(" not in app_source
    assert "return nmapui_run_cancellable_command(" not in app_source
    assert "return nmapui_emit_to_client(socketio, sid, event, data)" in app_events_runtime_source


def test_app_delegates_runtime_info_events_to_handler_module():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "register_shared_handlers(" in app_source
    assert "from nmapui.handlers.runtime_info import register_runtime_info_handlers" in app_composition_source
    assert "register_runtime_info_handlers(socketio, runtime_info_handler_deps)" in app_composition_source
    assert '@socketio.on("get_history_counts")' not in app_source
    assert '@socketio.on("get_network_key")' not in app_source
    assert '@socketio.on("get_local_ip")' not in app_source


def test_app_delegates_startup_checks_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_runtime_source = (ROOT / "nmapui" / "app_runtime.py").read_text()

    assert "from nmapui.startup import create_startup_state" in app_source
    assert "from nmapui.app_runtime import (" in app_source
    assert "startup_checks as startup_checks_runtime" in app_source
    assert "start_auto_scan_thread as start_auto_scan_thread_runtime" in app_source
    assert "execute_auto_scan as execute_auto_scan_runtime" in app_source
    assert "from nmapui.runtime_services import create_runtime_services" in app_source
    assert "from nmapui.tooling import ToolVersionRegistry" in app_source
    assert "runtime_services = create_runtime_services(" in app_source
    assert 'tool_versions = runtime_services["tool_versions"]' in app_source
    assert 'startup_state = runtime_services["startup_state"]' in app_source
    assert "startup_checks_runtime(" in app_source
    assert "run_startup_checks(deps, quick=quick)" in app_runtime_source
    assert "handler_start_auto_scan_thread(" in app_runtime_source
    assert "execute_auto_scan_impl(deps=deps)" in app_runtime_source
    assert 'versions["nmap"] = check_nmap()' not in app_source
    assert 'versions["vulners"] = version_result.stdout.strip()' not in app_source
    assert 'versions["arp_scan"] = version' not in app_source


def test_app_delegates_idle_state_manager_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    idle_state_source = (ROOT / "nmapui" / "idle_state.py").read_text()

    assert "from nmapui.idle_state import IdleStateManager" in app_source
    assert "idle_state_manager = IdleStateManager(" in app_source
    assert "class IdleStateManager:" not in app_source
    assert "class IdleStateManager:" in idle_state_source
    assert 'self.safe_emit("idle_state_changed", {"idle": self.idle_state})' in idle_state_source


def test_app_delegates_core_routes_to_handler_module():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "register_shared_handlers(" in app_source
    assert "from nmapui.handlers.routes import register_core_routes" in app_composition_source
    assert "register_core_routes(app, core_routes_deps)" in app_composition_source
    assert '@app.route("/")' not in app_source
    assert '@app.route("/api/health")' not in app_source
    assert '@app.route("/api/health/live")' not in app_source
    assert '@app.route("/api/health/ready")' not in app_source


def test_app_delegates_networking_helpers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "from nmapui.networking import (" in app_source
    assert "calculate_cidr as calculate_cidr_impl" in app_source
    assert "get_default_interface as get_default_interface_impl" in app_source
    assert "DEFAULT_INTERFACE = get_default_interface_impl(ni, logger)" in app_source
    assert '"calculate_cidr": calculate_cidr' in app_composition_source
    assert "identify_gateway_firewall_targets_for_key(" in app_source


def test_app_delegates_scan_job_handlers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    scan_runtime_source = (ROOT / "nmapui" / "scan_runtime.py").read_text()
    app_scan_runtime_source = (ROOT / "nmapui" / "app_scan_runtime.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "register_shared_handlers(" in app_source
    assert "from nmapui.handlers.scan_jobs import register_scan_job_handlers" in app_composition_source
    assert "from nmapui.app_scan_runtime import (" in app_source
    assert "start_scan_task as start_scan_task_runtime" in app_source
    assert "run_arp_scan as run_arp_scan_runtime" in app_source
    assert "run_nmap_with_xml_output as run_nmap_with_xml_output_runtime" in app_source
    assert "register_scan_job_handlers(socketio, scan_job_handler_deps)" in app_composition_source
    assert '@socketio.on("start_scan")' not in app_source
    assert '@socketio.on("generate_report")' not in app_source
    assert '@socketio.on("generate_pdf_from_saved")' not in app_source
    assert "def _make_broadcast_emit(" not in app_source
    assert "def _scan_workflow_context(" not in app_source
    assert "def make_broadcast_emit(" in scan_runtime_source
    assert "return start_scan_task_impl(" in app_scan_runtime_source


def test_app_delegates_connection_handlers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "register_shared_handlers(" in app_source
    assert "from nmapui.handlers.connections import register_connection_handlers" in app_composition_source
    assert "register_connection_handlers(socketio, connection_handler_deps)" in app_composition_source
    assert '@socketio.on("connect")' not in app_source


def test_app_delegates_scanning_helpers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_scan_runtime_source = (ROOT / "nmapui" / "app_scan_runtime.py").read_text()

    assert "run_arp_scan as run_arp_scan_runtime" in app_source
    assert "run_nmap_with_xml_output as run_nmap_with_xml_output_runtime" in app_source
    assert "return run_arp_scan_runtime(" in app_source
    assert "return run_nmap_with_xml_output_runtime(" in app_source
    assert "return run_arp_scan_impl(" in app_scan_runtime_source
    assert "return run_nmap_with_xml_output_impl(" in app_scan_runtime_source


def test_app_delegates_auto_scan_execution_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_runtime_source = (ROOT / "nmapui" / "app_runtime.py").read_text()

    assert "execute_auto_scan as execute_auto_scan_runtime" in app_source
    assert "return execute_auto_scan_runtime(" in app_source
    assert "execute_auto_scan_impl(deps=deps)" in app_runtime_source


def test_app_uses_shared_xml_merge_helper():
    app_source = (ROOT / "app.py").read_text()

    assert "merge_nmap_xml_files," in app_source
    assert "def merge_nmap_xml_files(" not in app_source


def test_app_uses_shared_workflow_context_builders():
    app_source = (ROOT / "app.py").read_text()
    workflow_context_source = (ROOT / "nmapui" / "workflow_context.py").read_text()
    scan_runtime_source = (ROOT / "nmapui" / "scan_runtime.py").read_text()
    report_runtime_source = (ROOT / "nmapui" / "report_runtime.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "from nmapui.report_runtime import (" in app_source
    assert "from nmapui.app_composition import (" in app_source
    assert "generate_report_task as generate_report_task_runtime" in app_source
    assert "generate_pdf_from_saved_task as generate_pdf_from_saved_task_runtime" in app_source
    assert "build_scan_task_deps(" in app_source
    assert "build_report_task_deps(" in app_source
    assert "build_saved_pdf_task_deps(" in app_source
    assert "build_report_workflow_context(" in report_runtime_source
    assert "class ScanWorkflowContext" in workflow_context_source
    assert "class ReportWorkflowContext" in workflow_context_source
    assert "context = build_scan_workflow_context(" in scan_runtime_source
    assert "workflow_generate_report_task(build_report_workflow_context(deps), sid, data)" in report_runtime_source
    assert "def build_scan_task_deps(" in app_composition_source
    assert "def build_report_task_deps(" in app_composition_source
    assert "def build_saved_pdf_task_deps(" in app_composition_source
    assert "def identify_gateway_firewall_targets(" not in app_source
    assert "def start_deep_scan(" not in app_source
    assert '"cve_pattern":' not in app_source
    assert '"port_info_regex":' not in app_source
    assert '"ip_regex":' not in app_source


def test_app_uses_shared_validation_helpers():
    app_source = (ROOT / "app.py").read_text()

    assert "from nmapui.validation import validate_target" in app_source
    assert "def validate_target(" not in app_source


def test_app_uses_shared_saved_pdf_helpers():
    app_source = (ROOT / "app.py").read_text()
    report_runtime_source = (ROOT / "nmapui" / "report_runtime.py").read_text()

    assert "find_latest_saved_scan_for_pdf," in app_source
    assert "generate_pdf_from_saved_task as generate_pdf_from_saved_task_runtime" in app_source
    assert "return generate_pdf_from_saved_task_runtime(" in app_source
    assert "return generate_pdf_from_saved_task_impl(deps, sid, data)" in report_runtime_source
    assert "def find_latest_saved_scan_for_pdf(" not in app_source


def test_app_uses_shared_scan_chunking_helper():
    app_source = (ROOT / "app.py").read_text()

    assert "split_subnet_into_chunks," in app_source
    assert "def split_subnet_into_chunks(" not in app_source


def test_app_uses_shared_private_ip_helper():
    app_source = (ROOT / "app.py").read_text()

    assert "is_private_ip," in app_source
    assert "def is_private_ip(" not in app_source


def test_app_uses_tool_version_registry_accessor_directly():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert '"get_versions": get_versions' in app_composition_source
    assert "def get_versions(" not in app_source


def test_app_uses_single_traceroute_dependency_bundle():
    app_source = (ROOT / "app.py").read_text()
    traceroute_runtime_source = (ROOT / "nmapui" / "traceroute_runtime.py").read_text()

    assert "def _traceroute_deps():" in app_source
    assert "return build_traceroute_deps(" in app_source
    assert "run_traceroute as run_traceroute_runtime" in app_source
    assert "run_traceroute_for_state(target, sid=sid, deps=deps)" in traceroute_runtime_source


def test_app_uses_shared_startup_dependency_builder():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "build_startup_check_deps(" in app_source
    assert "def build_startup_check_deps(" in app_composition_source


def test_app_uses_shared_handler_registration_builders():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "register_shared_handlers(" in app_source
    assert "build_auto_scan_handler_deps(" in app_source
    assert "build_scan_routes_deps(" in app_source
    assert "build_history_handler_deps(" in app_source
    assert "build_update_handler_deps(" in app_source
    assert "build_connection_handler_deps(" in app_source
    assert "build_core_routes_deps(" in app_source
    assert "build_customer_handler_deps(" in app_source
    assert "build_runtime_info_handler_deps(" in app_source
    assert "build_scan_job_handler_deps(" in app_source
    assert "def register_shared_handlers(" in app_composition_source
    assert "def build_auto_scan_handler_deps(" in app_composition_source
    assert "def build_scan_routes_deps(" in app_composition_source
    assert "def build_history_handler_deps(" in app_composition_source
    assert "def build_update_handler_deps(" in app_composition_source
    assert "def build_connection_handler_deps(" in app_composition_source
    assert "def build_core_routes_deps(" in app_composition_source
    assert "def build_customer_handler_deps(" in app_composition_source
    assert "def build_runtime_info_handler_deps(" in app_composition_source
    assert "def build_scan_job_handler_deps(" in app_composition_source
    assert "register_auto_scan_handlers(" not in app_source
    assert "register_scan_routes(" not in app_source
    assert "register_history_handlers(" not in app_source
    assert "register_update_handlers(" not in app_source
    assert "register_connection_handlers(" not in app_source
    assert "register_core_routes(" not in app_source
    assert "register_customer_handlers(" not in app_source
    assert "register_runtime_info_handlers(" not in app_source
    assert "register_scan_job_handlers(" not in app_source


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
    assert "reportSocket.emit('generate_report'" in report_generation_module
    assert "chunked: false" in report_generation_module
    assert "chunked: true" in report_generation_module
    assert "socket.on('client_state_snapshot'" in report_generation_module
    assert "document.getElementById('generate-report-btn').addEventListener('click'" in report_generation_module
    assert "document.getElementById('chunked-scan-btn')?.addEventListener('click'" in report_generation_module
    assert "socket.on('scan_results'" in report_generation_module
    assert "function getLastScanTarget()" in report_generation_module


def test_template_does_not_keep_inline_report_generation_block():
    template = (ROOT / "templates" / "index.html").read_text()

    assert "document.getElementById('generate-report-btn').addEventListener('click'" not in template
    assert "function startReportTimer()" not in template
    assert "function stopReportTimer()" not in template
    assert "const clientJobs =" not in template
    assert "let autoScanEnabled = false;" not in template
    assert "getClientJobs: window.getClientJobs" in template
    assert "getLastScanTarget: window.getLastScanTarget" in template
    assert "Complete + PDF" in template
    assert 'aria-label="Run a complete scan and generate a new PDF"' in template


def test_pdf_generation_prefers_browser_renderer_before_wkhtml():
    reporting_source = (ROOT / "nmapui" / "reporting.py").read_text()

    assert 'feedback("Trying browser-quality PDF rendering with Playwright")' in reporting_source
    assert 'await page.emulate_media(media="print")' in reporting_source
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
    assert "function formatReportCompleteMessage(data)" in discovery_module
    assert "showReportStatus(formatReportCompleteMessage(data), 'success');" in discovery_module
    assert "cell.innerHTML = items.map" not in template
    assert "data.cve_array.forEach(cve => cell.innerHTML +=" not in template
    assert "row.cells[4].innerHTML +=" not in template


def test_template_uses_dom_helpers_for_asset_modal_and_history_rendering():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    live_template = (ROOT / "templates" / "index.html").read_text()
    asset_module = (ROOT / "static" / "js" / "asset_details_modal.js").read_text()
    layout_module = (ROOT / "static" / "js" / "layout_runtime.js").read_text()

    assert "function renderAssetServices(asset)" in asset_module
    assert "function renderAssetVulnerabilities(asset)" in asset_module
    assert "function renderHistoryState(message, isError = false)" in layout_module
    assert "function createHistoryDiffSummary(diffSummary)" in layout_module
    assert "function renderHistoryList(scans)" in layout_module
    assert "createHistoryDiffSummary(scan.diff_summary)" in layout_module
    assert 'id="history-changed-filter"' in live_template
    assert 'document.getElementById("history-changed-filter").checked' in (ROOT / "static" / "js" / "history_modal.js").read_text()
    assert 'scans = scans.filter((scan) => scan.diff_summary?.has_changes);' in (ROOT / "static" / "js" / "history_modal.js").read_text()
    assert "details.className = 'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8';" not in layout_module
    assert "serviceDiv.innerHTML =" not in template
    assert "cveDiv.innerHTML =" not in template
    assert "historyList.innerHTML = scans.map" not in template
