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
        "socket.on('quick_scan_start', () => {",
        "socket.on('quick_scan_complete', () => {",
        "socket.on('arp_scan_start', () => {",
        "socket.on('arp_scan_complete', () => {",
        "socket.on('deep_scan_start', () => {",
        "socket.on('deep_scan_host_start', (data) => {",
        "socket.on('deep_scan_host_complete', (data) => {",
        "socket.on('deep_scan_complete', () => {",
        "socket.on('scan_feedback', msg => {",
        "socket.on('local_ip', data => {",
        "socket.on('network_key', data => {",
        "socket.on('customers_list', data => {",
        "socket.on('customer_info', data => {",
        "socket.on('versions', data => {",
        "socket.on('history_counts', data => {",
        "socket.on('report_complete', function(data) {",
        "socket.on('report_error', function(data) {",
        "socket.on('arp_results', data => {",
    ):
        assert duplicated_handler not in html


def test_template_uses_shared_table_sorter_module():
    html = (ROOT / "templates" / "index.html").read_text()
    sorter_source = (ROOT / "static" / "js" / "table_sorter.js").read_text()

    assert '<script src="/static/js/table_sorter.js"></script>' in html
    assert "window.tableSorter = new TableSorter('discovery-table');" in html
    assert "class TableSorter {" not in html
    assert "window.TableSorter = TableSorter;" in sorter_source


def test_template_uses_site_chrome_module():
    html = (ROOT / "templates" / "index.html").read_text()
    site_chrome_source = (ROOT / "static" / "js" / "site_chrome.js").read_text()

    assert '<script src="/static/js/site_chrome.js"></script>' in html
    assert "initializeSiteChrome();" in html
    assert "<!-- 2026 New Sites JavaScript Functionality -->" not in html
    assert "const mobileMenuBtn = document.getElementById('mobile-menu-btn');" not in html
    assert "const searchInput = document.getElementById('global-search');" not in html
    assert "window.initializeSiteChrome = initializeSiteChrome;" in site_chrome_source


def test_template_uses_shared_scan_display_modules():
    html = (ROOT / "templates" / "index.html").read_text()
    discovery_source = (ROOT / "static" / "js" / "discovery_ui.js").read_text()
    banner_source = (ROOT / "static" / "js" / "scan_banners.js").read_text()

    assert '<script src="/static/js/scan_banners.js"></script>' in html
    assert "window.socket = socket;" in html
    assert "function startPreciseClock()" not in html
    assert "function saveHostsToStorage()" not in html
    assert "function loadHostsFromStorage()" not in html
    assert "function showHistoricalDataBanner(data)" not in html
    assert "function showScanSummaryBanner(data)" not in html
    assert "function showUpdateModal()" not in html
    assert "window.saveHostsToStorage = saveHostsToStorage;" in discovery_source
    assert "window.loadHostsFromStorage = loadHostsFromStorage;" in discovery_source
    assert "window.showHistoricalDataBanner = showHistoricalDataBanner;" in banner_source
    assert "window.showScanSummaryBanner = showScanSummaryBanner;" in banner_source


def test_template_uses_shared_customer_ui_module():
    html = (ROOT / "templates" / "index.html").read_text()
    customer_source = (ROOT / "static" / "js" / "customer_ui.js").read_text()

    assert "initializeCustomerUI(socket);" in html
    assert "function showCustomerForm()" not in html
    assert "function addCustomer()" not in html
    assert "socket.on('customer_added'" not in html
    assert "socket.on('customer_identified'" not in html
    assert "window.initializeCustomerUI = initializeCustomerUI;" in customer_source
    assert "window.addCustomer = () => {" in customer_source
    assert "window.assignCustomer = () => {" in customer_source


def test_template_uses_shared_report_status_module():
    html = (ROOT / "templates" / "index.html").read_text()
    report_status_source = (ROOT / "static" / "js" / "report_status.js").read_text()

    assert '<script src="/static/js/report_status.js"></script>' in html
    assert "showReportStatus: window.showReportStatus" in html
    assert "function removeReportProgressCard()" not in html
    assert "function showReportStatus(message, type)" not in html
    assert "window.showReportStatus = showReportStatus;" in report_status_source
    assert "window.removeReportProgressCard = removeReportProgressCard;" in report_status_source


def test_template_uses_shared_auto_update_banner_module():
    html = (ROOT / "templates" / "index.html").read_text()
    auto_update_source = (ROOT / "static" / "js" / "auto_update_banner.js").read_text()

    assert '<script src="/static/js/auto_update_banner.js"></script>' in html
    assert "initializeAutoUpdateBanner(socket);" in html
    assert "let countdownInterval = null;" not in html
    assert "function showAutoUpdateBanner(updateInfo)" not in html
    assert "function performAutoUpdate()" not in html
    assert "function bindAutoUpdateButtons()" in auto_update_source
    assert "let autoUpdateBannerInitialized = false;" in auto_update_source
    assert "bindAutoUpdateButtons();" in auto_update_source


def test_wrapper_contract_uses_single_supported_launcher():
    build_script = (ROOT / "build.sh").read_text()

    assert 'PACKAGING_DIR="$ROOT_DIR/packaging/macos"' in build_script
    assert "ROOT_RUNTIME_PY=(" in build_script
    assert "customer_fingerprint_matcher.py" in build_script
    assert "customer_fingerprint_store.py" in build_script
    assert 'SRC="$PACKAGING_DIR/NmapUIMenuBarLauncher.swift"' in build_script
    assert not (ROOT / "NmapUIMenuBar.swift").exists()
    assert not (ROOT / "NmapUIMenuBarSimple.swift").exists()
    assert not (ROOT / "NmapUIMenuBarWithServer.swift").exists()
    assert (ROOT / "packaging" / "macos" / "NmapUIMenuBarLauncher.swift").exists()
    assert 'HOST_ARCH="$(uname -m)"' in build_script
    assert 'if [[ -n "${NMAPUI_SWIFT_TARGET:-}" ]]; then' in build_script
    assert 'SWIFT_TARGET="$NMAPUI_SWIFT_TARGET"' in build_script
    assert 'elif [[ "$HOST_ARCH" == "arm64" ]]; then' in build_script
    assert 'SWIFT_TARGET="arm64-apple-macosx13.0"' in build_script
    assert 'elif [[ "$HOST_ARCH" == "x86_64" ]]; then' in build_script
    assert 'SWIFT_TARGET="x86_64-apple-macosx13.0"' in build_script
    assert 'echo "Host architecture: $HOST_ARCH"' in build_script
    assert 'echo "Target: $SWIFT_TARGET"' in build_script
    assert '  -target "$SWIFT_TARGET" \\' in build_script
    assert 'if [[ "${NMAPUI_SKIP_OPEN:-}" == "1" ]]; then' in build_script
    assert 'echo "Skipping application auto-open because NMAPUI_SKIP_OPEN=1"' in build_script
    assert "export NMAPUI_ALLOW_UNSAFE_WERKZEUG=true" in build_script
    assert "export NMAPUI_TRUST_LOCAL_UI=true" in build_script
    assert 'BUNDLE_PLAYWRIGHT_BROWSERS="$APP_NAME/Contents/Resources/playwright-browsers"' in build_script
    assert 'PLAYWRIGHT_BROWSERS_PATH="$BUNDLE_PLAYWRIGHT_BROWSERS" python -m playwright install chromium' in build_script
    assert 'export PLAYWRIGHT_BROWSERS_PATH="$(pwd)/playwright-browsers"' in build_script


def test_wrapper_docs_reference_current_local_port():
    for doc_name in ("README.md", "packaging/macos/README.md", "packaging/macos/SETUP.md"):
        source = (ROOT / doc_name).read_text()
        assert "127.0.0.1:9000" in source
        assert "localhost:9999" not in source
    assert "NMAPUI_SWIFT_TARGET" in (ROOT / "README.md").read_text()


def test_pyinstaller_spec_includes_runtime_assets():
    spec = (ROOT / "packaging" / "pyinstaller" / "nmapui.spec").read_text()

    assert "config" in spec
    assert "VERSION" in spec
    assert "nmap-modern.xsl" in spec
    assert "nmap-pdf-olive-legacy.xsl" in spec
    assert "'playwright.async_api'" in spec
    assert "'eventlet'" not in spec
    assert "'gevent'" not in spec
    assert "'geventwebsocket'" not in spec
    assert "'weasyprint'" not in spec
    assert "'LSMinimumSystemVersion': '13.0'" in spec


def test_runtime_uses_separate_web_and_pdf_stylesheets():
    paths_source = (ROOT / "nmapui" / "paths.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert 'XSL_STYLESHEET = BASE_DIR / "nmap-modern.xsl"' in paths_source
    assert 'XSL_STYLESHEET_PDF = BASE_DIR / "nmap-pdf-olive-legacy.xsl"' in paths_source
    assert 'RUNTIME_DB_FILE = BASE_DIR / "data" / "runtime.sqlite3"' in paths_source
    assert 'GOOGLE_DRIVE_CREDENTIALS_FILE = BASE_DIR / "config" / "google_drive_credentials.json"' in paths_source
    assert '"web_stylesheet": web_stylesheet' in app_composition_source
    assert '"pdf_stylesheet": pdf_stylesheet' in app_composition_source


def test_runtime_sqlite_store_schema_exists():
    runtime_db_source = (ROOT / "nmapui" / "runtime_db.py").read_text()
    app_source = (ROOT / "app.py").read_text()
    runtime_services_source = (ROOT / "nmapui" / "runtime_services.py").read_text()
    runtime_history_source = (ROOT / "nmapui" / "runtime_history.py").read_text()

    assert "CREATE TABLE IF NOT EXISTS runtime_snapshots" in runtime_db_source
    assert "CREATE TABLE IF NOT EXISTS jobs" in runtime_db_source
    assert "CREATE TABLE IF NOT EXISTS job_events" in runtime_db_source
    assert "CREATE TABLE IF NOT EXISTS report_artifacts" in runtime_db_source
    assert "CREATE TABLE IF NOT EXISTS runtime_logs" in runtime_db_source
    assert "def list_jobs(" in runtime_db_source
    assert "def get_report_artifact(" in runtime_db_source
    assert "def delete_report_artifact(" in runtime_db_source
    assert "def append_job_event(" in runtime_db_source
    assert "def list_job_events(" in runtime_db_source
    assert "def create_runtime_state_store" in runtime_db_source
    assert "runtime_store = create_runtime_state_store(RUNTIME_DB_FILE)" in app_source
    assert '"runtime_store": runtime_store' in runtime_services_source
    assert "def _load_runtime_defaults(runtime_store):" in runtime_services_source
    assert 'saved_customer = runtime_store.get_runtime_snapshot("current_customer")' in runtime_services_source
    assert 'saved_network_key = runtime_store.get_runtime_snapshot("network_key")' in runtime_services_source
    assert 'saved_last_scan_target = runtime_store.get_runtime_snapshot("last_scan_target")' in runtime_services_source
    assert '"runtime_store": runtime_store' in (ROOT / "nmapui" / "app_composition.py").read_text()
    assert "def persist_report_artifact(" in (ROOT / "nmapui" / "reporting.py").read_text()
    assert "def normalize_runtime_report_row(artifact):" in runtime_history_source
    assert "def build_history_rows(" in runtime_history_source
    assert "def build_compare_result(" in runtime_history_source
    assert "def _backfill_runtime_artifact(" in runtime_history_source
    assert "def backfill_runtime_history_artifacts(" in runtime_history_source
    assert "backfill_runtime_history_artifacts(" in app_source
    assert '"runtime_store": runtime_store' in (ROOT / "nmapui" / "app_composition.py").read_text()


def test_runtime_backfill_admin_script_exists():
    script_source = (ROOT / "scripts" / "backfill_runtime_store.py").read_text()
    readme_source = (ROOT / "README.md").read_text()

    assert "def main():" in script_source
    assert "backfill_runtime_history_artifacts(" in script_source
    assert "create_runtime_state_store(" in script_source
    assert "scripts/backfill_runtime_store.py" in readme_source


def test_runtime_logs_route_and_ui_hydration_exist():
    routes_source = (ROOT / "nmapui" / "handlers" / "routes.py").read_text()
    audit_log_source = (ROOT / "static" / "js" / "audit_log.js").read_text()
    app_bindings_source = (ROOT / "nmapui" / "app_bindings.py").read_text()
    reports_tab_source = (ROOT / "static" / "js" / "reports_tab.js").read_text()
    history_modal_source = (ROOT / "static" / "js" / "history_modal.js").read_text()
    runtime_history_source = (ROOT / "nmapui" / "runtime_history.py").read_text()

    assert '@app.route("/api/runtime/logs")' in routes_source
    assert '@app.route("/api/runtime/reports")' in routes_source
    assert '@app.route("/api/runtime/reports/<path:scan_path>/html")' in routes_source
    assert '@app.route("/api/runtime/reports/<path:scan_path>/pdf")' in routes_source
    assert '@app.route("/api/runtime/reports/<path:scan_path>/xml")' in routes_source
    assert '@app.route("/api/runtime/history")' in routes_source
    assert '@app.route("/api/runtime/maintenance/backfill", methods=["POST"])' in routes_source
    assert '@app.route("/api/runtime/history/compare")' in routes_source
    assert 'runtime_store.get_recent_logs(' in routes_source
    assert 'runtime_store.get_runtime_snapshot("maintenance_backfill_status")' in routes_source
    assert 'runtime_store.upsert_runtime_snapshot(' in routes_source
    assert "runtime_store.list_report_artifacts()" in routes_source
    assert "build_history_rows(" in routes_source
    assert "build_compare_result(" in routes_source
    assert "backfill_runtime_history_artifacts(" in routes_source
    assert "iter_scan_metadata_documents(" in runtime_history_source
    assert "runtime_store.upsert_report_artifact(" in runtime_history_source
    assert "runtime_store.get_report_artifact(rel_path)" in runtime_history_source
    assert "function loadPersistedLogs()" in audit_log_source
    assert "fetch('/api/runtime/logs?limit=200')" in audit_log_source
    assert "function refreshPersistedLogs()" in audit_log_source
    assert "function schedulePersistedLogRefresh()" in audit_log_source
    assert "replacePersistedLogs(entries.slice().reverse());" in audit_log_source
    assert "async function fetchReportsForTab()" in reports_tab_source
    assert "fetch('/api/runtime/reports')" in reports_tab_source
    assert "fetch('/api/runtime/history')" in reports_tab_source
    assert 'fetch("/api/runtime/history")' in history_modal_source
    assert "_log_runtime_event(runtime_store, event, data)" in app_bindings_source
    assert 'category="job"' in app_bindings_source


def test_connection_handler_prefers_sqlite_snapshots_without_active_owner():
    connections_source = (ROOT / "nmapui" / "handlers" / "connections.py").read_text()
    app_handler_registration_source = (ROOT / "nmapui" / "app_handler_registration.py").read_text()

    assert "def _load_persisted_source_state(runtime_store):" in connections_source
    assert "def _load_persisted_active_job(runtime_store):" in connections_source
    assert "def _load_persisted_job_events(runtime_store, job_id):" in connections_source
    assert 'runtime_store.list_jobs(statuses=("running", "cancelling"), limit=1)' in connections_source
    assert 'runtime_store.list_job_events(job_id=job_id, limit=200)' in connections_source
    assert 'runtime_store.get_runtime_snapshot("current_customer")' in connections_source
    assert 'runtime_store.get_runtime_snapshot("network_key")' in connections_source
    assert 'runtime_store.get_runtime_snapshot("last_scan_target")' in connections_source
    assert "source_state = _load_persisted_source_state(runtime_store) or get_client_state()" in connections_source
    assert 'emit_to_client(new_sid, "job_status", persisted_job)' in connections_source
    assert 'emit_to_client(new_sid, event["event_name"], event["payload"])' in connections_source
    assert "runtime_store=runtime_store" in app_handler_registration_source


def test_scan_routes_accept_runtime_store_artifact_reads():
    scans_source = (ROOT / "nmapui" / "handlers" / "scans.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()
    app_handler_registration_source = (ROOT / "nmapui" / "app_handler_registration.py").read_text()
    reporting_source = (ROOT / "nmapui" / "reporting.py").read_text()

    assert "runtime_store = deps.get(\"runtime_store\")" in scans_source
    assert "build_history_rows(" in scans_source
    assert "build_scan_routes_deps(" in app_handler_registration_source
    assert '"runtime_store": runtime_store' in app_composition_source
    assert "build_compare_result(" in scans_source
    assert "def _load_runtime_artifact_payload(runtime_store, path):" in scans_source
    assert "def _resolve_runtime_artifact_path(*, runtime_store, scans_dir, scan_path, stored_path, default_name):" in scans_source
    assert 'stored_path=artifact.get("html_path") if artifact else None,' in scans_source
    assert 'stored_path=artifact.get("pdf_path") if artifact else None,' in scans_source
    assert 'stored_path=artifact.get("xml_path") if artifact else None,' in scans_source
    assert 'artifact_payload.get("downloads", {}).get("pdf", download_name)' in scans_source
    assert 'artifact_payload.get("downloads", {}).get("xml", download_name)' in scans_source
    assert "runtime_store.delete_report_artifact(path)" in scans_source
    assert "def build_artifact_downloads(metadata):" in reporting_source
    assert '"downloads": build_artifact_downloads(normalized_metadata),' in reporting_source


def test_history_and_saved_pdf_lookups_accept_runtime_store():
    reporting_source = (ROOT / "nmapui" / "reporting.py").read_text()
    history_source = (ROOT / "nmapui" / "handlers" / "history.py").read_text()
    task_bindings_source = (ROOT / "nmapui" / "app_task_bindings.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "def _resolve_artifact_file_path(*, scans_dir, scan_path, stored_path, default_name):" in reporting_source
    assert "def get_most_recent_scan_xml(" in reporting_source
    assert "runtime_store=None" in reporting_source
    assert "runtime_store.list_report_artifacts(customer_id=customer_id)" in reporting_source
    assert "def find_latest_saved_scan_for_pdf(" in reporting_source
    assert "runtime_store=runtime_store" in task_bindings_source
    assert '"runtime_store": runtime_store' in app_composition_source
    assert "runtime_store = deps.get(\"runtime_store\")" in history_source
    assert "runtime_store=runtime_store," in history_source


def test_failed_scan_persistence_accepts_runtime_store():
    reporting_source = (ROOT / "nmapui" / "reporting.py").read_text()
    workflows_source = (ROOT / "nmapui" / "workflows.py").read_text()

    assert "def mark_scan_failure(" in reporting_source
    assert "runtime_store=None" in reporting_source
    assert "persist_report_artifact(" in reporting_source
    assert "runtime_store=runtime_store," in reporting_source
    assert "stage=\"scan_chunks\",\n                            runtime_store=context.runtime_store," in workflows_source
    assert "stage=\"exception\",\n                runtime_store=context.runtime_store," in workflows_source


def test_pdf_stylesheet_stays_print_first_while_web_stylesheet_stays_interactive():
    pdf_stylesheet = (ROOT / "nmap-pdf-olive-legacy.xsl").read_text()
    web_stylesheet = (ROOT / "nmap-modern.xsl").read_text()
    strategy = (ROOT / "docs" / "guides" / "REPORT_STYLESHEET_STRATEGY.md").read_text()

    assert "cdn.datatables.net" not in pdf_stylesheet
    assert "code.jquery.com" not in pdf_stylesheet
    assert "$('#table-services').DataTable" not in pdf_stylesheet
    assert "@media print" in pdf_stylesheet
    assert "cdn.datatables.net" in web_stylesheet
    assert "$('#table-services').DataTable" in web_stylesheet
    assert "nmap-modern.xsl" in strategy
    assert "nmap-pdf-olive-legacy.xsl" in strategy
    assert "#scannedhosts" in strategy
    assert "#openservices" in strategy
    assert "#onlinehosts" in strategy
    assert "DataTables CSS and JS" in strategy
    assert "Playwright PDF rendering under `print` media" in strategy


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
    assert 'PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.playwright-browsers"' in install_script
    assert "python -m playwright install chromium" in install_script
    assert 'export PLAYWRIGHT_BROWSERS_PATH="$ROOT_DIR/.playwright-browsers"' in install_script


def test_local_playwright_browser_cache_is_gitignored():
    gitignore = (ROOT / ".gitignore").read_text()

    assert ".playwright-browsers/" in gitignore


def test_packaged_smoke_test_exists_and_is_gated():
    smoke_source = (ROOT / "tests" / "test_packaged_app_smoke.py").read_text()

    assert 'sys.platform != "darwin"' in smoke_source
    assert 'NMAPUI_RUN_PACKAGED_SMOKE' in smoke_source
    assert 'NMAPUI_SKIP_OPEN' in smoke_source
    assert 'build.sh' in smoke_source
    assert '/api/health/live' in smoke_source


def test_browser_regression_test_exists_and_is_gated():
    browser_source = (ROOT / "tests" / "test_browser_regressions.py").read_text()

    assert "NMAPUI_RUN_BROWSER_REGRESSION" in browser_source
    assert "from playwright.sync_api import sync_playwright" in browser_source
    assert "#tab-reports-btn" in browser_source
    assert "#history-tab-list" in browser_source
    assert "test_second_tab_replays_active_report_state" in browser_source


def test_customer_fingerprinter_uses_extracted_store_services():
    fingerprinter_source = (ROOT / "customer_fingerprint.py").read_text()
    store_source = (ROOT / "customer_fingerprint_store.py").read_text()
    matcher_source = (ROOT / "customer_fingerprint_matcher.py").read_text()

    assert "from customer_fingerprint_store import CustomerFingerprintStore, ScanHistoryStore" in fingerprinter_source
    assert "from customer_fingerprint_matcher import CustomerFingerprintMatcher" in fingerprinter_source
    assert "self.store = CustomerFingerprintStore(" in fingerprinter_source
    assert "self.scan_history_store = ScanHistoryStore(" in fingerprinter_source
    assert "self.matcher = CustomerFingerprintMatcher(" in fingerprinter_source
    assert "matched_customer, confidence = self.matcher.match_customer(" in fingerprinter_source
    assert "self.last_match_method = self.matcher.last_match_method" in fingerprinter_source
    assert "class CustomerFingerprintStore:" in store_source
    assert "class ScanHistoryStore:" in store_source
    assert "class CustomerFingerprintMatcher:" in matcher_source
    assert "def match_customer(" in matcher_source


def test_socket_event_docs_match_current_runtime_contract():
    docs = (ROOT / "docs" / "socket-events.md").read_text()
    runtime_info = (ROOT / "nmapui" / "handlers" / "runtime_info.py").read_text()
    history = (ROOT / "nmapui" / "handlers" / "history.py").read_text()
    updates = (ROOT / "nmapui" / "handlers" / "updates.py").read_text()
    connections = (ROOT / "nmapui" / "handlers" / "connections.py").read_text()
    scan_jobs = (ROOT / "nmapui" / "handlers" / "scan_jobs.py").read_text()

    assert "It is pinned by regression tests" in docs
    assert "`local_ip` | `S -> C` | `{ local_ip, subnet_mask, public_ip, cidr, interface }`" in docs
    assert "`history_counts` | `S -> C` | direct count document" in docs
    assert "`resumable_scan_check` `S -> C` with either `{ available: false }`" in docs
    assert "`customers_list` | `S -> C` | `Customer[]`" in docs
    assert "`generate_pdf_from_saved` | `C -> S` | saved-report PDF request payload" in docs
    assert "`update_error` | `S -> C` | `{ message }`" in docs
    assert "`client_state_snapshot` | `S -> C` | `{ last_scan_target?: string }`" in docs
    assert "`update_complete` | `S -> C` | `{ message }`" in docs
    assert "`scan_results` is intentionally overloaded" in docs

    assert '"local_ip": local_ip' in runtime_info
    assert 'emit("history_counts", get_report_counts())' in runtime_info
    assert 'emit("resumable_scan_check", {"available": False})' in history
    assert 'emit("update_error", {"message":' in updates
    assert '"client_state_snapshot"' in connections
    assert '@socketio.on("generate_pdf_from_saved")' in scan_jobs


def test_update_runtime_uses_manual_download_contract():
    runtime_source = (ROOT / "nmapui" / "runtime.py").read_text()
    updates_source = (ROOT / "nmapui" / "handlers" / "updates.py").read_text()
    update_modal_source = (ROOT / "static" / "js" / "update_modal.js").read_text()
    auto_update_source = (ROOT / "static" / "js" / "auto_update_banner.js").read_text()

    assert 'def _select_release_asset(' in runtime_source
    assert '"install_method": "manual_download"' in runtime_source
    assert '"asset_name": asset_name' in runtime_source
    assert '"current_version": current_version' in runtime_source
    assert 'Manual install required. Download the installer, complete installation, then relaunch NmapUI.' in updates_source
    assert '"manual_install": True' in updates_source
    assert 'socket.on("update_complete", (data) => {' in update_modal_source
    assert "Opening installer download..." in update_modal_source
    assert "Installer download will open when the countdown ends." in update_modal_source
    assert "is available to download" in auto_update_source


def test_runtime_status_route_and_menu_bar_indicator_contract():
    routes_source = (ROOT / "nmapui" / "handlers" / "routes.py").read_text()
    jobs_source = (ROOT / "nmapui" / "jobs.py").read_text()
    composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()
    app_source = (ROOT / "app.py").read_text()
    launcher_source = (
        ROOT / "packaging" / "macos" / "NmapUIMenuBarLauncher.swift"
    ).read_text()

    assert '@app.route("/api/runtime/status")' in routes_source
    assert '"active_job_types": sorted(' in routes_source
    assert "def snapshot(self):" in jobs_source
    assert '"has_active_jobs": bool(active_jobs)' in jobs_source
    assert '"job_registry": job_registry' in composition_source
    assert "job_registry=job_registry," in app_source
    assert 'let runtimeStatusURL = URL(string: "http://127.0.0.1:9000/api/runtime/status")!' in launcher_source
    assert "startStatusPolling()" in launcher_source
    assert "pollRuntimeStatus()" in launcher_source
    assert "Recent scan or report completed" in launcher_source
    assert 'symbolName = "dot.radiowaves.left.and.right"' in launcher_source
    assert 'symbolName = "checkmark.circle.fill"' in launcher_source


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
    assert "run_server_runtime(" in app_source
    assert 'cors_allowed_origins="*"' not in app_source


def test_app_delegates_state_persistence_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_state_runtime_source = (ROOT / "nmapui" / "app_state_runtime.py").read_text()
    app_runtime_bindings_source = (
        ROOT / "nmapui" / "app_runtime_bindings.py"
    ).read_text()

    assert "from nmapui.app_runtime_bindings import (" in app_source
    assert "build_state_bindings," in app_source
    assert 'state_bindings = build_state_bindings(' in app_source
    assert 'get_report_counts = state_bindings["get_report_counts"]' in app_source
    assert 'save_customers_config = state_bindings["save_customers_config"]' in app_source
    assert 'save_current_assignment = state_bindings["save_current_assignment"]' in app_source
    assert 'current_assignment_loader=state_bindings["load_current_assignment"]' in app_source
    assert 'load_current_assignment = runtime_bindings["load_current_assignment"]' in app_source
    assert "def build_state_bindings(" in app_runtime_bindings_source
    assert "return get_report_counts_runtime(" in app_runtime_bindings_source
    assert "save_current_assignment_runtime(" in app_runtime_bindings_source
    assert "save_customers_config_runtime(" in app_runtime_bindings_source
    assert "load_current_assignment_runtime(" in app_runtime_bindings_source
    assert "return get_report_counts_impl(" in app_state_runtime_source


def test_app_delegates_client_state_wrappers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_client_state_runtime_source = (
        ROOT / "nmapui" / "app_client_state_runtime.py"
    ).read_text()
    app_bindings_source = (ROOT / "nmapui" / "app_bindings.py").read_text()

    assert "from nmapui.app_bindings import build_client_state_helpers, build_event_helpers" in app_source
    assert 'client_state_helpers = build_client_state_helpers(' in app_source
    assert "runtime_store=runtime_store" in app_source
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
    assert 'persist_snapshot("current_customer", result)' in app_bindings_source
    assert 'persist_snapshot("network_key", result)' in app_bindings_source
    assert 'persist_snapshot("last_scan_target", {"value": result})' in app_bindings_source
    assert "client_state_registry.release(sid)" in app_client_state_runtime_source
    assert "if sid is not None and sync_default_state is not None:" in app_client_state_runtime_source


def test_app_delegates_event_and_job_wrappers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_events_runtime_source = (ROOT / "nmapui" / "app_events_runtime.py").read_text()
    app_runtime_bindings_source = (
        ROOT / "nmapui" / "app_runtime_bindings.py"
    ).read_text()
    app_bindings_source = (ROOT / "nmapui" / "app_bindings.py").read_text()

    assert "from nmapui.app_bindings import build_client_state_helpers, build_event_helpers" in app_source
    assert 'event_helpers = build_event_helpers(' in app_source
    assert 'emit_to_client = event_helpers["emit_to_client"]' in app_source
    assert 'emit_job_status = event_helpers["emit_job_status"]' in app_source
    assert 'update_job_progress = event_helpers["update_job_progress"]' in app_source
    assert 'ensure_job_not_cancelled = event_helpers["ensure_job_not_cancelled"]' in app_source
    assert 'run_cancellable_command = event_helpers["run_cancellable_command"]' in app_source
    assert "build_runtime_bindings," in app_source
    assert 'runtime_bindings = build_runtime_bindings(' in app_source
    assert 'return runtime_bindings["safe_emit"](event, data)' in app_source
    assert "safe_emit as safe_emit_runtime" in app_runtime_bindings_source
    assert "def safe_emit(event, data=None):" in app_runtime_bindings_source
    assert "def build_event_helpers(" in app_bindings_source
    assert "return nmapui_emit_to_client(" not in app_source
    assert "return nmapui_run_cancellable_command(" not in app_source
    assert "return nmapui_emit_to_client(socketio, sid, event, data)" in app_events_runtime_source


def test_app_delegates_runtime_info_events_to_handler_module():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()
    app_handler_registration_source = (ROOT / "nmapui" / "app_handler_registration.py").read_text()

    assert "register_app_handlers(" in app_source
    assert "from nmapui.handlers.runtime_info import register_runtime_info_handlers" in app_composition_source
    assert "build_runtime_info_handler_deps(" in app_handler_registration_source
    assert "register_runtime_info_handlers(socketio, runtime_info_handler_deps)" in app_composition_source
    assert '@socketio.on("get_history_counts")' not in app_source
    assert '@socketio.on("get_network_key")' not in app_source
    assert '@socketio.on("get_local_ip")' not in app_source


def test_app_delegates_startup_checks_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_runtime_source = (ROOT / "nmapui" / "app_runtime.py").read_text()
    app_runtime_bindings_source = (
        ROOT / "nmapui" / "app_runtime_bindings.py"
    ).read_text()

    assert "from nmapui.startup import create_startup_state" in app_source
    assert "from nmapui.app_runtime import (" in app_source
    assert "configure_root_logging as configure_root_logging_runtime" in app_source
    assert "run_server as run_server_runtime" in app_source
    assert "startup_checks as startup_checks_runtime" in app_source
    assert "build_runtime_bindings," in app_source
    assert "from nmapui.runtime_services import create_runtime_services" in app_source
    assert "from nmapui.tooling import ToolVersionRegistry" in app_source
    assert "runtime_services = create_runtime_services(" in app_source
    assert 'tool_versions = runtime_services["tool_versions"]' in app_source
    assert 'startup_state = runtime_services["startup_state"]' in app_source
    assert "configure_root_logging_runtime(base_dir=BASE_DIR)" in app_source
    assert "startup_checks_runtime(" in app_source
    assert 'execute_auto_scan = runtime_bindings["execute_auto_scan"]' in app_source
    assert 'start_auto_scan_thread = runtime_bindings["start_auto_scan_thread"]' in app_source
    assert "def build_runtime_bindings(" in app_runtime_bindings_source
    assert "return execute_auto_scan_runtime(" in app_runtime_bindings_source
    assert "thread_ref[\"thread\"] = start_auto_scan_thread_runtime(" in app_runtime_bindings_source
    assert "def configure_root_logging(*, base_dir):" in app_runtime_source
    assert "def run_server(" in app_runtime_source
    assert "runtime_options = build_runtime_options(argv or sys_module.argv)" in app_runtime_source
    assert "run_socketio_server(socketio, app, runtime_options)" in app_runtime_source
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
    app_handler_registration_source = (ROOT / "nmapui" / "app_handler_registration.py").read_text()

    assert "register_app_handlers(" in app_source
    assert "from nmapui.handlers.routes import register_core_routes" in app_composition_source
    assert "build_core_routes_deps(" in app_handler_registration_source
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
    app_handler_registration_source = (ROOT / "nmapui" / "app_handler_registration.py").read_text()
    app_task_bindings_source = (ROOT / "nmapui" / "app_task_bindings.py").read_text()

    assert "register_app_handlers(" in app_source
    assert "from nmapui.handlers.scan_jobs import register_scan_job_handlers" in app_composition_source
    assert "build_scan_job_handler_deps(" in app_handler_registration_source
    assert "from nmapui.app_task_bindings import build_task_bindings" in app_source
    assert "task_bindings = build_task_bindings(" in app_source
    assert 'start_scan_task = task_bindings["start_scan_task"]' in app_source
    assert 'generate_report_task = task_bindings["generate_report_task"]' in app_source
    assert 'generate_pdf_from_saved_task = task_bindings["generate_pdf_from_saved_task"]' in app_source
    assert 'run_arp_scan = task_bindings["run_arp_scan"]' in app_source
    assert 'run_nmap_with_xml_output = task_bindings["run_nmap_with_xml_output"]' in app_source
    assert "register_scan_job_handlers(socketio, scan_job_handler_deps)" in app_composition_source
    assert '@socketio.on("start_scan")' not in app_source
    assert '@socketio.on("generate_report")' not in app_source
    assert '@socketio.on("generate_pdf_from_saved")' not in app_source
    assert "def _make_broadcast_emit(" not in app_source
    assert "def _scan_workflow_context(" not in app_source
    assert "def build_task_bindings(" in app_task_bindings_source
    assert "def make_broadcast_emit(" in scan_runtime_source
    assert "return start_scan_task_impl(" in app_scan_runtime_source


def test_app_delegates_connection_handlers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()
    app_handler_registration_source = (ROOT / "nmapui" / "app_handler_registration.py").read_text()

    assert "register_app_handlers(" in app_source
    assert "from nmapui.handlers.connections import register_connection_handlers" in app_composition_source
    assert "build_connection_handler_deps(" in app_handler_registration_source
    assert "register_connection_handlers(socketio, connection_handler_deps)" in app_composition_source
    assert '@socketio.on("connect")' not in app_source


def test_app_delegates_scanning_helpers_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_scan_runtime_source = (ROOT / "nmapui" / "app_scan_runtime.py").read_text()
    app_task_bindings_source = (ROOT / "nmapui" / "app_task_bindings.py").read_text()

    assert 'run_arp_scan = task_bindings["run_arp_scan"]' in app_source
    assert 'run_nmap_with_xml_output = task_bindings["run_nmap_with_xml_output"]' in app_source
    assert "return run_arp_scan_runtime(" in app_task_bindings_source
    assert "return run_nmap_with_xml_output_runtime(" in app_task_bindings_source
    assert "return run_arp_scan_impl(" in app_scan_runtime_source
    assert "return run_nmap_with_xml_output_impl(" in app_scan_runtime_source


def test_app_delegates_auto_scan_execution_to_shared_module():
    app_source = (ROOT / "app.py").read_text()
    app_runtime_source = (ROOT / "nmapui" / "app_runtime.py").read_text()
    app_runtime_bindings_source = (
        ROOT / "nmapui" / "app_runtime_bindings.py"
    ).read_text()

    assert 'execute_auto_scan = runtime_bindings["execute_auto_scan"]' in app_source
    assert "def build_runtime_bindings(" in app_runtime_bindings_source
    assert "return execute_auto_scan_runtime(" in app_runtime_bindings_source
    assert "current_customer=get_current_customer()" in app_runtime_bindings_source
    assert "network_key=get_network_key()" in app_runtime_bindings_source
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
    app_task_bindings_source = (ROOT / "nmapui" / "app_task_bindings.py").read_text()

    assert "from nmapui.app_task_bindings import build_task_bindings" in app_source
    assert "build_scan_task_deps(" not in app_source
    assert "build_report_task_deps(" not in app_source
    assert "build_saved_pdf_task_deps(" not in app_source
    assert "build_report_workflow_context(" in report_runtime_source
    assert "class ScanWorkflowContext" in workflow_context_source
    assert "class ReportWorkflowContext" in workflow_context_source
    assert "context = build_scan_workflow_context(" in scan_runtime_source
    assert "workflow_generate_report_task(build_report_workflow_context(deps), sid, data)" in report_runtime_source
    assert 'job_type="report"' in report_runtime_source
    assert '"broadcaster": broadcaster' in app_composition_source
    assert "def build_scan_task_deps(" in app_composition_source
    assert "def build_report_task_deps(" in app_composition_source
    assert "def build_saved_pdf_task_deps(" in app_composition_source
    assert "def build_task_bindings(" in app_task_bindings_source
    assert "build_scan_task_deps(" in app_task_bindings_source
    assert "build_report_task_deps(" in app_task_bindings_source
    assert "build_saved_pdf_task_deps(" in app_task_bindings_source
    assert "start_scan_task_runtime(" in app_task_bindings_source
    assert "generate_report_task_runtime(" in app_task_bindings_source
    assert "generate_pdf_from_saved_task_runtime(" in app_task_bindings_source
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
    app_task_bindings_source = (ROOT / "nmapui" / "app_task_bindings.py").read_text()

    assert "find_latest_saved_scan_for_pdf," in app_source
    assert 'generate_pdf_from_saved_task = task_bindings["generate_pdf_from_saved_task"]' in app_source
    assert "return generate_pdf_from_saved_task_runtime(" in app_task_bindings_source
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
    app_runtime_bindings_source = (
        ROOT / "nmapui" / "app_runtime_bindings.py"
    ).read_text()

    assert "build_traceroute_bindings," in app_source
    assert 'traceroute_bindings = build_traceroute_bindings(' in app_source
    assert 'run_traceroute = traceroute_bindings["run_traceroute"]' in app_source
    assert 'deps=traceroute_bindings["traceroute_deps"](),' in app_source
    assert "run_traceroute as run_traceroute_runtime" in app_source
    assert "def build_traceroute_bindings(" in app_runtime_bindings_source
    assert "return build_traceroute_deps(" in app_runtime_bindings_source
    assert "run_traceroute_for_state(target, sid=sid, deps=deps)" in traceroute_runtime_source


def test_app_uses_shared_startup_dependency_builder():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()

    assert "build_startup_check_deps(" in app_source
    assert "def build_startup_check_deps(" in app_composition_source


def test_app_uses_shared_handler_registration_builders():
    app_source = (ROOT / "app.py").read_text()
    app_composition_source = (ROOT / "nmapui" / "app_composition.py").read_text()
    app_handler_registration_source = (ROOT / "nmapui" / "app_handler_registration.py").read_text()

    assert "from nmapui.app_handler_registration import register_app_handlers" in app_source
    assert "register_app_handlers(" in app_source
    assert "build_auto_scan_handler_deps(" not in app_source
    assert "build_scan_routes_deps(" not in app_source
    assert "build_history_handler_deps(" not in app_source
    assert "build_update_handler_deps(" not in app_source
    assert "build_connection_handler_deps(" not in app_source
    assert "build_core_routes_deps(" not in app_source
    assert "build_customer_handler_deps(" not in app_source
    assert "build_runtime_info_handler_deps(" not in app_source
    assert "build_scan_job_handler_deps(" not in app_source
    assert "def register_shared_handlers(" in app_composition_source
    assert "def register_app_handlers(" in app_handler_registration_source
    assert "register_shared_handlers(" in app_handler_registration_source
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


def test_app_delegates_root_logging_setup_to_shared_runtime_module():
    app_source = (ROOT / "app.py").read_text()
    app_runtime_source = (ROOT / "nmapui" / "app_runtime.py").read_text()

    assert "configure_root_logging_runtime(base_dir=BASE_DIR)" in app_source
    assert "RotatingFileHandler" not in app_source
    assert "_root_logger = logging.getLogger()" not in app_source
    assert "RotatingFileHandler" in app_runtime_source
    assert "root_logger._nmapui_configured = True" in app_runtime_source


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
    scan_runtime_module = (ROOT / "static" / "js" / "scan_runtime.js").read_text()
    update_modal_module = (ROOT / "static" / "js" / "update_modal.js").read_text()
    audit_log_module = (ROOT / "static" / "js" / "audit_log.js").read_text()

    assert "let getClientJobs = null;" not in report_generation_module
    assert "let reportGetClientJobs =" in report_generation_module
    assert "reportGetClientJobs = deps?.getClientJobs || window.getClientJobs || reportGetClientJobs;" in report_generation_module
    assert "let getClientJobs = null;" not in auto_scan_module
    assert "let autoScanGetClientJobs =" in auto_scan_module
    assert "autoScanGetClientJobs = deps?.getClientJobs || window.getClientJobs || autoScanGetClientJobs;" in auto_scan_module
    assert "function initializeUpdateModal(socket, deps = {})" in update_modal_module
    assert "const showReportStatus =" in update_modal_module
    assert 'const version = document.getElementById("update-version");' in update_modal_module
    assert "if (version) {" in update_modal_module
    assert 'const status = document.getElementById("update-current-status");' in update_modal_module
    assert "reportSocket.emit('generate_report'" in report_generation_module
    assert "chunked: false" in report_generation_module
    assert "chunked: true" in report_generation_module
    assert "let reportGenerationInitialized = false;" in report_generation_module
    assert "let reportActionPending = false;" in report_generation_module
    assert "if (reportGenerationInitialized) {" in report_generation_module
    assert "reportActionPending = true;" in report_generation_module
    assert "socket.on('client_state_snapshot'" in report_generation_module
    assert "socket.on('job_status', function(data) {" in report_generation_module
    assert "document.getElementById('generate-report-btn').addEventListener('click'" in report_generation_module
    assert "document.getElementById('chunked-scan-btn')?.addEventListener('click'" in report_generation_module
    assert "socket.on('scan_results'" in report_generation_module
    assert "function getLastScanTarget()" in report_generation_module
    assert "let scanRuntimeInitialized = false;" in scan_runtime_module
    assert "if (scanRuntimeInitialized) {" in scan_runtime_module
    assert "const showReportStatus = window.showReportStatus || (() => {});" in scan_runtime_module
    assert "const updateReportProgress = window.updateReportProgress || (() => {});" in scan_runtime_module
    assert "const dimExistingRows = window.dimExistingRows || (() => {});" in scan_runtime_module
    assert "const saveHostsToStorage = window.saveHostsToStorage || (() => {});" in scan_runtime_module
    assert "window.showHistoryModal()" in (ROOT / "static" / "js" / "layout_runtime.js").read_text()
    assert "const logEntries = [];" in audit_log_module
    assert "function renderLogsTab()" in audit_log_module
    assert "function initializeLogsTab()" in audit_log_module
    assert "socket.on('job_status', function (data) {" in audit_log_module
    assert "socket.on('report_complete', function (data) {" in audit_log_module
    assert "socket.on('update_status', function (data) {" in audit_log_module
    assert "window.exportVisibleLogs = exportVisibleLogs;" in audit_log_module


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
    assert 'id="report-status-actions"' in template
    assert 'id="tab-dashboard-btn"' in template
    assert 'id="tab-history-btn"' in template
    assert 'id="tab-reports-btn"' in template
    assert 'id="tab-logs-btn"' in template
    assert 'id="tab-settings-btn"' in template
    assert 'id="history-tab-panel"' in template
    assert 'id="reports-tab-panel"' in template
    assert 'id="logs-tab-panel"' in template
    assert 'id="settings-tab-panel"' in template
    assert 'id="history-compare-panel"' in template
    assert 'id="history-compare-summary"' in template
    assert 'id="logs-search-input"' in template
    assert 'id="logs-level-filter"' in template
    assert 'id="logs-tab-entries"' in template
    assert 'id="logs-export-btn"' in template
    assert 'id="logs-clear-btn"' in template
    assert 'id="save-settings-btn"' in template
    assert 'id="settings-profile-list"' in template
    assert 'id="settings-scan-only-mode"' in template
    assert 'id="settings-excluded-targets"' in template
    assert 'id="settings-google-drive-enabled"' in template
    assert 'id="settings-remote-sync-enabled"' in template
    assert 'id="settings-google-drive-test-btn"' in template
    assert 'id="settings-remote-sync-test-btn"' in template
    assert '<script src="/static/js/reports_tab.js"></script>' in template
    assert '<script src="/static/js/settings_tab.js"></script>' in template
    assert "initializeAuditLog();" in template
    assert "initializeSettingsTab();" in template


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
    report_status_module = (ROOT / "static" / "js" / "report_status.js").read_text()
    reports_tab_module = (ROOT / "static" / "js" / "reports_tab.js").read_text()
    settings_tab_module = (ROOT / "static" / "js" / "settings_tab.js").read_text()

    assert "function renderCveArrayCell(cell, cveArray)" in discovery_module
    assert "function appendServiceInfoLine(cell, line)" in discovery_module
    assert "function renderDelimitedCell(cell, items, options = {})" in discovery_module
    assert "function formatReportCompleteMessage(data)" in discovery_module
    assert "window.showReportCompleteStatus(data)" in discovery_module
    assert "window.dispatchEvent(new CustomEvent('report-complete-refresh'));" in discovery_module
    assert "function requestLocalRuntimeInfo()" in discovery_module
    assert "socket.on('connect', () => {" in discovery_module
    assert "window.setTimeout(() => {" in discovery_module
    assert "socket.emit('get_local_ip');" in discovery_module
    assert "function showReportActions(path)" in report_status_module
    assert "function showReportCompleteStatus(data)" in report_status_module
    assert "buildLink(`/api/runtime/reports/${path}/html`, 'View Report', true);" in report_status_module
    assert "buildLink(`/api/runtime/reports/${path}/pdf`, 'Download PDF');" in report_status_module
    assert "buildLink(`/api/runtime/reports/${path}/xml`, 'Download XML');" in report_status_module
    assert "function initializeReportsTab()" in reports_tab_module
    assert "async function compareHistoryScans(basePath, currentPath)" in reports_tab_module
    assert "/api/runtime/history/compare?base_path=" in reports_tab_module
    assert "function createHistoryDetailBlock(scan)" in reports_tab_module
    assert "function ensureTabPanelsAreSiblings()" in reports_tab_module
    assert "panel.parentElement !== dashboardPanel" in reports_tab_module
    assert "parent.insertBefore(panel, dashboardPanel.nextSibling);" in reports_tab_module
    assert "switchAppTab('history')" in reports_tab_module
    assert "switchAppTab('reports')" in reports_tab_module
    assert "switchAppTab('logs')" in reports_tab_module
    assert "switchAppTab('settings')" in reports_tab_module
    assert "const panels = {" in reports_tab_module
    assert "function loadReportsTab(force = false)" in reports_tab_module
    assert "function loadHistoryTab(force = false)" in reports_tab_module
    assert "window.loadSettingsTab()" in reports_tab_module
    assert "window.addEventListener('report-complete-refresh'" in reports_tab_module
    assert "buildRuntimeReportArtifactUrl(scan.path, 'html')" in reports_tab_module
    assert "buildRuntimeReportArtifactUrl(scan.path, 'pdf')" in reports_tab_module
    assert "buildRuntimeReportArtifactUrl(scan.path, 'xml')" in reports_tab_module
    assert "Select Base" in reports_tab_module
    assert "Compare to Base" in reports_tab_module
    assert "async function loadSettingsTab(force = false)" in settings_tab_module
    assert "async function saveSettingsTab()" in settings_tab_module
    assert "async function testGoogleDriveSettings()" in settings_tab_module
    assert "async function testRemoteSyncSettings()" in settings_tab_module
    assert "async function runRuntimeBackfill()" in settings_tab_module
    assert "function addTargetProfile()" in settings_tab_module
    assert "function applyProfileToDashboard(profile)" in settings_tab_module
    assert "setSyncStatus('settings-google-drive-status'" in settings_tab_module
    assert "setSyncStatus('settings-remote-sync-status'" in settings_tab_module
    assert "setMaintenanceStatus('Running runtime backfill...')" in settings_tab_module
    assert "function syncMaintenanceStatusFromSummary(summary)" in settings_tab_module
    assert "const lastBackfillValue =" in settings_tab_module
    assert "fetch('/api/settings/validate/google-drive'" in settings_tab_module
    assert "fetch('/api/settings/validate/remote-sync'" in settings_tab_module
    assert "fetch('/api/runtime/maintenance/backfill'" in settings_tab_module
    assert "window.initializeSettingsTab = initializeSettingsTab;" in settings_tab_module
    assert "window.loadSettingsTab = loadSettingsTab;" in settings_tab_module
    assert 'id="settings-runtime-backfill-btn"' in template
    assert 'id="settings-maintenance-status"' in template
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
