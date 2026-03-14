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


def test_wrapper_build_creates_clean_bundle_runtime():
    build_script = subprocess.check_output(
        ["git", "show", ":build.sh"],
        cwd=ROOT,
        text=True,
    )

    assert 'cp -r "$ROOT_DIR/.venv"' not in build_script
    assert 'cp -r "$ROOT_DIR/venv"' not in build_script
    assert 'python3 -m venv "$BUNDLE_VENV"' in build_script
    assert 'python -m pip install -r "$ROOT_DIR/requirements.txt"' in build_script
    assert 'cp -r "$ROOT_DIR/nmapui" "$APP_NAME/Contents/Resources/"' in build_script
    assert 'cp -r "$ROOT_DIR/config" "$APP_NAME/Contents/Resources/"' in build_script


def test_wrapper_docs_reference_current_local_port():
    for doc_name in ("packaging/macos/README.md", "packaging/macos/SETUP.md"):
        source = (ROOT / doc_name).read_text()
        assert "127.0.0.1:9000" in source
        assert "localhost:9999" not in source


def test_docs_match_current_pdf_generation_runtime_contract():
    readme = subprocess.check_output(
        ["git", "show", ":README.md"],
        cwd=ROOT,
        text=True,
    )
    building = subprocess.check_output(
        ["git", "show", ":BUILDING.md"],
        cwd=ROOT,
        text=True,
    )
    setup = subprocess.check_output(
        ["git", "show", ":docs/guides/SETUP.md"],
        cwd=ROOT,
        text=True,
    )

    assert "wkhtmltopdf (primary HTML to PDF backend)" in readme
    assert "playwright install chromium" in readme
    assert "The managed Python environment in `requirements.txt` includes Playwright, but not WeasyPrint." in readme
    assert "Optional PDF fallback: playwright install chromium" in building
    assert "**wkhtmltopdf** - Primary HTML to PDF conversion" in setup
    assert "**textutil** - macOS-only last-resort PDF fallback" in setup


def test_pyinstaller_spec_includes_runtime_assets():
    spec = (ROOT / "packaging" / "pyinstaller" / "nmapui.spec").read_text()

    assert "config" in spec
    assert "VERSION" in spec
    assert "nmap-modern.xsl" in spec


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


def test_app_defers_fingerprinter_and_default_interface_side_effects():
    app_source = subprocess.check_output(
        ["git", "show", ":app.py"],
        cwd=ROOT,
        text=True,
    )
    history_source = subprocess.check_output(
        ["git", "show", ":nmapui/handlers/history.py"],
        cwd=ROOT,
        text=True,
    )
    customer_source = subprocess.check_output(
        ["git", "show", ":nmapui/handlers/customers.py"],
        cwd=ROOT,
        text=True,
    )

    assert "customer_fingerprinter = CustomerFingerprinter()" not in app_source
    assert "DEFAULT_INTERFACE = get_default_interface()" not in app_source
    assert "# Load auto scan config on startup\nload_auto_scan_config(auto_scan_config)" not in app_source
    assert "def get_customer_fingerprinter():" in app_source
    assert "def get_default_interface_cached():" in app_source
    assert '"get_customer_fingerprinter": get_customer_fingerprinter' in app_source
    assert "begin_startup_state(startup_state, quick=quick)\n    load_auto_scan_config(auto_scan_config)" in app_source
    assert 'customer_fingerprinter = deps["customer_fingerprinter"]' not in history_source
    assert 'customer_fingerprinter = deps["customer_fingerprinter"]' not in customer_source
    assert 'get_customer_fingerprinter = deps["get_customer_fingerprinter"]' in history_source
    assert 'get_customer_fingerprinter = deps["get_customer_fingerprinter"]' in customer_source


def test_app_exposes_explicit_stack_builder_and_runtime_registration():
    app_source = subprocess.check_output(
        ["git", "show", ":app.py"],
        cwd=ROOT,
        text=True,
    )

    assert "def create_app_stack(import_name):" in app_source
    assert "def register_runtime_modules(app, socketio):" in app_source
    assert "def create_application(import_name):" in app_source
    assert "app, socketio = create_app_stack(import_name)" in app_source
    assert "register_runtime_modules(app, socketio)" in app_source
    assert "app, socketio = create_application(__name__)" in app_source


def test_template_unifies_scan_result_listeners_and_normalizes_feedback():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )

    assert template.count("socket.on('scan_results'") == 1
    assert template.count("socket.on('deep_scan_results'") == 1
    assert template.count("socket.on('arp_results'") == 1
    assert "function normalizeFeedbackMessage(msg)" in template
    assert "const message = normalizeFeedbackMessage(msg);" in template


def test_template_uses_dom_helpers_for_update_and_route_rendering():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    update_module = (ROOT / "static" / "js" / "update_modal.js").read_text()

    assert "function setUpdateReleaseNotes(data)" in update_module
    assert "function appendUpdateLogLine(message, isError = false)" in update_module
    assert "function renderRoutePath(data)" in template
    assert "notesDiv.innerHTML =" not in template
    assert "log.innerHTML +=" not in template


def test_template_uses_dom_helpers_for_scan_result_rendering():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )

    assert "function renderCveArrayCell(cell, cveArray)" in template
    assert "function appendServiceInfoLine(cell, line)" in template
    assert "function renderDelimitedCell(cell, items, options = {})" in template
    assert "cell.innerHTML = items.map" not in template
    assert "data.cve_array.forEach(cve => cell.innerHTML +=" not in template
    assert "row.cells[4].innerHTML +=" not in template


def test_template_uses_dom_helpers_for_asset_modal_and_history_rendering():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )

    assert "function renderAssetServices(asset)" in template
    assert "function renderAssetVulnerabilities(asset)" in template
    assert "function renderHistoryState(message, isError = false)" in template
    assert "function renderHistoryList(scans)" in template
    assert "serviceDiv.innerHTML =" not in template
    assert "cveDiv.innerHTML =" not in template
    assert "historyList.innerHTML = scans.map" not in template


def test_template_validates_external_links_and_avoids_report_card_innerhtml():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )

    assert "function setSafeExternalLink(link, rawUrl)" in template
    assert "if (setSafeExternalLink(link, cve.url))" in template
    assert "if (setSafeExternalLink(link, vuln.url))" in template
    assert "reportCard.innerHTML =" not in template


def test_template_does_not_include_dead_new_sites_prototype_script():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )

    for dead_selector in (
        "2026 New Sites JavaScript Functionality",
        "mobile-menu-btn",
        "global-search",
        "filter-pill",
        ".compact-card",
    ):
        assert dead_selector not in template


def test_template_loads_external_table_sorter_module():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    sorter_module = (ROOT / "static" / "js" / "table_sorter.js").read_text()

    assert '<script src="/static/js/table_sorter.js"></script>' in template
    assert "class TableSorter" not in template
    assert "window.TableSorter = TableSorter;" in sorter_module


def test_template_loads_external_history_modal_module():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    history_module = (ROOT / "static" / "js" / "history_modal.js").read_text()

    assert '<script src="/static/js/history_modal.js"></script>' in template
    assert "async function loadScanHistory(" not in template
    assert "function showHistoryModal()" not in template
    assert "window.loadScanHistory = loadScanHistory;" in history_module
    assert "window.showHistoryModal = showHistoryModal;" in history_module


def test_template_loads_external_update_modal_module():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    update_module = (ROOT / "static" / "js" / "update_modal.js").read_text()

    assert '<script src="/static/js/update_modal.js"></script>' in template
    assert "function setUpdateReleaseNotes(data)" not in template
    assert "function startAppUpdate()" not in template
    assert "initializeUpdateModal(socket);" in template
    assert "window.showUpdateModal = showUpdateModal;" in update_module
    assert "window.startAppUpdate = () => {" in update_module


def test_template_loads_external_report_status_module():
    template = subprocess.check_output(
        ["git", "show", ":templates/index.html"],
        cwd=ROOT,
        text=True,
    )
    report_module = (ROOT / "static" / "js" / "report_status.js").read_text()

    assert '<script src="/static/js/report_status.js"></script>' in template
    assert "function createReportProgressCard(message)" not in template
    assert "function updateReportProgress(message)" not in template
    assert "function showReportStatus(message, type)" not in template
    assert "window.updateReportProgress = updateReportProgress;" in report_module
    assert "window.showReportStatus = showReportStatus;" in report_module
