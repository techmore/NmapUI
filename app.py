from flask import Flask, request
from flask_socketio import SocketIO
from flask_cors import CORS
import sys
import requests
import re
import ipaddress
import netifaces as ni
import shutil
import logging
from customer_fingerprint import CustomerFingerprinter
from nmapui.auth import log_auth_posture
from nmapui.auto_scan import (
    DEFAULT_AUTO_SCAN_CONFIG,
    load_auto_scan_config,
    save_auto_scan_config,
    should_run_auto_scan,
    validate_auto_scan_config_update,
)
from nmapui.app_runtime import (
    configure_root_logging as configure_root_logging_runtime,
    run_server as run_server_runtime,
    startup_checks as startup_checks_runtime,
)
from nmapui.app_runtime_bindings import (
    build_runtime_bindings,
    build_state_bindings,
    build_traceroute_bindings,
)
from nmapui.app_task_bindings import build_task_bindings
from nmapui.app_bindings import build_client_state_helpers, build_event_helpers
from nmapui.app_composition import (
    build_execute_auto_scan_deps,
    build_startup_check_deps,
)
from nmapui.app_handler_registration import register_app_handlers
from nmapui.health import build_liveness_payload, build_readiness_payload
from nmapui.idle_state import IdleStateManager
from nmapui.jobs import (
    ClientJobRegistry,
    PerClientRateLimiter,
    ScanBroadcaster,
)
from nmapui.client_state import ClientStateRegistry
from nmapui.bootstrap import (
    begin_startup_state,
    build_runtime_options,
    complete_startup_state,
    get_allowed_origins,
    run_socketio_server,
)
from nmapui.networking import identify_gateway_firewall_targets as identify_gateway_firewall_targets_for_key
from nmapui.networking import (
    calculate_cidr as calculate_cidr_impl,
    get_default_interface as get_default_interface_impl,
    is_private_ip,
)
from nmapui.paths import (
    BASE_DIR,
    CURRENT_ASSIGNMENT_FILE,
    GOOGLE_DRIVE_CREDENTIALS_FILE,
    GOOGLE_DRIVE_TOKEN_KEY_FILE,
    GOOGLE_DRIVE_TOKEN_FILE,
    REMOTE_SYNC_SECRET_FILE,
    REMOTE_SYNC_SECRET_KEY_FILE,
    RUNTIME_DB_FILE,
    SCANS_DIR,
    SETTINGS_FILE,
    VULNERS_SCRIPT,
    XSL_STYLESHEET,
    XSL_STYLESHEET_PDF,
    resolve_scan_path,
)
from nmapui.google_drive import (
    build_google_drive_auth_status,
    build_google_drive_auth_url,
    disconnect_google_drive,
    exchange_google_drive_auth_code,
    ensure_google_drive_reports_folder,
    upload_files_to_google_drive,
)
from nmapui.runtime import (
    check_for_updates,
    get_app_version,
)
from nmapui.runtime_db import create_runtime_state_store
from nmapui.runtime_history import backfill_runtime_history_artifacts
from nmapui.runtime_services import create_runtime_services
from nmapui.startup import create_startup_state
from nmapui.state import merge_customer_metadata
from nmapui.tooling import ToolVersionRegistry
from nmapui.reporting import (
    convert_html_to_pdf,
    convert_xml_to_html,
    extract_scan_statistics,
    find_latest_saved_scan_for_pdf,
    get_most_recent_scan_xml,
    merge_nmap_xml_files,
    parse_scan_xml_for_assets,
    save_scan_metadata,
)
from nmapui.scanning import (
    check_arp_scan,
    check_nmap,
    check_vulners,
    create_scan_folder,
    split_subnet_into_chunks,
)
from nmapui.settings import (
    load_remote_sync_secret,
    load_settings_state,
    save_settings_state,
    validate_google_drive_settings,
    validate_remote_sync_settings,
)
from nmapui.traceroute_runtime import run_traceroute as run_traceroute_runtime
from nmapui.validation import validate_target
from persistence import (
    load_json_document,
    normalize_current_assignment_document,
    normalize_scan_metadata_document,
    save_json_document,
    save_yaml_document,
    sanitize_customer_dir_name,
)

configure_root_logging_runtime(base_dir=BASE_DIR)

logger = logging.getLogger(__name__)

app = Flask(__name__)
allowed_origins = get_allowed_origins()
socketio = SocketIO(app, cors_allowed_origins=allowed_origins)
CORS(app, resources={r"/api/*": {"origins": allowed_origins}})


def safe_emit(event, data=None):
    return runtime_bindings["safe_emit"](event, data)


# Global idle state manager
idle_state_manager = IdleStateManager(
    safe_emit=safe_emit,
    check_for_updates=check_for_updates,
    logger=logger,
)

# Global customer fingerprinter
customer_fingerprinter = CustomerFingerprinter()
runtime_store = create_runtime_state_store(RUNTIME_DB_FILE)
customer_fingerprinter.set_runtime_store(runtime_store)
customer_fingerprinter.backfill_runtime_scan_history()
backfill_runtime_history_artifacts(
    runtime_store=runtime_store,
    scans_dir=SCANS_DIR,
    load_json_document=load_json_document,
    normalize_scan_metadata_document=normalize_scan_metadata_document,
    logger=logger,
)
runtime_services = create_runtime_services(
    default_auto_scan_config=DEFAULT_AUTO_SCAN_CONFIG,
    rate_limiter_cls=PerClientRateLimiter,
    job_registry_cls=ClientJobRegistry,
    client_state_registry_cls=ClientStateRegistry,
    tool_version_registry_cls=ToolVersionRegistry,
    startup_state_factory=create_startup_state,
    idle_state_manager=idle_state_manager,
    runtime_store=runtime_store,
)

network_key = runtime_services["network_key"]
current_customer = runtime_services["current_customer"]
last_scan_target = runtime_services["last_scan_target"]
auto_scan_config = runtime_services["auto_scan_config"]
auto_scan_thread = runtime_services["auto_scan_thread"]
AUTO_SCAN_STARTUP_AT = runtime_services["auto_scan_startup_at"]
AUTO_SCAN_STARTUP_GRACE_SECONDS = runtime_services["auto_scan_startup_grace_seconds"]
rate_limiter = runtime_services["rate_limiter"]
job_registry = runtime_services["job_registry"]
broadcaster = ScanBroadcaster()
client_state_registry = runtime_services["client_state_registry"]
settings_state = load_settings_state(
    settings_path=SETTINGS_FILE,
    load_json_document=load_json_document,
    remote_sync_secret_path=REMOTE_SYNC_SECRET_FILE,
    remote_sync_secret_key_path=REMOTE_SYNC_SECRET_KEY_FILE,
)

event_helpers = build_event_helpers(
    socketio=socketio,
    job_registry=job_registry,
    broadcaster=broadcaster,
    runtime_store=runtime_store,
)
emit_to_client = event_helpers["emit_to_client"]
emit_job_status = event_helpers["emit_job_status"]
update_job_progress = event_helpers["update_job_progress"]
ensure_job_not_cancelled = event_helpers["ensure_job_not_cancelled"]
run_cancellable_command = event_helpers["run_cancellable_command"]

client_state_helpers = build_client_state_helpers(
    client_state_registry=client_state_registry,
    get_current_customer=lambda: current_customer,
    get_network_key=lambda: network_key,
    get_last_scan_target=lambda: last_scan_target,
    set_default_customer=lambda customer: globals().__setitem__("current_customer", customer),
    set_default_network_key=lambda key: globals().__setitem__("network_key", key),
    set_default_last_scan_target=lambda target: globals().__setitem__("last_scan_target", target),
    runtime_store=runtime_store,
)
get_client_state = client_state_helpers["get_client_state"]
get_current_customer_state = client_state_helpers["get_current_customer_state"]
set_current_customer_state = client_state_helpers["set_current_customer_state"]
set_network_key_state = client_state_helpers["set_network_key_state"]
set_last_scan_target_state = client_state_helpers["set_last_scan_target_state"]
release_client_state = client_state_helpers["release_client_state"]

# Load auto scan config on startup
load_auto_scan_config(auto_scan_config)
# Global version information — populated by startup_checks().
tool_versions = runtime_services["tool_versions"]
startup_state = runtime_services["startup_state"]
state_bindings = build_state_bindings(
    current_assignment_file=CURRENT_ASSIGNMENT_FILE,
    current_customer=current_customer,
    scans_dir=SCANS_DIR,
    normalize_current_assignment_document=normalize_current_assignment_document,
    normalize_scan_metadata_document=normalize_scan_metadata_document,
    load_json_document=load_json_document,
    save_json_document=save_json_document,
    save_yaml_document=save_yaml_document,
    get_customer_fingerprinter=lambda: customer_fingerprinter,
    merge_customer_metadata=merge_customer_metadata,
    client_state_registry=client_state_registry,
    get_current_customer_state=get_current_customer_state,
    logger=logger,
)
get_report_counts = state_bindings["get_report_counts"]
save_customers_config = state_bindings["save_customers_config"]
save_current_assignment = state_bindings["save_current_assignment"]

DEFAULT_INTERFACE = get_default_interface_impl(ni, logger)

runtime_bindings = build_runtime_bindings(
    build_execute_auto_scan_deps=build_execute_auto_scan_deps,
    auto_scan_config=auto_scan_config,
    get_current_customer=lambda: current_customer,
    get_last_scan_target=lambda: last_scan_target,
    logger=logger,
    get_network_key=lambda: network_key,
    rate_limiter=rate_limiter,
    save_auto_scan_config=save_auto_scan_config,
    validate_target=validate_target,
    auto_scan_thread=auto_scan_thread,
    socketio=socketio,
    should_run_auto_scan=should_run_auto_scan,
    startup_at=AUTO_SCAN_STARTUP_AT,
    startup_grace_seconds=AUTO_SCAN_STARTUP_GRACE_SECONDS,
    current_assignment_loader=state_bindings["load_current_assignment"],
    set_current_customer=lambda value: globals().__setitem__("current_customer", value),
)
execute_auto_scan = runtime_bindings["execute_auto_scan"]
load_current_assignment = runtime_bindings["load_current_assignment"]
start_auto_scan_thread = runtime_bindings["start_auto_scan_thread"]

traceroute_bindings = build_traceroute_bindings(
    emit_to_client=emit_to_client,
    safe_emit=safe_emit,
    get_client_state=get_client_state,
    socketio_sleep=socketio.sleep,
    logger=logger,
    is_private_ip=is_private_ip,
    requests=requests,
    set_network_key_state=set_network_key_state,
    get_customer_fingerprinter=lambda: customer_fingerprinter,
    merge_customer_metadata=merge_customer_metadata,
    set_current_customer_state=set_current_customer_state,
    get_current_customer_state=get_current_customer_state,
    runtime_store=runtime_store,
)
run_traceroute = traceroute_bindings["run_traceroute"]

upload_report_artifacts_to_google_drive = lambda *, scan_path, file_paths, metadata, settings_state: upload_files_to_google_drive(
    credentials_path=GOOGLE_DRIVE_CREDENTIALS_FILE,
    token_path=GOOGLE_DRIVE_TOKEN_FILE,
    key_path=GOOGLE_DRIVE_TOKEN_KEY_FILE,
    file_paths=file_paths,
    folder_id=str((((settings_state or {}).get("sync") or {}).get("google_drive") or {}).get("folder_id", "") or "").strip(),
    requests_module=requests,
)

register_app_handlers(
    app=app,
    socketio=socketio,
    auto_scan_config=auto_scan_config,
    save_auto_scan_config=save_auto_scan_config,
    validate_auto_scan_config_update=validate_auto_scan_config_update,
    scans_dir=SCANS_DIR,
    resolve_scan_path=resolve_scan_path,
    load_json_document=load_json_document,
    normalize_scan_metadata_document=normalize_scan_metadata_document,
    get_most_recent_scan_xml=get_most_recent_scan_xml,
    customer_fingerprinter=customer_fingerprinter,
    sanitize_customer_dir_name=sanitize_customer_dir_name,
    parse_scan_xml_for_assets=parse_scan_xml_for_assets,
    get_versions=tool_versions.get_versions,
    emit_job_status=emit_job_status,
    job_registry=job_registry,
    emit_to_client=emit_to_client,
    rate_limiter=rate_limiter,
    broadcaster=broadcaster,
    release_client_state=release_client_state,
    check_for_updates=check_for_updates,
    idle_state_manager=idle_state_manager,
    get_client_state=get_client_state,
    set_current_customer_state=set_current_customer_state,
    set_last_scan_target_state=lambda *, value, sid=None: set_last_scan_target_state(
        value=value,
        sid=sid,
    ),
    set_network_key_state=set_network_key_state,
    build_liveness_payload=build_liveness_payload,
    build_readiness_payload=build_readiness_payload,
    get_app_version=get_app_version,
    get_default_interface_cached=lambda: DEFAULT_INTERFACE,
    settings_state=settings_state,
    startup_state=startup_state,
    runtime_store=runtime_store,
    get_auto_scan_thread=runtime_bindings["get_auto_scan_thread"],
    upload_report_artifacts_to_google_drive=upload_report_artifacts_to_google_drive,
    get_customer_fingerprinter=lambda: customer_fingerprinter,
    get_current_customer=lambda: get_current_customer_state(request.sid),
    set_current_customer=lambda value: set_current_customer_state(
        value=value,
        sid=request.sid,
    ),
    merge_customer_metadata=merge_customer_metadata,
    save_current_assignment=lambda: save_current_assignment(request.sid),
    save_customers_config=save_customers_config,
    save_json_document=save_json_document,
    calculate_cidr=calculate_cidr_impl,
    get_report_counts=get_report_counts,
    netifaces=ni,
    requests=requests,
    run_traceroute=lambda target, sid=None: run_traceroute_runtime(
        target=target,
        sid=sid,
        deps=traceroute_bindings["traceroute_deps"](),
    ),
    validate_target=validate_target,
    start_scan_task=lambda sid, target: start_scan_task(sid, target),
    generate_report_task=lambda sid, data: generate_report_task(sid, data),
    generate_pdf_from_saved_task=lambda sid, data: generate_pdf_from_saved_task(sid, data),
    save_settings=lambda payload: save_settings_state(
        settings_path=SETTINGS_FILE,
        save_json_document=save_json_document,
        settings_state=payload,
        remote_sync_secret_path=REMOTE_SYNC_SECRET_FILE,
        remote_sync_secret_key_path=REMOTE_SYNC_SECRET_KEY_FILE,
    ),
    validate_google_drive_settings=lambda *, folder_id: validate_google_drive_settings(
        folder_id=folder_id,
        credentials_path=GOOGLE_DRIVE_CREDENTIALS_FILE,
    ),
    get_google_drive_auth_status=lambda: build_google_drive_auth_status(
        credentials_path=GOOGLE_DRIVE_CREDENTIALS_FILE,
        token_path=GOOGLE_DRIVE_TOKEN_FILE,
        key_path=GOOGLE_DRIVE_TOKEN_KEY_FILE,
    ),
    build_google_drive_auth_url=lambda *, redirect_uri: build_google_drive_auth_url(
        credentials_path=GOOGLE_DRIVE_CREDENTIALS_FILE,
        token_path=GOOGLE_DRIVE_TOKEN_FILE,
        key_path=GOOGLE_DRIVE_TOKEN_KEY_FILE,
        redirect_uri=redirect_uri,
    ),
    exchange_google_drive_auth_code=lambda *, code, state: exchange_google_drive_auth_code(
        credentials_path=GOOGLE_DRIVE_CREDENTIALS_FILE,
        token_path=GOOGLE_DRIVE_TOKEN_FILE,
        key_path=GOOGLE_DRIVE_TOKEN_KEY_FILE,
        code=code,
        state=state,
        requests_module=requests,
    ),
    ensure_google_drive_reports_folder=lambda: ensure_google_drive_reports_folder(
        credentials_path=GOOGLE_DRIVE_CREDENTIALS_FILE,
        token_path=GOOGLE_DRIVE_TOKEN_FILE,
        key_path=GOOGLE_DRIVE_TOKEN_KEY_FILE,
        requests_module=requests,
    ),
    disconnect_google_drive=lambda: disconnect_google_drive(
        token_path=GOOGLE_DRIVE_TOKEN_FILE,
        key_path=GOOGLE_DRIVE_TOKEN_KEY_FILE,
        requests_module=requests,
    ),
    validate_remote_sync_settings=lambda *, endpoint, api_key: validate_remote_sync_settings(
        endpoint=endpoint,
        api_key=api_key
        or load_remote_sync_secret(
            secret_path=REMOTE_SYNC_SECRET_FILE,
            key_path=REMOTE_SYNC_SECRET_KEY_FILE,
        ),
        requests_module=requests,
    ),
    logger=logger,
)
task_bindings = build_task_bindings(
    broadcaster=broadcaster,
    emit_to_client=emit_to_client,
    get_client_state=get_client_state,
    ensure_job_not_cancelled=ensure_job_not_cancelled,
    idle_state_manager=idle_state_manager,
    update_job_progress=update_job_progress,
    socketio=socketio,
    run_cancellable_command=run_cancellable_command,
    identify_gateway_firewall_targets=lambda hosts, sid=None: identify_gateway_firewall_targets_for_key(
        hosts,
        get_client_state(sid=sid)["network_key"],
    ),
    job_registry=job_registry,
    emit_job_status=emit_job_status,
    logger=logger,
    settings_state=settings_state,
    vulners_script=VULNERS_SCRIPT,
    default_interface=DEFAULT_INTERFACE,
    which=shutil.which,
    stylesheet_pdf=XSL_STYLESHEET_PDF,
    validate_target=validate_target,
    split_subnet_into_chunks=split_subnet_into_chunks,
    create_scan_folder=create_scan_folder,
    scans_dir=SCANS_DIR,
    sanitize_customer_dir_name=sanitize_customer_dir_name,
    merge_nmap_xml_files=merge_nmap_xml_files,
    convert_xml_to_html=convert_xml_to_html,
    convert_html_to_pdf=convert_html_to_pdf,
    web_stylesheet=XSL_STYLESHEET,
    stylesheet=XSL_STYLESHEET,
    get_app_version=get_app_version,
    save_scan_metadata=save_scan_metadata,
    network_key=network_key,
    current_customer=current_customer,
    extract_scan_statistics=extract_scan_statistics,
    customer_fingerprinter=customer_fingerprinter,
    upload_report_artifacts_to_google_drive=upload_report_artifacts_to_google_drive,
    runtime_store=runtime_store,
    find_latest_saved_scan_for_pdf=find_latest_saved_scan_for_pdf,
    load_json_document=load_json_document,
    normalize_scan_metadata_document=normalize_scan_metadata_document,
)
start_scan_task = task_bindings["start_scan_task"]
run_arp_scan = task_bindings["run_arp_scan"]
run_nmap_with_xml_output = task_bindings["run_nmap_with_xml_output"]
generate_report_task = task_bindings["generate_report_task"]
generate_pdf_from_saved_task = task_bindings["generate_pdf_from_saved_task"]


def startup_checks(quick=False):
    startup_checks_runtime(
        deps=build_startup_check_deps(
            begin_startup_state=begin_startup_state,
            check_arp_scan=check_arp_scan,
            check_nmap=check_nmap,
            check_vulners=check_vulners,
            complete_startup_state=complete_startup_state,
            get_app_version=get_app_version,
            get_default_interface_cached=lambda: DEFAULT_INTERFACE,
            get_versions=tool_versions.get_versions,
            load_auto_scan_config=load_auto_scan_config,
            load_current_assignment=load_current_assignment,
            logger=logger,
            network_key=network_key,
            runtime_store=runtime_store,
            run_traceroute=run_traceroute,
            safe_emit=safe_emit,
            startup_state=startup_state,
            tool_versions=tool_versions,
            auto_scan_config=auto_scan_config,
            vulners_script=VULNERS_SCRIPT,
        ),
        quick=quick,
    )

def run_server(argv=None):
    run_server_runtime(
        argv=argv,
        build_runtime_options=build_runtime_options,
        log_auth_posture=log_auth_posture,
        startup_checks=startup_checks,
        start_auto_scan_thread=start_auto_scan_thread,
        run_socketio_server=run_socketio_server,
        socketio=socketio,
        app=app,
        sys_module=sys,
    )


if __name__ == "__main__":
    run_server()
