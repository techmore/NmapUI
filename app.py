from flask import Flask, request
from flask_socketio import SocketIO
from flask_cors import CORS
from typing import Optional
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
    execute_auto_scan as execute_auto_scan_runtime,
    start_auto_scan_thread as start_auto_scan_thread_runtime,
    startup_checks as startup_checks_runtime,
)
from nmapui.app_events_runtime import (
    emit_job_status as emit_job_status_runtime,
    emit_to_client as emit_to_client_runtime,
    ensure_job_not_cancelled as ensure_job_not_cancelled_runtime,
    run_cancellable_command as run_cancellable_command_runtime,
    safe_emit as safe_emit_runtime,
    update_job_progress as update_job_progress_runtime,
)
from nmapui.app_scan_runtime import (
    run_arp_scan as run_arp_scan_runtime,
    run_nmap_with_xml_output as run_nmap_with_xml_output_runtime,
    start_scan_task as start_scan_task_runtime,
)
from nmapui.app_client_state_runtime import (
    get_client_state as get_client_state_runtime,
    get_current_customer_state as get_current_customer_state_runtime,
    release_client_state as release_client_state_runtime,
    set_current_customer_state as set_current_customer_state_runtime,
    set_last_scan_target_state as set_last_scan_target_state_runtime,
    set_network_key_state as set_network_key_state_runtime,
)
from nmapui.app_state_runtime import (
    get_report_counts as get_report_counts_runtime,
    load_current_assignment as load_current_assignment_runtime,
    save_current_assignment as save_current_assignment_runtime,
    save_customers_config as save_customers_config_runtime,
)
from nmapui.handlers.auto_scan import (
    register_auto_scan_handlers,
)
from nmapui.handlers.connections import register_connection_handlers
from nmapui.handlers.customers import register_customer_handlers
from nmapui.handlers.history import register_history_handlers
from nmapui.handlers.routes import register_core_routes
from nmapui.handlers.runtime_info import register_runtime_info_handlers
from nmapui.handlers.scan_jobs import register_scan_job_handlers
from nmapui.handlers.scans import register_scan_routes
from nmapui.handlers.updates import register_update_handlers
from nmapui.health import build_liveness_payload, build_readiness_payload
from nmapui.idle_state import IdleStateManager
from nmapui.jobs import (
    ClientJobRegistry,
    PerClientRateLimiter,
    ScanBroadcaster,
)
from nmapui.client_state import ClientStateRegistry
from nmapui.bootstrap import (
    build_runtime_options,
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
    SCANS_DIR,
    VULNERS_SCRIPT,
    XSL_STYLESHEET,
    XSL_STYLESHEET_PDF,
    resolve_scan_path,
)
from nmapui.runtime import (
    check_for_updates,
    get_app_version,
)
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
from nmapui.report_runtime import (
    generate_pdf_from_saved_task as generate_pdf_from_saved_task_runtime,
    generate_report_task as generate_report_task_runtime,
)
from nmapui.scanning import (
    check_arp_scan,
    check_nmap,
    check_vulners,
    create_scan_folder,
    split_subnet_into_chunks,
)
from nmapui.traceroute_runtime import (
    build_traceroute_deps,
    run_traceroute as run_traceroute_runtime,
)
from nmapui.validation import validate_target
from persistence import (
    load_json_document,
    normalize_current_assignment_document,
    normalize_scan_metadata_document,
    save_json_document,
    save_yaml_document,
    sanitize_customer_dir_name,
)

from logging.handlers import RotatingFileHandler

_log_fmt = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_root_logger = logging.getLogger()
_root_logger.setLevel(logging.INFO)

# Console handler (existing behaviour)
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_log_fmt)
_root_logger.addHandler(_console_handler)

# Rotating file handler — 10 MB per file, keep 5 backups
_log_dir = BASE_DIR / "logs"
_log_dir.mkdir(exist_ok=True)
_file_handler = RotatingFileHandler(
    _log_dir / "nmapui.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8",
)
_file_handler.setFormatter(_log_fmt)
_root_logger.addHandler(_file_handler)

logger = logging.getLogger(__name__)

app = Flask(__name__)
allowed_origins = get_allowed_origins()
socketio = SocketIO(app, cors_allowed_origins=allowed_origins)
CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

def safe_emit(event, data=None):
    return safe_emit_runtime(event, data)


def emit_to_client(sid: str, event: str, data=None):
    return emit_to_client_runtime(socketio=socketio, sid=sid, event=event, data=data)


def emit_job_status(sid: str, job_type: str):
    return emit_job_status_runtime(
        socketio=socketio,
        job_registry=job_registry,
        sid=sid,
        job_type=job_type,
    )


def update_job_progress(
    sid: str,
    job_type: str,
    phase: str,
    message: Optional[str] = None,
    progress: Optional[int] = None,
    details=None,
):
    return update_job_progress_runtime(
        socketio=socketio,
        job_registry=job_registry,
        sid=sid,
        job_type=job_type,
        phase=phase,
        message=message,
        progress=progress,
        details=details,
    )


def ensure_job_not_cancelled(sid: str, job_type: str):
    return ensure_job_not_cancelled_runtime(
        job_registry=job_registry,
        sid=sid,
        job_type=job_type,
    )


def get_client_state(*, sid=None):
    return get_client_state_runtime(
        sid=sid,
        client_state_registry=client_state_registry,
        current_customer=current_customer,
        network_key=network_key,
        last_scan_target=last_scan_target,
    )


def get_current_customer_state(sid=None):
    return get_current_customer_state_runtime(
        sid=sid,
        get_client_state=get_client_state,
    )


def set_current_customer_state(value, sid=None):
    return set_current_customer_state_runtime(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_customer=lambda customer: globals().__setitem__("current_customer", customer),
        sync_default_state=lambda customer: (
            globals().__setitem__("current_customer", customer),
            client_state_registry.set_default_customer(customer),
        ),
    )


def set_network_key_state(value, sid=None):
    return set_network_key_state_runtime(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_network_key=lambda key: globals().__setitem__("network_key", key),
        sync_default_state=lambda key: (
            globals().__setitem__("network_key", key),
            client_state_registry.set_default_network_key(key),
        ),
    )


def set_last_scan_target_state(value, sid=None):
    return set_last_scan_target_state_runtime(
        value=value,
        sid=sid,
        client_state_registry=client_state_registry,
        set_default_last_scan_target=lambda target: globals().__setitem__("last_scan_target", target),
        sync_default_state=lambda target: (
            globals().__setitem__("last_scan_target", target),
            client_state_registry.set_default_last_scan_target(target),
        ),
    )


def release_client_state(sid):
    release_client_state_runtime(
        sid=sid,
        client_state_registry=client_state_registry,
    )


def run_cancellable_command(
    cmd,
    sid: Optional[str] = None,
    job_type: Optional[str] = None,
    timeout: Optional[int] = None,
):
    return run_cancellable_command_runtime(
        job_registry=job_registry,
        cmd=cmd,
        sid=sid,
        job_type=job_type,
        timeout=timeout,
    )


# Global idle state manager
idle_state_manager = IdleStateManager(
    safe_emit=safe_emit,
    check_for_updates=check_for_updates,
    logger=logger,
)

# Global customer fingerprinter
customer_fingerprinter = CustomerFingerprinter()
runtime_services = create_runtime_services(
    default_auto_scan_config=DEFAULT_AUTO_SCAN_CONFIG,
    rate_limiter_cls=PerClientRateLimiter,
    job_registry_cls=ClientJobRegistry,
    client_state_registry_cls=ClientStateRegistry,
    tool_version_registry_cls=ToolVersionRegistry,
    startup_state_factory=create_startup_state,
    idle_state_manager=idle_state_manager,
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


def execute_auto_scan():
    return execute_auto_scan_runtime(
        deps={
            "auto_scan_config": auto_scan_config,
            "current_customer": current_customer,
            "get_last_scan_target": lambda: last_scan_target,
            "logger": logger,
            "network_key": network_key,
            "rate_limiter": rate_limiter,
            "safe_emit": safe_emit,
            "save_auto_scan_config": save_auto_scan_config,
            "validate_target": validate_target,
        }
    )


# Load auto scan config on startup
load_auto_scan_config(auto_scan_config)
register_auto_scan_handlers(
    app,
    socketio,
    {
        "auto_scan_config": auto_scan_config,
        "save_auto_scan_config": save_auto_scan_config,
        "validate_auto_scan_config_update": validate_auto_scan_config_update,
        "logger": logger,
    },
)
register_scan_routes(
    app,
    {
        "scans_dir": SCANS_DIR,
        "resolve_scan_path": resolve_scan_path,
        "load_json_document": load_json_document,
        "normalize_scan_metadata_document": normalize_scan_metadata_document,
        "logger": logger,
    },
)
# Global version information — populated by startup_checks().
tool_versions = runtime_services["tool_versions"]
startup_state = runtime_services["startup_state"]


register_history_handlers(
    socketio,
    {
        "get_most_recent_scan_xml": get_most_recent_scan_xml,
        "customer_fingerprinter": customer_fingerprinter,
        "scans_dir": SCANS_DIR,
        "sanitize_customer_dir_name": sanitize_customer_dir_name,
        "parse_scan_xml_for_assets": parse_scan_xml_for_assets,
        "get_versions": tool_versions.get_versions,
        "emit_job_status": emit_job_status,
        "job_registry": job_registry,
        "emit_to_client": emit_to_client,
        "rate_limiter": rate_limiter,
        "broadcaster": broadcaster,
        "release_client_state": release_client_state,
        "logger": logger,
    },
)
register_update_handlers(
    socketio,
    {
        "check_for_updates": check_for_updates,
        "idle_state_manager": idle_state_manager,
        "logger": logger,
    },
)
register_connection_handlers(
    socketio,
    {
        "broadcaster": broadcaster,
        "emit_to_client": emit_to_client,
        "get_client_state": get_client_state,
        "job_registry": job_registry,
        "logger": logger,
        "set_current_customer_state": set_current_customer_state,
        "set_last_scan_target_state": set_last_scan_target_state,
        "set_network_key_state": set_network_key_state,
        "auto_scan_config": auto_scan_config,
    },
)
register_core_routes(
    app,
    {
        "build_liveness_payload": build_liveness_payload,
        "build_readiness_payload": build_readiness_payload,
        "get_app_version": get_app_version,
        "get_default_interface_cached": lambda: DEFAULT_INTERFACE,
        "get_versions": tool_versions.get_versions,
        "startup_state": startup_state,
        "get_auto_scan_thread": lambda: auto_scan_thread,
    },
)


def run_traceroute(target="1.1.1.1"):
    return run_traceroute_runtime(target=target, deps=_traceroute_deps())


def get_report_counts():
    return get_report_counts_runtime(
        scans_dir=SCANS_DIR,
        load_json_document=load_json_document,
        normalize_scan_metadata_document=normalize_scan_metadata_document,
    )


def save_customers_config():
    save_customers_config_runtime(
        get_customer_fingerprinter=lambda: customer_fingerprinter,
        save_yaml_document=save_yaml_document,
        logger=logger,
    )


def save_current_assignment(sid=None):
    save_current_assignment_runtime(
        current_assignment_file=CURRENT_ASSIGNMENT_FILE,
        get_current_customer_state=get_current_customer_state,
        save_json_document=save_json_document,
        logger=logger,
        sid=sid,
    )


register_customer_handlers(
    socketio,
    {
        "get_customer_fingerprinter": lambda: customer_fingerprinter,
        "network_key": lambda sid=None: get_client_state(sid=sid)["network_key"],
        "get_current_customer": lambda: get_current_customer_state(request.sid),
        "set_current_customer": lambda value: set_current_customer_state(value, request.sid),
        "merge_customer_metadata": merge_customer_metadata,
        "save_current_assignment": lambda: save_current_assignment(request.sid),
        "save_customers_config": save_customers_config,
        "normalize_scan_metadata_document": normalize_scan_metadata_document,
        "load_json_document": load_json_document,
        "save_json_document": save_json_document,
        "logger": logger,
    },
)

def load_current_assignment():
    global current_customer
    current_customer = load_current_assignment_runtime(
        current_assignment_file=CURRENT_ASSIGNMENT_FILE,
        current_customer=current_customer,
        normalize_current_assignment_document=normalize_current_assignment_document,
        load_json_document=load_json_document,
        get_customer_fingerprinter=lambda: customer_fingerprinter,
        merge_customer_metadata=merge_customer_metadata,
        client_state_registry=client_state_registry,
        logger=logger,
    )


DEFAULT_INTERFACE = get_default_interface_impl(ni, logger)


def _traceroute_deps():
    return build_traceroute_deps(
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
    )


register_runtime_info_handlers(
    socketio,
    {
        "calculate_cidr": calculate_cidr_impl,
        "get_client_state": get_client_state,
        "get_default_interface_cached": lambda: DEFAULT_INTERFACE,
        "get_report_counts": get_report_counts,
        "logger": logger,
        "netifaces": ni,
        "requests": requests,
        "run_traceroute": lambda target, sid=None: run_traceroute_runtime(
            target=target,
            sid=sid,
            deps=_traceroute_deps(),
        ),
    },
)
register_scan_job_handlers(
    socketio,
    {
        "validate_target": validate_target,
        "rate_limiter": rate_limiter,
        "job_registry": job_registry,
        "emit_job_status": emit_job_status,
        "set_last_scan_target_state": lambda *, value, sid=None: set_last_scan_target_state(
            value,
            sid,
        ),
        "start_scan_task": start_scan_task,
        "generate_report_task": generate_report_task,
        "generate_pdf_from_saved_task": generate_pdf_from_saved_task,
        "broadcaster": broadcaster,
    },
)

def start_scan_task(sid, target):
    """Run scan workflow in a background task for a single client."""
    return start_scan_task_runtime(
        sid=sid,
        target=target,
        broadcaster=broadcaster,
        emit_to_client=emit_to_client,
        get_client_state=get_client_state,
        ensure_job_not_cancelled=ensure_job_not_cancelled,
        idle_state_manager=idle_state_manager,
        update_job_progress=update_job_progress,
        socketio_sleep=socketio.sleep,
        run_cancellable_command=run_cancellable_command,
        run_arp_scan=run_arp_scan,
        identify_gateway_firewall_targets=lambda hosts: identify_gateway_firewall_targets_for_key(
            hosts, get_client_state(sid=sid)["network_key"]
        ),
        job_registry=job_registry,
        emit_job_status=emit_job_status,
        logger=logger,
        vulners_script=VULNERS_SCRIPT,
    )


def run_arp_scan(target, interface=None, sid=None):
    return run_arp_scan_runtime(
        target=target,
        interface=interface,
        sid=sid,
        get_default_interface_cached=lambda: DEFAULT_INTERFACE,
        which=shutil.which,
        emit_to_client=emit_to_client,
        socketio_emit=socketio.emit,
        socketio_sleep=socketio.sleep,
        run_cancellable_command=run_cancellable_command,
    )


def run_nmap_with_xml_output(target, output_base, scan_type="comprehensive", sid=None):
    return run_nmap_with_xml_output_runtime(
        target=target,
        output_base=output_base,
        scan_type=scan_type,
        sid=sid,
        vulners_script=VULNERS_SCRIPT,
        stylesheet_pdf=XSL_STYLESHEET_PDF,
        emit_to_client=emit_to_client,
        socketio_emit=socketio.emit,
        socketio_sleep=socketio.sleep,
        run_cancellable_command=run_cancellable_command,
    )



def generate_report_task(sid, data):
    """Run report generation in a background task for a single client."""
    return generate_report_task_runtime(
        sid=sid,
        data=data,
        deps={
            "job_registry": job_registry,
            "idle_state_manager": idle_state_manager,
            "emit_job_status": emit_job_status,
            "emit_to_client": emit_to_client,
            "update_job_progress": update_job_progress,
            "validate_target": validate_target,
            "split_subnet_into_chunks": split_subnet_into_chunks,
            "create_scan_folder": create_scan_folder,
            "scans_dir": SCANS_DIR,
            "sanitize_customer_dir_name": sanitize_customer_dir_name,
            "run_nmap_with_xml_output": run_nmap_with_xml_output,
            "merge_nmap_xml_files": merge_nmap_xml_files,
            "socketio_sleep": socketio.sleep,
            "convert_xml_to_html": convert_xml_to_html,
            "convert_html_to_pdf": convert_html_to_pdf,
            "web_stylesheet": XSL_STYLESHEET,
            "pdf_stylesheet": XSL_STYLESHEET_PDF,
            "stylesheet": XSL_STYLESHEET,
            "get_app_version": get_app_version,
            "save_scan_metadata": save_scan_metadata,
            "get_client_state": get_client_state,
            "network_key": network_key,
            "current_customer": current_customer,
            "extract_scan_statistics": extract_scan_statistics,
            "customer_fingerprinter": customer_fingerprinter,
        },
    )

def generate_pdf_from_saved_task(sid, data):
    return generate_pdf_from_saved_task_runtime(
        sid=sid,
        data=data,
        deps={
            "job_registry": job_registry,
            "emit_job_status": emit_job_status,
            "emit_to_client": emit_to_client,
            "get_client_state": get_client_state,
            "find_latest_saved_scan_for_pdf": lambda target, **kwargs: find_latest_saved_scan_for_pdf(
                target,
                scans_dir=SCANS_DIR,
                load_json_document=load_json_document,
                normalize_scan_metadata_document=normalize_scan_metadata_document,
                **kwargs,
            ),
            "convert_xml_to_html": convert_xml_to_html,
            "convert_html_to_pdf": convert_html_to_pdf,
            "get_app_version": get_app_version,
            "logger": logger,
            "scans_dir": SCANS_DIR,
            "socketio_sleep": socketio.sleep,
            "web_stylesheet": XSL_STYLESHEET,
            "pdf_stylesheet": XSL_STYLESHEET_PDF,
        },
    )


def startup_checks(quick=False):
    startup_checks_runtime(
        deps={
            "begin_startup_state": begin_startup_state,
            "check_arp_scan": check_arp_scan,
            "check_nmap": check_nmap,
            "check_vulners": check_vulners,
            "complete_startup_state": complete_startup_state,
            "get_app_version": get_app_version,
            "get_default_interface_cached": lambda: DEFAULT_INTERFACE,
            "get_versions": tool_versions.get_versions,
            "load_auto_scan_config": load_auto_scan_config,
            "load_current_assignment": load_current_assignment,
            "logger": logger,
            "network_key": network_key,
            "run_traceroute": run_traceroute,
            "safe_emit": safe_emit,
            "startup_state": startup_state,
            "tool_versions": tool_versions,
            "auto_scan_config": auto_scan_config,
            "vulners_script": VULNERS_SCRIPT,
        },
        quick=quick,
    )

def start_auto_scan_thread():
    """Start the auto-scan worker once per process."""
    global auto_scan_thread
    auto_scan_thread = start_auto_scan_thread_runtime(
        auto_scan_thread=auto_scan_thread,
        socketio=socketio,
        auto_scan_config=auto_scan_config,
        should_run_auto_scan=should_run_auto_scan,
        startup_at=AUTO_SCAN_STARTUP_AT,
        startup_grace_seconds=AUTO_SCAN_STARTUP_GRACE_SECONDS,
        execute_auto_scan=execute_auto_scan,
        logger=logger,
    )

def run_server(argv=None):
    runtime_options = build_runtime_options(argv or sys.argv)
    quick_mode = runtime_options["quick_mode"]

    log_auth_posture()
    startup_checks(quick=quick_mode)
    start_auto_scan_thread()
    run_socketio_server(socketio, app, runtime_options)


if __name__ == "__main__":
    run_server()
