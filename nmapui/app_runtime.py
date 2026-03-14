from nmapui.auto_scan_runtime import execute_auto_scan as execute_auto_scan_impl
from nmapui.handlers.auto_scan import start_auto_scan_thread as handler_start_auto_scan_thread
from nmapui.startup_checks import run_startup_checks


def execute_auto_scan(*, deps):
    return execute_auto_scan_impl(deps=deps)


def startup_checks(*, deps, quick=False):
    run_startup_checks(deps, quick=quick)


def start_auto_scan_thread(
    *,
    auto_scan_thread,
    socketio,
    auto_scan_config,
    should_run_auto_scan,
    startup_at,
    startup_grace_seconds,
    execute_auto_scan,
    logger,
):
    thread_ref = {"thread": auto_scan_thread}
    handler_start_auto_scan_thread(
        thread_ref=thread_ref,
        socketio=socketio,
        auto_scan_config=auto_scan_config,
        should_run_auto_scan=should_run_auto_scan,
        startup_at=startup_at,
        startup_grace_seconds=startup_grace_seconds,
        execute_auto_scan=execute_auto_scan,
        logger=logger,
    )
    return thread_ref["thread"]
