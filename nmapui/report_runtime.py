from nmapui.reporting import generate_pdf_from_saved_task as generate_pdf_from_saved_task_impl
from nmapui.scan_runtime import make_broadcast_emit
from nmapui.workflow_context import build_report_workflow_context
from nmapui.workflows import generate_report_task as workflow_generate_report_task


def generate_report_task(*, sid, data, deps):
    broadcaster = deps.get("broadcaster")
    if broadcaster is not None:
        deps = {
            **deps,
            "emit_to_client": make_broadcast_emit(
                owner_sid=sid,
                broadcaster=broadcaster,
                emit_to_client=deps["emit_to_client"],
                job_type="report",
                runtime_store=deps.get("runtime_store"),
            ),
            "on_job_end": lambda: broadcaster.end_job(sid, job_type="report"),
        }
    return workflow_generate_report_task(build_report_workflow_context(deps), sid, data)


def generate_pdf_from_saved_task(*, sid, data, deps):
    broadcaster = deps.get("broadcaster")
    if broadcaster is not None:
        deps = {
            **deps,
            "emit_to_client": make_broadcast_emit(
                owner_sid=sid,
                broadcaster=broadcaster,
                emit_to_client=deps["emit_to_client"],
                job_type="report",
                runtime_store=deps.get("runtime_store"),
            ),
        }
    return generate_pdf_from_saved_task_impl(deps, sid, data)
