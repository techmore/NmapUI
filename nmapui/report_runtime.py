from nmapui.reporting import generate_pdf_from_saved_task as generate_pdf_from_saved_task_impl
from nmapui.workflow_context import build_report_workflow_context
from nmapui.workflows import generate_report_task as workflow_generate_report_task


def generate_report_task(*, sid, data, deps):
    return workflow_generate_report_task(build_report_workflow_context(deps), sid, data)


def generate_pdf_from_saved_task(*, sid, data, deps):
    return generate_pdf_from_saved_task_impl(deps, sid, data)
