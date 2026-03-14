import re


def build_scan_workflow_context(deps):
    context = {
        "get_client_state": deps["get_client_state"],
        "ensure_job_not_cancelled": deps["ensure_job_not_cancelled"],
        "idle_state_manager": deps["idle_state_manager"],
        "update_job_progress": deps["update_job_progress"],
        "emit_to_client": deps["emit_to_client"],
        "socketio_sleep": deps["socketio_sleep"],
        "run_cancellable_command": deps["run_cancellable_command"],
        "run_arp_scan": deps["run_arp_scan"],
        "identify_gateway_firewall_targets": deps["identify_gateway_firewall_targets"],
        "start_deep_scan": deps["start_deep_scan"],
        "job_registry": deps["job_registry"],
        "emit_job_status": deps["emit_job_status"],
        "logger": deps["logger"],
        "vulners_script": deps["vulners_script"],
        "cve_pattern": re.compile(
            r"CVE-\d{4}-\d+\s+(\d+\.\d+)\s+(https://vulners\.com/cve/CVE-\d{4}-\d+)"
        ),
        "port_info_regex": re.compile(r"(\d+)/tcp\s+(\w+)\s+(.*)"),
        "ip_regex": re.compile(r"Nmap scan report for .*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        "hostname_regex": re.compile(
            r"Nmap scan report for ([^ ]+) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)"
        ),
        "host_status_regex": re.compile(r"Host is (up|down) \(([\d.]+s latency\))"),
        "open_port_regex": re.compile(r"(\d+)\/tcp\s+(\w+)\s+(\w+)"),
        "nmap_done_regex": re.compile(
            r"Nmap done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds"
        ),
        "ip_sort_key": deps["ip_sort_key"],
    }
    on_job_end = deps.get("on_job_end")
    if on_job_end is not None:
        context["on_job_end"] = on_job_end
    return context


def build_report_workflow_context(deps):
    context = {
        "job_registry": deps["job_registry"],
        "idle_state_manager": deps["idle_state_manager"],
        "emit_job_status": deps["emit_job_status"],
        "emit_to_client": deps["emit_to_client"],
        "update_job_progress": deps["update_job_progress"],
        "validate_target": deps["validate_target"],
        "split_subnet_into_chunks": deps["split_subnet_into_chunks"],
        "create_scan_folder": deps["create_scan_folder"],
        "scans_dir": deps["scans_dir"],
        "sanitize_customer_dir_name": deps["sanitize_customer_dir_name"],
        "run_nmap_with_xml_output": deps["run_nmap_with_xml_output"],
        "merge_nmap_xml_files": deps["merge_nmap_xml_files"],
        "socketio_sleep": deps["socketio_sleep"],
        "convert_xml_to_html": deps["convert_xml_to_html"],
        "convert_html_to_pdf": deps["convert_html_to_pdf"],
        "stylesheet": deps["stylesheet"],
        "get_app_version": deps["get_app_version"],
        "save_scan_metadata": deps["save_scan_metadata"],
        "get_client_state": deps["get_client_state"],
        "network_key": deps["network_key"],
        "current_customer": deps["current_customer"],
        "extract_scan_statistics": deps["extract_scan_statistics"],
        "customer_fingerprinter": deps["customer_fingerprinter"],
    }
    web_stylesheet = deps.get("web_stylesheet")
    if web_stylesheet is not None:
        context["web_stylesheet"] = web_stylesheet
    pdf_stylesheet = deps.get("pdf_stylesheet")
    if pdf_stylesheet is not None:
        context["pdf_stylesheet"] = pdf_stylesheet
    return context
