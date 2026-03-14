from datetime import datetime
import logging
import re

from nmapui.reporting import (
    build_report_diff_summary,
    inject_diff_summary_into_report_html,
    mark_scan_failure,
)


logger = logging.getLogger(__name__)


def start_deep_scan(context, targets, sid, is_gateway_phase=False):
    emit_to_client = context.emit_to_client
    socketio_sleep = context.socketio_sleep
    ensure_job_not_cancelled = context.ensure_job_not_cancelled
    run_cancellable_command = context.run_cancellable_command
    vulners_script = context.vulners_script

    try:
        ensure_job_not_cancelled(sid, "scan")
        emit_to_client(sid, "deep_scan_start")
        socketio_sleep(0)

        for target in targets:
            ensure_job_not_cancelled(sid, "scan")
            emit_to_client(sid, "deep_scan_host_start", {"ip": target})
            cmd = ["nmap", "-T3", "-sV", "--script", str(vulners_script), target]
            emit_to_client(sid, "scan_feedback", f"Executing: {' '.join(cmd)}")
            logger.info("Executing: %s", " ".join(cmd))
            socketio_sleep(0)

            result = run_cancellable_command(
                cmd,
                sid=sid,
                job_type="scan",
            )
            output = result.stdout
            # Use target as the authoritative IP — avoids parentheses when nmap
            # resolves a hostname: "Nmap scan report for host (1.2.3.4)"
            current_host = {"ip": target, "ports": [], "cves": []}
            parsed_data = [current_host]
            cve_pattern = context.cve_pattern

            # Emit raw nmap output to the client log for auditing
            emit_to_client(sid, "scan_raw_output", {"target": target, "output": output})

            for line in output.splitlines():
                if "/tcp" in line:
                    port_info = context.port_info_regex.search(line)
                    if port_info:
                        # Normalize internal whitespace that nmap uses for column alignment
                        service_raw = re.sub(r"\s+", " ", port_info.group(3)).strip()
                        current_host["ports"].append(
                            {
                                "port": port_info.group(1),
                                "state": port_info.group(2),
                                "service": service_raw,
                            }
                        )
                elif "CVE" in line:
                    match = cve_pattern.search(line)
                    if match:
                        cve_id = match.group(0).split()[0]
                        cve_score = match.group(1)
                        cve_url = match.group(2)
                        try:
                            score_f = float(cve_score)
                        except ValueError:
                            score_f = 0.0
                        # Log all CVEs found (regardless of score) for auditing
                        logger.info("CVE found for %s: %s score=%s", target, cve_id, cve_score)
                        if score_f >= 6.0:
                            current_host["cves"].append({"id": cve_id, "score": cve_score, "url": cve_url})
                elif "Service Info: " in line:
                    trimmed_line = line.replace("Service Info: ", "").strip()
                    current_host.setdefault("service_info", []).append(trimmed_line)
                    emit_to_client(sid, "service_info", {"target": target, "line": trimmed_line})

            emit_to_client(sid, "deep_scan_results", parsed_data)
            emit_to_client(sid, "cve_array", {"target": target, "cve_array": current_host["cves"]})
            emit_to_client(sid, "deep_scan_host_complete", {"ip": target})

        emit_to_client(sid, "deep_scan_complete")
    except RuntimeError as exc:
        if str(exc) == "scan cancelled":
            emit_to_client(sid, "scan_error", "Scan cancelled")
            return
        emit_to_client(sid, "scan_error", str(exc))
    except Exception as exc:
        emit_to_client(sid, "scan_error", str(exc))


def start_scan_task(context, sid, target):
    """Run scan workflow in a background task for a single client."""
    ensure_job_not_cancelled = context.ensure_job_not_cancelled
    idle_state_manager = context.idle_state_manager
    update_job_progress = context.update_job_progress
    emit_to_client = context.emit_to_client
    socketio_sleep = context.socketio_sleep
    run_cancellable_command = context.run_cancellable_command
    run_arp_scan = context.run_arp_scan
    identify_gateway_firewall_targets = context.identify_gateway_firewall_targets
    start_deep_scan_fn = context.start_deep_scan
    job_registry = context.job_registry
    emit_job_status = context.emit_job_status
    logger = context.logger
    scan_rules = (context.settings_state or {}).get("scan_rules", {})
    scan_only_mode = bool(scan_rules.get("scan_only_mode", False))
    excluded_targets = [
        str(item or "").strip()
        for item in scan_rules.get("excluded_targets", [])
        if str(item or "").strip()
    ]
    ip_regex = context.ip_regex
    hostname_regex = context.hostname_regex
    host_status_regex = context.host_status_regex
    open_port_regex = context.open_port_regex
    ip_sort_key = context.ip_sort_key

    operation_id = f"quick_scan:{sid}"
    try:
        ensure_job_not_cancelled(sid, "scan")
        idle_state_manager.start_operation(operation_id)
        update_job_progress(
            sid,
            "scan",
            phase="quick_scan",
            message=f"Starting quick scan on {target}",
            progress=5,
        )
        emit_to_client(sid, "quick_scan_start", f"Starting quick scan on {target}")
        command_str = f"nmap -sn {target}"
        emit_to_client(sid, "scan_feedback", f"Executing: {command_str}")
        logger.info(command_str)
        socketio_sleep(0)

        cmd = ["nmap", "-sn", target]
        if excluded_targets:
            exclusion_arg = ",".join(excluded_targets)
            cmd[1:1] = ["--exclude", exclusion_arg]
            emit_to_client(
                sid,
                "scan_feedback",
                f"Applying exclusions to quick scan: {exclusion_arg}",
            )
        output = run_cancellable_command(cmd, sid=sid, job_type="scan").stdout
        lines = output.split("\n")

        hosts, current_host = [], None
        total_ips, hosts_up, time_taken = 0, 0, 0.0
        for line in lines:
            ip_match = ip_regex.search(line)
            if ip_match:
                ip_addr = ip_match.group(1)
                hostname = ""
                hostname_match = hostname_regex.search(line)
                if hostname_match:
                    hostname = hostname_match.group(1)
                current_host = {"ip": ip_addr, "hostname": hostname, "status": None, "ports": []}
                hosts.append(current_host)
            elif "Nmap done:" in line:
                match = context.nmap_done_regex.search(line)
                if match:
                    total_ips = int(match.group(1))
                    hosts_up = int(match.group(2))
                    time_taken = float(match.group(3))
                    logger.info("Total IPs: %s", total_ips)
                    logger.info("Hosts Up: %s", hosts_up)
                    logger.info("Time Taken: %s seconds", time_taken)
                else:
                    logger.warning("No match found")
                emit_to_client(
                    sid,
                    "quickscan_results",
                    {"total_ips": total_ips, "hosts_up": hosts_up, "time_taken": time_taken},
                )
            else:
                host_status_match = host_status_regex.match(line)
                if host_status_match and current_host:
                    current_host["status"] = host_status_match.group(1)
                else:
                    open_port_match = open_port_regex.match(line)
                    if open_port_match and current_host:
                        current_host["ports"].append(
                            {
                                "port": open_port_match.group(1),
                                "state": open_port_match.group(2),
                                "service": open_port_match.group(3),
                            }
                        )

        sorted_hosts = sorted(hosts, key=lambda host: ip_sort_key(host["ip"]))
        emit_to_client(sid, "quick_scan_complete")
        socketio_sleep(0)

        arp_data = {}
        if scan_only_mode:
            emit_to_client(
                sid,
                "scan_feedback",
                "Scan-only mode enabled; skipping MAC/vendor detection",
            )
        else:
            update_job_progress(sid, "scan", phase="arp_scan", message="Collecting MAC and vendor data", progress=35)
            emit_to_client(sid, "arp_scan_start")
            socketio_sleep(0)
            arp_data = run_arp_scan(target, sid=sid)
            for host in sorted_hosts:
                if host["ip"] in arp_data:
                    host["mac"] = arp_data[host["ip"]]["mac"]
                    host["vendor"] = arp_data[host["ip"]]["vendor"]

            if arp_data:
                emit_to_client(sid, "arp_results", arp_data)

            emit_to_client(sid, "arp_scan_complete")

        display_hosts = []
        for host in sorted_hosts:
            display_host = host.copy()
            ports_list = host.get("ports", [])
            display_host["open_ports"] = ", ".join([f"{p['port']}/{p['service']}" for p in ports_list]) if ports_list else ""
            display_host.setdefault("mac", "")
            display_host.setdefault("vendor", "")
            display_host.setdefault("hostname", "")
            display_host.setdefault("version", "")
            display_host.setdefault("cves", "")
            display_hosts.append(display_host)

        emit_to_client(sid, "scan_results", display_hosts)
        socketio_sleep(0)

        regular_hosts, gateway_hosts = identify_gateway_firewall_targets(hosts)
        regular_targets = [host["ip"] for host in regular_hosts]
        gateway_targets = [host["ip"] for host in gateway_hosts]

        logger.info("Phase 1 - Regular hosts: %s", len(regular_targets))
        logger.info("Phase 2 - Gateway hosts: %s", len(gateway_targets))

        if regular_targets:
            update_job_progress(
                sid,
                "scan",
                phase="deep_scan",
                message=f"Deep scanning {len(regular_targets)} regular hosts",
                progress=60,
            )
            start_deep_scan_fn(context, regular_targets, sid, is_gateway_phase=False)

        if gateway_targets:
            update_job_progress(
                sid,
                "scan",
                phase="gateway_scan",
                message=f"Deep scanning {len(gateway_targets)} gateway hosts",
                progress=80,
            )
            start_deep_scan_fn(context, gateway_targets, sid, is_gateway_phase=True)

        update_job_progress(sid, "scan", phase="complete", message="Scan workflow completed", progress=100)
    except RuntimeError as exc:
        if str(exc) == "scan cancelled":
            job_registry.complete(sid, "scan", status="cancelled")
            emit_job_status(sid, "scan")
            emit_to_client(sid, "scan_error", "Scan cancelled")
        else:
            job_registry.complete(sid, "scan", status="failed", details={"error": str(exc)})
            emit_job_status(sid, "scan")
            emit_to_client(sid, "scan_error", str(exc))
    except Exception as exc:
        job_registry.complete(sid, "scan", status="failed", details={"error": str(exc)})
        emit_job_status(sid, "scan")
        emit_to_client(sid, "scan_error", str(exc))
    finally:
        current_job = job_registry.get(sid, "scan")
        if current_job and current_job.get("status") == "running":
            job_registry.complete(sid, "scan", status="completed")
            emit_job_status(sid, "scan")
        job_registry.clear_if_disconnected(sid, "scan")
        idle_state_manager.end_operation(operation_id)
        # Tear down the broadcaster slot so new tabs no longer join this job
        on_job_end = context.on_job_end
        if on_job_end:
            on_job_end()


def generate_report_task(context, sid, data):
    """Run report generation in a background task for a single client."""
    job_registry = context.job_registry
    idle_state_manager = context.idle_state_manager
    emit_job_status = context.emit_job_status
    emit_to_client = context.emit_to_client
    update_job_progress = context.update_job_progress
    validate_target = context.validate_target
    split_subnet_into_chunks = context.split_subnet_into_chunks
    create_scan_folder = context.create_scan_folder
    scans_dir = context.scans_dir
    sanitize_customer_dir_name = context.sanitize_customer_dir_name
    run_nmap_with_xml_output = context.run_nmap_with_xml_output
    merge_nmap_xml_files = context.merge_nmap_xml_files
    socketio_sleep = context.socketio_sleep
    convert_xml_to_html = context.convert_xml_to_html
    convert_html_to_pdf = context.convert_html_to_pdf
    web_stylesheet = context.web_stylesheet or context.stylesheet
    pdf_stylesheet = context.pdf_stylesheet or web_stylesheet
    get_app_version = context.get_app_version
    save_scan_metadata = context.save_scan_metadata
    get_client_state = context.get_client_state
    if get_client_state is not None:
        client_state = get_client_state(sid=sid)
        network_key = client_state["network_key"]
        current_customer = client_state["current_customer"]
    else:
        network_key = context.network_key
        current_customer = context.current_customer
    extract_scan_statistics = context.extract_scan_statistics
    customer_fingerprinter = context.customer_fingerprinter
    on_job_end = context.on_job_end
    scan_rules = (context.settings_state or {}).get("scan_rules", {})
    scan_only_mode = bool(scan_rules.get("scan_only_mode", False))
    excluded_targets = [
        str(item or "").strip()
        for item in scan_rules.get("excluded_targets", [])
        if str(item or "").strip()
    ]

    operation_id = f"report_generation:{sid}"
    idle_state_manager.start_operation(operation_id)
    target = data.get("target")
    scan_dir = None
    is_auto_scan = data.get("auto_scan", False)

    customer_name = data.get("customer_name")
    if not customer_name or customer_name in ["Unknown", "Unassigned", "Unknown Network"]:
        customer_name = current_customer.get("name", "Unknown")
    customer_name = customer_name.split(" (")[0]

    current_customer_id = str(current_customer.get("id", "") or "")
    if customer_name in ["Unknown", "Unassigned", "Unknown Network"] or current_customer_id in ["", "unknown"]:
        public_ip = str(network_key.get("public_ip") or "").strip()
        exit_ip = str(network_key.get("exit_ip") or "").strip()
        if public_ip or exit_ip:
            generated_customer = customer_fingerprinter.ensure_generated_customer(network_key)
            current_customer = {
                "id": generated_customer.get("id"),
                "name": generated_customer.get("name"),
                "confidence": generated_customer.get("confidence", 0.35),
                "metadata": generated_customer.get("metadata", {}),
            }
            customer_name = current_customer["name"].split(" (")[0]

    if not target:
        job_registry.complete(sid, "report", status="failed", details={"error": "No target specified"})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": "No target specified"})
        idle_state_manager.end_operation(operation_id)
        return

    is_valid, error_msg = validate_target(target)
    if not is_valid:
        job_registry.complete(sid, "report", status="failed", details={"error": error_msg})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": error_msg})
        idle_state_manager.end_operation(operation_id)
        return

    chunked_scan = data.get("chunked", True)
    targets = split_subnet_into_chunks(target) if chunked_scan else [target]
    num_chunks = len(targets)
    logger.info("Target split into %s chunks: %s", num_chunks, targets)

    if num_chunks > 1:
        emit_to_client(sid, "scan_feedback", f"Large network detected - scanning in {num_chunks} chunks")
        socketio_sleep(0)
    elif not chunked_scan:
        emit_to_client(sid, "scan_feedback", "Running a single comprehensive scan without chunking")
        socketio_sleep(0)

    if scan_only_mode:
        emit_to_client(
            sid,
            "scan_feedback",
            "Scan-only mode enabled; forcing unprivileged scan technique",
        )
    if excluded_targets:
        emit_to_client(
            sid,
            "scan_feedback",
            f"Applying exclusions to report scan: {', '.join(excluded_targets)}",
        )

    logger.info("=" * 60)
    logger.info("REPORT GENERATION STARTED")
    logger.info("  Target: %s", target)
    logger.info("  Customer: %s", customer_name)
    logger.info("  Auto Scan: %s", is_auto_scan)
    logger.info("=" * 60)

    emit_to_client(sid, "scan_feedback", f"📋 Generating report for {customer_name} - Target: {target}")
    update_job_progress(
        sid,
        "report",
        phase="preparing",
        message=f"Preparing report for {target}",
        progress=5,
        details={"auto_scan": is_auto_scan, "customer_name": customer_name},
    )
    socketio_sleep(0)

    start_time = datetime.now()

    try:
        emit_to_client(sid, "scan_feedback", "📁 Creating scan folder...")
        update_job_progress(sid, "report", phase="create_folder", message="Creating scan folder", progress=10)
        socketio_sleep(0)
        scan_dir = create_scan_folder(
            customer_name,
            target,
            scans_dir=scans_dir,
            sanitize_customer_dir_name=sanitize_customer_dir_name,
        )
        output_base = scan_dir / "scan"
        logger.info("Scan folder created: %s", scan_dir)
        emit_to_client(sid, "scan_feedback", f"✓ Scan folder: {scan_dir.name}")
        socketio_sleep(0)

        xml_files = []
        for i, chunk_target in enumerate(targets):
            chunk_progress = 15 + int(((i + 1) / max(num_chunks, 1)) * 40)
            if num_chunks > 1:
                emit_to_client(sid, "scan_feedback", f"🔍 Scanning chunk {i + 1}/{num_chunks}: {chunk_target}")
                update_job_progress(
                    sid,
                    "report",
                    phase="scan_chunks",
                    message=f"Scanning chunk {i + 1} of {num_chunks}",
                    progress=chunk_progress,
                    details={"chunk_index": i + 1, "chunk_total": num_chunks},
                )
            else:
                emit_to_client(sid, "scan_feedback", "🔍 Starting nmap comprehensive scan (this may take 5-10 minutes)...")
                update_job_progress(sid, "report", phase="scan", message="Running comprehensive scan", progress=35)
            socketio_sleep(0)

            chunk_output_base = output_base if num_chunks == 1 else scan_dir / f"scan_chunk_{i}"
            run_kwargs = {}
            if excluded_targets:
                run_kwargs["excluded_targets"] = excluded_targets
            if scan_only_mode:
                run_kwargs["scan_only_mode"] = True

            if not run_nmap_with_xml_output(
                chunk_target,
                chunk_output_base,
                "comprehensive",
                sid=sid,
                **run_kwargs,
            ):
                if job_registry.is_cancelled(sid, "report"):
                    if scan_dir is not None:
                        mark_scan_failure(
                            scan_dir,
                            target=target,
                            customer_name=customer_name,
                            current_customer=current_customer,
                            error="Report generation cancelled",
                            stage="scan_chunks",
                        )
                    job_registry.complete(sid, "report", status="cancelled")
                    emit_job_status(sid, "report")
                    emit_to_client(sid, "report_error", {"error": "Report generation cancelled"})
                    return
                if scan_dir is not None:
                    mark_scan_failure(
                        scan_dir,
                        target=target,
                        customer_name=customer_name,
                        current_customer=current_customer,
                        error=f"Nmap scan failed on chunk {i + 1}",
                        stage="scan_chunks",
                    )
                job_registry.complete(
                    sid,
                    "report",
                    status="failed",
                    details={"error": f"Nmap scan failed on chunk {i + 1}"},
                )
                emit_job_status(sid, "report")
                emit_to_client(sid, "report_error", {"error": f"Nmap scan failed on chunk {i + 1}"})
                return

            xml_files.append(chunk_output_base.with_suffix(".xml"))

        if num_chunks > 1:
            emit_to_client(sid, "scan_feedback", "🔀 Merging scan results from chunks...")
            update_job_progress(sid, "report", phase="merge", message="Merging chunked XML results", progress=60)
            socketio_sleep(0)
            xml_path = scan_dir / "scan.xml"
            merge_nmap_xml_files(xml_files, xml_path)
        else:
            xml_path = output_base.with_suffix(".xml")

        xml_path = scan_dir / "scan.xml"
        web_html_path = scan_dir / "scan_web.html"
        pdf_html_path = scan_dir / "scan_pdf.html"
        pdf_path = scan_dir / "scan_report.pdf"
        current_metadata = {
            "path": str(scan_dir.relative_to(scans_dir)),
            "timestamp": datetime.now().isoformat(),
            "customer_id": str(current_customer.get("id", "") or ""),
            "target": target,
        }
        diff_summary = build_report_diff_summary(
            current_metadata,
            xml_path,
            scans_dir=scans_dir,
        )

        feedback = lambda message: (emit_to_client(sid, "scan_feedback", message), socketio_sleep(0))

        emit_to_client(sid, "scan_feedback", "📄 Converting XML to HTML (web view)...")
        update_job_progress(sid, "report", phase="html_web", message="Generating web HTML report", progress=70)
        socketio_sleep(0)
        if convert_xml_to_html(xml_path, web_html_path, stylesheet=web_stylesheet, get_app_version=get_app_version, feedback=feedback):
            inject_diff_summary_into_report_html(web_html_path, diff_summary)
            file_size = web_html_path.stat().st_size if web_html_path.exists() else 0
            logger.info("✓ Web HTML created: %s (%s bytes)", web_html_path, file_size)
            emit_to_client(sid, "scan_feedback", f"✓ Web HTML: {file_size} bytes")
        else:
            logger.error("✗ Web HTML conversion failed")
            emit_to_client(sid, "scan_feedback", "✗ Web HTML conversion failed")

        emit_to_client(sid, "scan_feedback", "📄 Converting XML to HTML (PDF view)...")
        update_job_progress(sid, "report", phase="html_pdf", message="Generating PDF HTML report", progress=78)
        socketio_sleep(0)
        if convert_xml_to_html(xml_path, pdf_html_path, stylesheet=pdf_stylesheet, get_app_version=get_app_version, feedback=feedback):
            inject_diff_summary_into_report_html(pdf_html_path, diff_summary)
            file_size = pdf_html_path.stat().st_size if pdf_html_path.exists() else 0
            logger.info("✓ PDF HTML created: %s (%s bytes)", pdf_html_path, file_size)
            emit_to_client(sid, "scan_feedback", f"✓ PDF HTML: {file_size} bytes")
        else:
            logger.error("✗ PDF HTML conversion failed")
            emit_to_client(sid, "scan_feedback", "✗ PDF HTML conversion failed")

        emit_to_client(sid, "scan_feedback", "📑 Generating PDF report...")
        update_job_progress(sid, "report", phase="pdf", message="Rendering PDF output", progress=86)
        socketio_sleep(0)
        if convert_html_to_pdf(pdf_html_path, pdf_path, feedback=feedback):
            file_size = pdf_path.stat().st_size if pdf_path.exists() else 0
            logger.info("✓ PDF created: %s (%s bytes)", pdf_path, file_size)
            emit_to_client(sid, "scan_feedback", f"✓ PDF: {file_size} bytes")
        else:
            logger.warning("PDF generation failed - HTML reports are fully functional")
            emit_to_client(sid, "scan_feedback", "✅ HTML reports complete - open in browser or print to PDF manually")
            emit_to_client(sid, "scan_feedback", f"📄 Files: {web_html_path.name} & {pdf_html_path.name} ({pdf_html_path.stat().st_size} bytes each)")

        files = {
            "xml": xml_path,
            "web_html": web_html_path,
            "pdf_html": pdf_html_path,
            "pdf": pdf_path,
            "nmap": scan_dir / "scan.nmap",
            "gnmap": scan_dir / "scan.gnmap",
        }

        end_time = datetime.now()
        duration = end_time - start_time
        duration_minutes = int(duration.total_seconds() // 60)
        duration_seconds = int(duration.total_seconds() % 60)
        duration_str = f"{duration_minutes}m{duration_seconds}s"

        emit_to_client(sid, "scan_feedback", "💾 Saving scan metadata with duration...")
        update_job_progress(sid, "report", phase="metadata", message="Saving metadata", progress=92)
        socketio_sleep(0)
        save_scan_metadata(
            scan_dir,
            customer_name,
            target,
            files,
            network_key=network_key,
            current_customer=current_customer,
            start_time=start_time,
            end_time=end_time,
        )

        emit_to_client(sid, "scan_feedback", "📊 Extracting scan statistics...")
        update_job_progress(sid, "report", phase="statistics", message="Extracting scan statistics", progress=96)
        socketio_sleep(0)
        scan_stats = extract_scan_statistics(xml_path)

        emit_to_client(
            sid,
            "scan_complete_summary",
            {
                "duration_formatted": duration_str,
                "hosts_up": scan_stats.get("hosts_up", 0) if scan_stats else 0,
                "total_ports": scan_stats.get("total_ports_found", 0) if scan_stats else 0,
                "total_cves": scan_stats.get("total_cves", 0) if scan_stats else 0,
                "target": target,
            },
        )
        socketio_sleep(0)

        logger.info("Report generation completed in %s", duration_str)
        emit_to_client(sid, "scan_feedback", f"✅ Report generation completed in {duration_str}")
        update_job_progress(
            sid,
            "report",
            phase="complete",
            message="Report generation completed",
            progress=100,
            details={"duration_formatted": duration_str},
        )
        socketio_sleep(0)

        cust_id = None
        for customer in customer_fingerprinter.customers:
            if customer.get("name") == customer_name:
                cust_id = customer.get("id")
                break

        if not cust_id and current_customer.get("name") == customer_name:
            cust_id = current_customer.get("id")

        if cust_id and cust_id != "unknown":
            customer_fingerprinter.update_last_scan_duration(cust_id, duration_str)
            if current_customer.get("id") == cust_id:
                if "metadata" not in current_customer:
                    current_customer["metadata"] = {}
                current_customer["metadata"]["last_scan_duration"] = duration_str
                emit_to_client(sid, "customer_info", current_customer)

        logger.info("=" * 60)
        logger.info("REPORT GENERATION SUCCESSFUL")
        logger.info("  Duration: %s", duration_str)
        logger.info("  Location: %s", scan_dir)
        logger.info("=" * 60)

        relative_path = str(scan_dir.relative_to(scans_dir))
        emit_to_client(
            sid,
            "report_complete",
            {
                "status": "success",
                "path": relative_path,
                "scan_dir": str(scan_dir),
                "diff_summary": diff_summary,
            },
        )
        job_registry.complete(
            sid,
            "report",
            status="completed",
            details={"target": target, "path": relative_path},
        )
        emit_job_status(sid, "report")
    except Exception as exc:
        if scan_dir is not None:
            mark_scan_failure(
                scan_dir,
                target=target,
                customer_name=customer_name,
                current_customer=current_customer,
                error=str(exc),
                stage="exception",
            )
        logger.exception("Report generation failed")
        logger.error("=" * 60)
        logger.error("REPORT GENERATION FAILED")
        logger.error("  Error: %s", exc)
        logger.error("=" * 60)
        job_registry.complete(sid, "report", status="failed", details={"error": str(exc)})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": str(exc)})
    finally:
        current_job = job_registry.get(sid, "report")
        if current_job and current_job.get("status") == "running":
            job_registry.complete(sid, "report", status="completed")
            emit_job_status(sid, "report")
        job_registry.clear_if_disconnected(sid, "report")
        if on_job_end:
            on_job_end()
        idle_state_manager.end_operation(operation_id)
