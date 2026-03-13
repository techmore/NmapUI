from datetime import datetime
import logging


logger = logging.getLogger(__name__)


def generate_report_task(context, sid, data):
    """Run report generation in a background task for a single client."""
    job_registry = context["job_registry"]
    idle_state_manager = context["idle_state_manager"]
    emit_job_status = context["emit_job_status"]
    emit_to_client = context["emit_to_client"]
    update_job_progress = context["update_job_progress"]
    validate_target = context["validate_target"]
    split_subnet_into_chunks = context["split_subnet_into_chunks"]
    create_scan_folder = context["create_scan_folder"]
    scans_dir = context["scans_dir"]
    sanitize_customer_dir_name = context["sanitize_customer_dir_name"]
    run_nmap_with_xml_output = context["run_nmap_with_xml_output"]
    merge_nmap_xml_files = context["merge_nmap_xml_files"]
    socketio_sleep = context["socketio_sleep"]
    convert_xml_to_html = context["convert_xml_to_html"]
    convert_html_to_pdf = context["convert_html_to_pdf"]
    stylesheet = context["stylesheet"]
    get_app_version = context["get_app_version"]
    save_scan_metadata = context["save_scan_metadata"]
    network_key = context["network_key"]
    current_customer = context["current_customer"]
    extract_scan_statistics = context["extract_scan_statistics"]
    customer_fingerprinter = context["customer_fingerprinter"]

    operation_id = f"report_generation:{sid}"
    idle_state_manager.start_operation(operation_id)
    target = data.get("target")
    is_auto_scan = data.get("auto_scan", False)

    customer_name = data.get("customer_name")
    if not customer_name or customer_name in ["Unknown", "Unassigned", "Unknown Network"]:
        customer_name = current_customer.get("name", "Unknown")
    customer_name = customer_name.split(" (")[0]

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

    targets = split_subnet_into_chunks(target)
    num_chunks = len(targets)
    logger.info("Target split into %s chunks: %s", num_chunks, targets)

    if num_chunks > 1:
        emit_to_client(sid, "scan_feedback", f"Large network detected - scanning in {num_chunks} chunks")
        socketio_sleep(0)

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
            if not run_nmap_with_xml_output(chunk_target, chunk_output_base, "comprehensive", sid=sid):
                if job_registry.is_cancelled(sid, "report"):
                    job_registry.complete(sid, "report", status="cancelled")
                    emit_job_status(sid, "report")
                    emit_to_client(sid, "report_error", {"error": "Report generation cancelled"})
                    return
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

        feedback = lambda message: (emit_to_client(sid, "scan_feedback", message), socketio_sleep(0))

        emit_to_client(sid, "scan_feedback", "📄 Converting XML to HTML (web view)...")
        update_job_progress(sid, "report", phase="html_web", message="Generating web HTML report", progress=70)
        socketio_sleep(0)
        if convert_xml_to_html(xml_path, web_html_path, stylesheet=stylesheet, get_app_version=get_app_version, feedback=feedback):
            file_size = web_html_path.stat().st_size if web_html_path.exists() else 0
            logger.info("✓ Web HTML created: %s (%s bytes)", web_html_path, file_size)
            emit_to_client(sid, "scan_feedback", f"✓ Web HTML: {file_size} bytes")
        else:
            logger.error("✗ Web HTML conversion failed")
            emit_to_client(sid, "scan_feedback", "✗ Web HTML conversion failed")

        emit_to_client(sid, "scan_feedback", "📄 Converting XML to HTML (PDF view)...")
        update_job_progress(sid, "report", phase="html_pdf", message="Generating PDF HTML report", progress=78)
        socketio_sleep(0)
        if convert_xml_to_html(xml_path, pdf_html_path, stylesheet=stylesheet, get_app_version=get_app_version, feedback=feedback):
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
            {"status": "success", "path": relative_path, "scan_dir": str(scan_dir)},
        )
        job_registry.complete(
            sid,
            "report",
            status="completed",
            details={"target": target, "path": relative_path},
        )
        emit_job_status(sid, "report")
    except Exception as exc:
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
        idle_state_manager.end_operation(operation_id)
