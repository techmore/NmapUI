from datetime import datetime, timedelta
import io
import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET

from persistence import (
    iter_scan_metadata_documents,
    load_json_document,
    normalize_scan_metadata_document,
    save_json_document,
    upsert_scan_metadata_index_entry,
)


logger = logging.getLogger(__name__)


def _get_scans_dir_for_scan(scan_dir):
    return scan_dir.parents[2]


def merge_nmap_xml_files(xml_files, output_path):
    """Merge multiple Nmap XML files into one with updated statistics."""
    if not xml_files:
        raise ValueError("No XML files to merge")

    base_tree = ET.parse(xml_files[0])
    base_root = base_tree.getroot()
    nmaprun = base_root

    all_hosts = []
    earliest_start = None
    latest_end = None
    total_up = 0
    total_down = 0
    total_ips = 0

    for xml_file in xml_files:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall("host"):
            all_hosts.append(host)
            starttime = host.get("starttime")
            endtime = host.get("endtime")
            if starttime:
                start_ts = int(starttime)
                if earliest_start is None or start_ts < earliest_start:
                    earliest_start = start_ts
            if endtime:
                end_ts = int(endtime)
                if latest_end is None or end_ts > latest_end:
                    latest_end = end_ts

        runstats = root.find("runstats")
        if runstats is not None:
            hosts = runstats.find("hosts")
            if hosts is not None:
                total_up += int(hosts.get("up", "0"))
                total_down += int(hosts.get("down", "0"))
                total_ips += int(hosts.get("total", "0"))

    if total_ips == 0:
        for host in all_hosts:
            status = host.find("status")
            if status is not None and status.get("state") == "up":
                total_up += 1
            else:
                total_down += 1
        total_ips = total_up + total_down

    for host in base_root.findall("host"):
        base_root.remove(host)

    for host in all_hosts:
        nmaprun.append(host)

    runstats = base_root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            if earliest_start and latest_end:
                total_elapsed = latest_end - earliest_start
                elapsed_str = f"{total_elapsed // 60}m{total_elapsed % 60}s"
            else:
                elapsed_str = "unknown"
            finished.set(
                "summary",
                f"Nmap done at {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}; {total_ips} IP addresses ({total_up} hosts up) scanned in {elapsed_str}",
            )
            finished.set("hosts", f"{total_up} up, {total_down} down, {total_ips} total")

        hosts = runstats.find("hosts")
        if hosts is not None:
            hosts.set("up", str(total_up))
            hosts.set("down", str(total_down))
            hosts.set("total", str(total_ips))

    scaninfo = base_root.find("scaninfo")
    if scaninfo is not None:
        all_targets = []
        for xml_file in xml_files:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            args = root.get("args")
            if args:
                parts = args.split()
                if parts:
                    target = parts[-1]
                    if target not in all_targets:
                        all_targets.append(target)

        if all_targets:
            scaninfo.set("numservices", "1000")

    first_content = xml_files[0].read_text(encoding="utf-8")
    header_end = first_content.find("<nmaprun")
    headers = (
        first_content[:header_end]
        if header_end != -1
        else '<?xml version="1.0" encoding="UTF-8"?>\n'
    )

    footer_start = first_content.find("</nmaprun>") + len("</nmaprun>")
    footer = first_content[footer_start:] if footer_start > 0 else ""

    xml_string = io.StringIO()
    base_tree.write(xml_string, encoding="unicode", xml_declaration=False)
    merged_content = xml_string.getvalue()

    output_path.write_text(headers + merged_content + footer, encoding="utf-8")


def convert_xml_to_html(
    xml_path,
    html_path,
    *,
    stylesheet,
    get_app_version,
    feedback=None,
):
    """Convert Nmap XML to HTML using xsltproc."""
    if not stylesheet.exists():
        logger.error("XSL stylesheet not found: %s", stylesheet)
        return False

    techmore_version = get_app_version()
    cmd = [
        "xsltproc",
        "--stringparam",
        "techmore_version",
        techmore_version,
        "-o",
        str(html_path),
        str(stylesheet),
        str(xml_path),
    ]
    command_str = " ".join(cmd)
    if feedback:
        feedback(f"Executing: {command_str}")
    logger.info("Executing: %s", command_str)

    try:
        subprocess.run(cmd, check=True)
        return True
    except Exception as exc:
        logger.error("XML to HTML conversion failed: %s", exc)
        return False


def convert_html_to_pdf(html_path, pdf_path, *, feedback=None):
    """Convert HTML to PDF using playwright, wkhtmltopdf, weasyprint, or textutil."""
    if feedback:
        feedback("Trying browser-quality PDF rendering with Playwright")
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def generate_pdf():
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True, args=["--no-sandbox"]
                )
                page = await browser.new_page(
                    viewport={"width": 1440, "height": 2160}
                )
                await page.emulate_media(media="screen")
                await page.goto(
                    f"file://{html_path.resolve()}",
                    wait_until="networkidle",
                )
                # Give hosted fonts and CSS a brief moment to settle before capture.
                await page.wait_for_timeout(1200)
                await page.pdf(
                    path=str(pdf_path),
                    format="Letter",
                    print_background=True,
                    prefer_css_page_size=True,
                    margin={
                        "top": "8mm",
                        "right": "8mm",
                        "bottom": "10mm",
                        "left": "8mm",
                    },
                )
                await browser.close()

        asyncio.run(generate_pdf())
        return True
    except Exception as exc:
        logger.error("playwright failed: %s", exc)

    wkhtml = shutil.which("wkhtmltopdf")
    if wkhtml:
        cmd = [
            wkhtml,
            "--enable-local-file-access",
            "--encoding",
            "utf-8",
            "--background",
            "--javascript-delay",
            "1500",
            "--load-error-handling",
            "ignore",
            "--load-media-error-handling",
            "ignore",
            "--viewport-size",
            "1440x2160",
            "--margin-top",
            "8mm",
            "--margin-right",
            "8mm",
            "--margin-bottom",
            "10mm",
            "--margin-left",
            "8mm",
            "--page-size",
            "Letter",
            str(html_path),
            str(pdf_path),
        ]
        command_str = " ".join(cmd)
        if feedback:
            feedback(f"Falling back to wkhtmltopdf: {command_str}")
        try:
            subprocess.run(cmd, check=True)
            return True
        except Exception as exc:
            logger.error("wkhtmltopdf failed: %s", exc)

    if feedback:
        feedback("Falling back to weasyprint for PDF generation")
    try:
        from weasyprint import HTML

        HTML(str(html_path)).write_pdf(
            str(pdf_path),
            stylesheets=None,
        )
        return True
    except Exception as exc:
        logger.error("weasyprint failed: %s", exc)

    if feedback:
        feedback("Falling back to textutil for PDF generation")
    try:
        cmd = ["textutil", "-convert", "pdf", "-output", str(pdf_path), str(html_path)]
        if feedback:
            feedback("Executing: textutil HTML to PDF")
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except Exception as exc:
        logger.error("textutil failed: %s", exc)

    return False


def save_scan_metadata(
    scan_dir,
    customer_name,
    target,
    files,
    *,
    network_key,
    current_customer,
    start_time=None,
    end_time=None,
):
    """Save scan metadata to JSON file with duration tracking."""
    duration_seconds = None
    duration_formatted = None
    customer_id = ""
    if isinstance(current_customer, dict):
        customer_id = str(current_customer.get("id", "") or "")

    if start_time and end_time:
        duration = end_time - start_time
        duration_seconds = duration.total_seconds()
        duration_minutes = int(duration_seconds // 60)
        duration_secs = int(duration_seconds % 60)
        duration_formatted = f"{duration_minutes}m{duration_secs}s"

    metadata = {
        "schema_version": 1,
        "customer_name": customer_name,
        "customer_id": customer_id,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "time": datetime.now().strftime("%H:%M:%S"),
        "scan_start_time": start_time.isoformat() if start_time else None,
        "scan_end_time": end_time.isoformat() if end_time else None,
        "duration_seconds": duration_seconds,
        "duration_formatted": duration_formatted,
        "network_key": network_key,
        "customer_info": current_customer,
        "files": {k: str(v) for k, v in files.items()},
        "status": "completed",
        "completed_successfully": True,
    }

    save_json_document(
        scan_dir / "metadata.json", normalize_scan_metadata_document(metadata)
    )
    upsert_scan_metadata_index_entry(
        _get_scans_dir_for_scan(scan_dir),
        scan_dir,
        metadata,
    )


def mark_scan_failure(
    scan_dir,
    *,
    target,
    customer_name,
    current_customer,
    error,
    stage,
):
    """Persist failure metadata for an incomplete scan directory."""
    metadata_path = scan_dir / "metadata.json"
    existing = normalize_scan_metadata_document(
        load_json_document(metadata_path, {})
    ) if metadata_path.exists() else normalize_scan_metadata_document({})

    customer_id = ""
    if isinstance(current_customer, dict):
        customer_id = str(current_customer.get("id", "") or "")

    metadata = {
        **existing,
        "schema_version": 1,
        "customer_name": existing.get("customer_name") or customer_name,
        "customer_id": existing.get("customer_id") or customer_id,
        "target": existing.get("target") or target,
        "timestamp": existing.get("timestamp") or datetime.now().isoformat(),
        "date": existing.get("date") or datetime.now().strftime("%Y-%m-%d"),
        "time": existing.get("time") or datetime.now().strftime("%H:%M:%S"),
        "customer_info": existing.get("customer_info") or current_customer,
        "status": "failed",
        "failure_stage": stage,
        "failure_error": str(error),
        "completed_successfully": False,
    }

    save_json_document(metadata_path, metadata)
    upsert_scan_metadata_index_entry(
        _get_scans_dir_for_scan(scan_dir),
        scan_dir,
        metadata,
    )


def extract_scan_statistics(xml_path):
    """Extract comprehensive scan statistics from nmap XML output."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        stats = {
            "total_hosts": 0,
            "hosts_up": 0,
            "hosts_down": 0,
            "total_ports_found": 0,
            "scan_elapsed_seconds": None,
            "total_cves": 0,
        }

        runstats = root.find("runstats")
        if runstats is not None:
            hosts_elem = runstats.find("hosts")
            if hosts_elem is not None:
                stats["hosts_up"] = int(hosts_elem.get("up", 0))
                stats["hosts_down"] = int(hosts_elem.get("down", 0))
                stats["total_hosts"] = int(hosts_elem.get("total", 0))

            finished = runstats.find("finished")
            if finished is not None:
                stats["scan_elapsed_seconds"] = float(finished.get("elapsed", 0))

        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        stats["total_ports_found"] += 1

                    for script in port.findall("script"):
                        if script.get("id") == "vulners":
                            for table in script.findall(".//table"):
                                for elem in table.findall("elem"):
                                    if elem.get("key") == "id" and "CVE" in (
                                        elem.text or ""
                                    ):
                                        stats["total_cves"] += 1

        logger.info("Extracted scan statistics: %s", stats)
        return stats
    except Exception as exc:
        logger.error("Failed to extract scan statistics from %s: %s", xml_path, exc)
        return {
            "total_hosts": 0,
            "hosts_up": 0,
            "hosts_down": 0,
            "total_ports_found": 0,
            "scan_elapsed_seconds": None,
            "total_cves": 0,
        }


def parse_vulners_script(script_elem, port_id, service_name):
    """Parse vulners NSE script output to extract CVE and exploit data."""
    vulnerabilities = []

    try:
        for table in script_elem.findall(".//table"):
            cpe = table.get("key", "")
            vuln = {"port": port_id, "service": service_name, "cpe": cpe}

            elems = {}
            for elem in table.findall("elem"):
                key = elem.get("key")
                value = elem.text or ""
                elems[key] = value

            if "id" in elems:
                vuln["cve_id"] = elems["id"]
                vuln["type"] = elems.get("type", "unknown")
                vuln["is_exploit"] = elems.get("is_exploit", "false").lower() == "true"
                vuln["cvss"] = elems.get("cvss", "N/A")

                vuln_id = vuln["cve_id"]
                if vuln["type"] == "cve":
                    vuln["url"] = f"https://vulners.com/cve/{vuln_id}"
                elif vuln["type"] == "githubexploit":
                    vuln["url"] = f"https://vulners.com/githubexploit/{vuln_id}"
                else:
                    vuln["url"] = f"https://vulners.com/{vuln['type']}/{vuln_id}"

                vulnerabilities.append(vuln)
    except Exception as exc:
        logger.error("Failed to parse vulners script: %s", exc)

    return vulnerabilities


def parse_scan_xml_for_assets(xml_path):
    """Parse nmap XML file and extract asset data including vulnerability information."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        assets = []

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            asset = {
                "ip": "",
                "hostname": "",
                "mac": "",
                "vendor": "",
                "ports": "",
                "status": "up",
                "vulnerabilities": [],
            }

            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    asset["ip"] = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    asset["mac"] = addr.get("addr")
                    asset["vendor"] = addr.get("vendor", "")

            hostnames = host.find("hostnames")
            if hostnames is not None:
                hostname = hostnames.find("hostname")
                if hostname is not None:
                    asset["hostname"] = hostname.get("name", "")

            ports_elem = host.find("ports")
            if ports_elem is not None:
                open_ports = []
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = port.get("portid")
                        service = port.find("service")
                        service_name = (
                            service.get("name", "") if service is not None else ""
                        )
                        service_product = (
                            service.get("product", "") if service is not None else ""
                        )

                        open_ports.append(
                            f"{port_id} ({service_name})" if service_name else port_id
                        )

                        for script in port.findall("script"):
                            if script.get("id") == "vulners":
                                asset["vulnerabilities"].extend(
                                    parse_vulners_script(
                                        script, port_id, service_name or service_product
                                    )
                                )

                asset["ports"] = ", ".join(open_ports)

            if asset["ip"]:
                assets.append(asset)

        logger.info("Parsed %s assets from XML: %s", len(assets), xml_path)
        return assets
    except Exception as exc:
        logger.error("Failed to parse XML for asset resumption: %s", exc)
        return []


def get_most_recent_scan_xml(
    customer_id,
    *,
    customers,
    scans_dir,
    sanitize_customer_dir_name,
    max_days=7,
):
    """Find the most recent scan XML file for a customer within max_days."""
    customer = next(
        (candidate for candidate in customers if candidate.get("id") == customer_id),
        None,
    )
    customer_name = customer.get("name", "Unknown") if customer else "Unknown"

    cutoff_date = datetime.now() - timedelta(days=max_days)
    recent_scans = []
    for metadata_file, metadata in iter_scan_metadata_documents(
        scans_dir,
        load_json_document,
        normalize_scan_metadata_document,
        logger=logger,
    ):
        scan_dir = metadata_file.parent
        xml_file = scan_dir / "scan.xml"
        if not xml_file.exists():
            continue

        scan_time_str = metadata.get("timestamp", "")
        if not scan_time_str:
            continue

        metadata_customer_id = metadata.get("customer_id", "")
        if not metadata_customer_id:
            metadata_customer_id = str(
                metadata.get("customer_info", {}).get("id", "") or ""
            )

        if metadata_customer_id != customer_id:
            continue

        try:
            scan_time = datetime.fromisoformat(scan_time_str)
        except ValueError as exc:
            logger.warning("Failed to parse scan timestamp from %s: %s", metadata_file, exc)
            continue

        if scan_time >= cutoff_date:
            recent_scans.append(
                {
                    "xml_path": xml_file,
                    "metadata": metadata,
                    "scan_time": scan_time,
                }
            )

    if not recent_scans and customer:
        safe_customer_name = sanitize_customer_dir_name(customer_name)
        search_dirs = [
            scans_dir / safe_customer_name,
            scans_dir / customer_name,
            scans_dir / "Unknown_Network",
        ]

        for customer_scans_dir in search_dirs:
            if not customer_scans_dir.exists():
                continue
            for date_dir in customer_scans_dir.iterdir():
                if not date_dir.is_dir():
                    continue
                for scan_dir in date_dir.iterdir():
                    if not scan_dir.is_dir():
                        continue

                    metadata_file = scan_dir / "metadata.json"
                    xml_file = scan_dir / "scan.xml"
                    if not (metadata_file.exists() and xml_file.exists()):
                        continue

                    try:
                        metadata = normalize_scan_metadata_document(
                            load_json_document(metadata_file, {})
                        )
                        scan_time_str = metadata.get("timestamp", "")
                        if not scan_time_str:
                            continue
                        scan_time = datetime.fromisoformat(scan_time_str)
                        if scan_time >= cutoff_date:
                            recent_scans.append(
                                {
                                    "xml_path": xml_file,
                                    "metadata": metadata,
                                    "scan_time": scan_time,
                                }
                            )
                    except Exception as exc:
                        logger.warning(
                            "Failed to load metadata from %s: %s",
                            metadata_file,
                            exc,
                        )

    if not recent_scans:
        logger.info(
            "No recent scans found for customer %s within %s days",
            customer_name,
            max_days,
        )
        return None, None

    recent_scans.sort(key=lambda item: item["scan_time"], reverse=True)
    most_recent = recent_scans[0]
    logger.info("Found most recent scan for %s: %s", customer_name, most_recent["xml_path"])
    return most_recent["xml_path"], most_recent["metadata"]


def find_latest_saved_scan_for_pdf(
    target,
    *,
    scans_dir,
    load_json_document,
    normalize_scan_metadata_document,
    max_days=30,
    customer_id=None,
):
    cutoff_date = datetime.now() - timedelta(days=max_days)
    matches = []

    for metadata_file, metadata in iter_scan_metadata_documents(
        scans_dir,
        load_json_document,
        normalize_scan_metadata_document,
        logger=logger,
    ):
        scan_dir = metadata_file.parent
        xml_file = scan_dir / "scan.xml"
        if not xml_file.exists():
            continue

        timestamp = metadata.get("timestamp")
        if not timestamp or metadata.get("target") != target:
            continue

        try:
            scan_time = datetime.fromisoformat(timestamp)
        except ValueError:
            continue

        if scan_time < cutoff_date:
            continue

        metadata_customer_id = metadata.get("customer_id") or str(
            metadata.get("customer_info", {}).get("id", "") or ""
        )
        if customer_id and metadata_customer_id and metadata_customer_id != customer_id:
            continue

        matches.append((scan_time, scan_dir, xml_file))

    if not matches:
        return None, None

    matches.sort(key=lambda item: item[0], reverse=True)
    _, scan_dir, xml_file = matches[0]
    return scan_dir, xml_file


def generate_pdf_from_saved_task(context, sid, data):
    job_registry = context["job_registry"]
    emit_job_status = context["emit_job_status"]
    emit_to_client = context["emit_to_client"]
    get_client_state = context["get_client_state"]
    find_latest_saved_scan_for_pdf = context["find_latest_saved_scan_for_pdf"]
    convert_xml_to_html = context["convert_xml_to_html"]
    convert_html_to_pdf = context["convert_html_to_pdf"]
    get_app_version = context["get_app_version"]
    logger = context["logger"]
    scans_dir = context["scans_dir"]
    socketio_sleep = context["socketio_sleep"]
    web_stylesheet = context["web_stylesheet"]
    pdf_stylesheet = context["pdf_stylesheet"]

    target = data.get("target")
    max_days = int(data.get("max_days", 30))
    customer_id = str(get_client_state(sid=sid)["current_customer"].get("id", "") or "")

    if not target:
        emit_to_client(sid, "report_error", {"error": "No target specified"})
        return

    if not job_registry.start(
        sid,
        "report",
        {"target": target, "customer_name": data.get("customer_name"), "mode": "pdf_only"},
    ):
        emit_to_client(sid, "report_error", {"error": "A report job is already running for this client"})
        emit_job_status(sid, "report")
        return

    emit_job_status(sid, "report")
    start_time = datetime.now()

    try:
        emit_to_client(sid, "scan_feedback", f"Looking for latest saved scan for {target}...")
        scan_dir, xml_path = find_latest_saved_scan_for_pdf(
            target,
            customer_id=customer_id if customer_id and customer_id != "unknown" else None,
            max_days=max_days,
        )

        if not scan_dir or not xml_path:
            raise RuntimeError("No saved scan found for this target. Run a chunked scan first.")

        emit_to_client(sid, "scan_feedback", f"Using saved scan: {scan_dir.name}")
        web_html_path = scan_dir / "scan_web.html"
        pdf_html_path = scan_dir / "scan_pdf.html"
        pdf_path = scan_dir / "scan_report.pdf"
        feedback = lambda message: (emit_to_client(sid, "scan_feedback", message), socketio_sleep(0))

        emit_to_client(sid, "scan_feedback", "Converting XML to HTML (web view)...")
        convert_xml_to_html(
            xml_path,
            web_html_path,
            stylesheet=web_stylesheet,
            get_app_version=get_app_version,
            feedback=feedback,
        )

        emit_to_client(sid, "scan_feedback", "Converting XML to HTML (PDF view)...")
        convert_xml_to_html(
            xml_path,
            pdf_html_path,
            stylesheet=pdf_stylesheet,
            get_app_version=get_app_version,
            feedback=feedback,
        )

        emit_to_client(sid, "scan_feedback", "Generating PDF report...")
        if not convert_html_to_pdf(pdf_html_path, pdf_path, feedback=feedback):
            raise RuntimeError("PDF generation failed from saved scan")

        duration = datetime.now() - start_time
        duration_str = f"{int(duration.total_seconds() // 60)}m{int(duration.total_seconds() % 60)}s"
        relative_path = str(scan_dir.relative_to(scans_dir))

        emit_to_client(sid, "scan_feedback", f"PDF generation completed in {duration_str}")
        emit_to_client(
            sid,
            "report_complete",
            {"status": "success", "path": relative_path, "scan_dir": str(scan_dir)},
        )
        job_registry.complete(
            sid,
            "report",
            status="completed",
            details={"target": target, "path": relative_path, "mode": "pdf_only"},
        )
        emit_job_status(sid, "report")
    except Exception as exc:
        logger.exception("PDF generation from saved scan failed")
        job_registry.complete(sid, "report", status="failed", details={"error": str(exc)})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": str(exc)})
    finally:
        job_registry.clear_if_disconnected(sid, "report")
