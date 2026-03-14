from datetime import datetime, timedelta
import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET

from persistence import (
    load_json_document,
    normalize_scan_metadata_document,
    save_json_document,
)


logger = logging.getLogger(__name__)


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
    for metadata_file in scans_dir.glob("**/metadata.json"):
        scan_dir = metadata_file.parent
        xml_file = scan_dir / "scan.xml"
        if not xml_file.exists():
            continue

        try:
            metadata = normalize_scan_metadata_document(
                load_json_document(metadata_file, {})
            )
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
            logger.warning("Failed to load metadata from %s: %s", metadata_file, exc)

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
