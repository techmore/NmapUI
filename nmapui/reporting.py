from datetime import datetime, timedelta
from html import escape
import io
import logging
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from persistence import (
    get_scan_metadata_index_path,
    iter_scan_metadata_documents,
    load_json_document,
    load_scan_metadata_index,
    normalize_scan_metadata_document,
    normalize_scan_metadata_index_document,
    save_json_document,
    save_scan_metadata_index,
    upsert_scan_metadata_index_entry,
)


logger = logging.getLogger(__name__)


def _get_scans_dir_for_scan(scan_dir):
    return scan_dir.parents[2]


def _normalize_asset_ports(asset):
    ports = set()
    for item in (asset.get("ports") or "").split(","):
        value = item.strip()
        if value:
            ports.add(value)
    return ports


def _normalize_asset_vulns(asset):
    vulns = set()
    for vuln in asset.get("vulnerabilities") or []:
        cve_id = str(vuln.get("cve_id", "") or "").strip()
        if cve_id:
            vulns.add(cve_id)
    return vulns


def _asset_identity(asset):
    hostname = str(asset.get("hostname", "") or "").strip().lower()
    ip = str(asset.get("ip", "") or "").strip()
    mac = str(asset.get("mac", "") or "").strip().lower()
    if ip:
        return ("ip", ip)
    if hostname:
        return ("hostname", hostname)
    return ("mac", mac)


def summarize_asset_differences(current_assets, previous_assets):
    current_by_id = {_asset_identity(asset): asset for asset in current_assets or []}
    previous_by_id = {_asset_identity(asset): asset for asset in previous_assets or []}

    added_hosts = []
    removed_hosts = []
    changed_hosts = []
    new_ports = set()
    removed_ports = set()
    new_vulnerabilities = set()
    removed_vulnerabilities = set()

    for asset_id, asset in current_by_id.items():
        previous = previous_by_id.get(asset_id)
        if previous is None:
            added_hosts.append(asset.get("ip") or asset.get("hostname") or asset.get("mac"))
            new_ports.update(_normalize_asset_ports(asset))
            new_vulnerabilities.update(_normalize_asset_vulns(asset))
            continue

        current_ports = _normalize_asset_ports(asset)
        previous_ports = _normalize_asset_ports(previous)
        current_vulns = _normalize_asset_vulns(asset)
        previous_vulns = _normalize_asset_vulns(previous)

        added_for_host = sorted(current_ports - previous_ports)
        removed_for_host = sorted(previous_ports - current_ports)
        added_vulns = sorted(current_vulns - previous_vulns)
        removed_vulns = sorted(previous_vulns - current_vulns)

        if added_for_host or removed_for_host or added_vulns or removed_vulns:
            changed_hosts.append(
                {
                    "host": asset.get("ip") or asset.get("hostname") or asset.get("mac"),
                    "new_ports": added_for_host,
                    "removed_ports": removed_for_host,
                    "new_vulnerabilities": added_vulns,
                    "removed_vulnerabilities": removed_vulns,
                }
            )

        new_ports.update(added_for_host)
        removed_ports.update(removed_for_host)
        new_vulnerabilities.update(added_vulns)
        removed_vulnerabilities.update(removed_vulns)

    for asset_id, asset in previous_by_id.items():
        if asset_id not in current_by_id:
            removed_hosts.append(asset.get("ip") or asset.get("hostname") or asset.get("mac"))
            removed_ports.update(_normalize_asset_ports(asset))
            removed_vulnerabilities.update(_normalize_asset_vulns(asset))

    return {
        "has_changes": bool(
            added_hosts
            or removed_hosts
            or changed_hosts
            or new_ports
            or removed_ports
            or new_vulnerabilities
            or removed_vulnerabilities
        ),
        "added_hosts": sorted(value for value in added_hosts if value),
        "removed_hosts": sorted(value for value in removed_hosts if value),
        "changed_hosts": changed_hosts,
        "new_ports": sorted(new_ports),
        "removed_ports": sorted(removed_ports),
        "new_vulnerabilities": sorted(new_vulnerabilities),
        "removed_vulnerabilities": sorted(removed_vulnerabilities),
    }


def find_previous_scan_metadata(current_metadata, scan_entries):
    current_path = str(current_metadata.get("path", "") or "")
    current_timestamp = str(current_metadata.get("timestamp", "") or "")
    current_customer_id = str(current_metadata.get("customer_id", "") or "")
    current_target = str(current_metadata.get("target", "") or "")

    for entry in scan_entries or []:
        if entry.get("path") == current_path:
            continue
        if str(entry.get("customer_id", "") or "") != current_customer_id:
            continue
        if str(entry.get("target", "") or "") != current_target:
            continue
        if str(entry.get("timestamp", "") or "") >= current_timestamp:
            continue
        return entry
    return None


def build_report_diff_summary(current_metadata, current_xml_path, *, scans_dir):
    scan_entries = []
    for metadata_path, metadata in iter_scan_metadata_documents(
        scans_dir,
        load_json_document,
        normalize_scan_metadata_document,
        logger=logger,
    ):
        scan_entries.append(
            {
                **metadata,
                "path": str(metadata_path.parent.relative_to(scans_dir)),
            }
        )

    scan_entries.sort(key=lambda item: str(item.get("timestamp", "") or ""), reverse=True)
    previous = find_previous_scan_metadata(current_metadata, scan_entries)
    if not previous:
        return None

    previous_xml_path = scans_dir / str(previous.get("path", "")) / "scan.xml"
    if not previous_xml_path.exists() or not current_xml_path.exists():
        return None

    diff_summary = summarize_asset_differences(
        parse_scan_xml_for_assets(current_xml_path),
        parse_scan_xml_for_assets(previous_xml_path),
    )
    if not diff_summary.get("has_changes"):
        return None

    return {
        **diff_summary,
        "baseline_path": previous.get("path"),
        "baseline_timestamp": previous.get("timestamp"),
    }


def refresh_persisted_diff_summaries(
    scans_dir,
    *,
    customer_id,
    target,
    logger=logger,
):
    if not customer_id or not target:
        return

    index_path = get_scan_metadata_index_path(scans_dir)
    if not index_path.exists():
        return

    index_document = load_scan_metadata_index(
        scans_dir,
        load_json_document,
        normalize_scan_metadata_index_document,
    )
    entries = index_document.get("entries", [])
    relevant_entries = [
        entry
        for entry in entries
        if str(entry.get("metadata", {}).get("customer_id", "") or "") == str(customer_id)
        and str(entry.get("metadata", {}).get("target", "") or "") == str(target)
    ]
    relevant_entries.sort(
        key=lambda item: str(item.get("metadata", {}).get("timestamp", "") or "")
    )

    previous_entry = None
    updated_by_path = {}
    for entry in relevant_entries:
        metadata = normalize_scan_metadata_document(entry.get("metadata", {}))
        current_path = str(entry.get("path", "") or "")
        current_xml_path = scans_dir / current_path / "scan.xml"
        diff_summary = None

        if (
            previous_entry is not None
            and current_xml_path.exists()
            and (scans_dir / str(previous_entry.get("path", "")) / "scan.xml").exists()
        ):
            previous_xml_path = scans_dir / str(previous_entry.get("path", "")) / "scan.xml"
            try:
                summary = summarize_asset_differences(
                    parse_scan_xml_for_assets(current_xml_path),
                    parse_scan_xml_for_assets(previous_xml_path),
                )
                if summary.get("has_changes"):
                    diff_summary = {
                        **summary,
                        "baseline_path": previous_entry.get("path"),
                        "baseline_timestamp": previous_entry.get("metadata", {}).get("timestamp", ""),
                    }
            except Exception as exc:
                logger.error(
                    "Error refreshing persisted diff summary for %s: %s",
                    current_path,
                    exc,
                )

        if diff_summary:
            metadata["diff_summary"] = diff_summary
        else:
            metadata["diff_summary"] = None

        metadata_path = scans_dir / current_path / "metadata.json"
        if metadata_path.exists():
            save_json_document(metadata_path, normalize_scan_metadata_document(metadata))

        updated_entry = {
            **entry,
            "metadata": normalize_scan_metadata_document(metadata),
        }
        updated_by_path[current_path] = updated_entry
        previous_entry = updated_entry

    if not updated_by_path:
        return

    merged_entries = []
    for entry in entries:
        path = str(entry.get("path", "") or "")
        merged_entries.append(updated_by_path.get(path, entry))

    save_scan_metadata_index(scans_dir, {"entries": merged_entries})


def render_report_diff_summary_html(diff_summary):
    if not diff_summary or not diff_summary.get("has_changes"):
        return ""

    facts = []
    if diff_summary.get("added_hosts"):
        facts.append(f"{len(diff_summary['added_hosts'])} new host(s)")
    if diff_summary.get("removed_hosts"):
        facts.append(f"{len(diff_summary['removed_hosts'])} removed host(s)")
    if diff_summary.get("changed_hosts"):
        facts.append(f"{len(diff_summary['changed_hosts'])} changed host(s)")
    if diff_summary.get("new_ports"):
        facts.append(f"{len(diff_summary['new_ports'])} new port(s)")
    if diff_summary.get("removed_ports"):
        facts.append(f"{len(diff_summary['removed_ports'])} removed port(s)")
    if diff_summary.get("new_vulnerabilities"):
        count = len(diff_summary["new_vulnerabilities"])
        facts.append(f"{count} new vulnerabilit{'y' if count == 1 else 'ies'}")
    if diff_summary.get("removed_vulnerabilities"):
        count = len(diff_summary["removed_vulnerabilities"])
        facts.append(f"{count} resolved vulnerabilit{'y' if count == 1 else 'ies'}")

    baseline_timestamp = str(diff_summary.get("baseline_timestamp", "") or "").strip()
    baseline_value = baseline_timestamp
    if baseline_timestamp:
        try:
            baseline_value = datetime.fromisoformat(baseline_timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            baseline_value = baseline_timestamp

    facts_markup = "".join(
        f'<li style="margin:0 0 6px;">{escape(item)}</li>' for item in facts
    )

    return (
        '<section id="scan-diff-summary" '
        'style="margin:24px 0;padding:18px 20px;border:1px solid #d8c98f;'
        'border-radius:14px;background:#f7f0d4;color:#4c3f1f;">'
        '<h2 style="margin:0 0 8px;font-size:1.2rem;">Changes Since Previous Scan</h2>'
        f'<p style="margin:0 0 12px;font-size:0.92rem;color:#6a5a2a;">Baseline: {escape(baseline_value)}</p>'
        '<ul style="margin:0;padding-left:20px;">'
        f"{facts_markup}"
        "</ul>"
        "</section>"
    )


def inject_diff_summary_into_report_html(html_path, diff_summary):
    if not diff_summary or not diff_summary.get("has_changes") or not html_path.exists():
        return False

    html_text = html_path.read_text(encoding="utf-8")
    summary_html = render_report_diff_summary_html(diff_summary)
    if not summary_html:
        return False

    html_text = re.sub(
        r'<section id="scan-diff-summary".*?</section>',
        "",
        html_text,
        count=1,
        flags=re.DOTALL,
    )

    body_match = re.search(r"<body[^>]*>", html_text, flags=re.IGNORECASE)
    if body_match:
        insert_at = body_match.end()
        updated = html_text[:insert_at] + summary_html + html_text[insert_at:]
    elif "</body>" in html_text:
        updated = html_text.replace("</body>", f"{summary_html}</body>", 1)
    else:
        updated = html_text + summary_html

    html_path.write_text(updated, encoding="utf-8")
    return True


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
                await page.emulate_media(media="print")
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
    runtime_store=None,
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
    scans_dir = _get_scans_dir_for_scan(scan_dir)
    upsert_scan_metadata_index_entry(
        scans_dir,
        scan_dir,
        metadata,
    )
    refresh_persisted_diff_summaries(
        scans_dir,
        customer_id=customer_id,
        target=target,
    )
    persist_report_artifact(
        scan_dir=scan_dir,
        customer_id=customer_id,
        target=target,
        files=files,
        metadata=metadata,
        runtime_store=runtime_store,
    )


def persist_report_artifact(
    *,
    scan_dir,
    customer_id,
    target,
    files,
    metadata,
    runtime_store=None,
):
    if runtime_store is None:
        return

    scans_dir = _get_scans_dir_for_scan(scan_dir)
    runtime_store.upsert_report_artifact(
        scan_path=str(scan_dir.relative_to(scans_dir)),
        customer_id=str(customer_id or ""),
        target=str(target or ""),
        html_path=str(files.get("web_html", "") or ""),
        pdf_path=str(files.get("pdf", "") or ""),
        xml_path=str(files.get("xml", "") or ""),
        payload=normalize_scan_metadata_document(metadata),
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
    scans_dir = _get_scans_dir_for_scan(scan_dir)
    upsert_scan_metadata_index_entry(
        scans_dir,
        scan_dir,
        metadata,
    )
    refresh_persisted_diff_summaries(
        scans_dir,
        customer_id=metadata.get("customer_id"),
        target=metadata.get("target"),
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
    on_job_end = context.get("on_job_end")
    broadcaster = context.get("broadcaster")
    runtime_store = context.get("runtime_store")

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
    if broadcaster is not None:
        broadcaster.start_job(sid, job_type="report")
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
        metadata_path = scan_dir / "metadata.json"
        current_metadata = normalize_scan_metadata_document(
            load_json_document(metadata_path, {})
        )
        current_metadata["path"] = str(scan_dir.relative_to(scans_dir))
        diff_summary = build_report_diff_summary(
            current_metadata,
            xml_path,
            scans_dir=scans_dir,
        )

        emit_to_client(sid, "scan_feedback", "Converting XML to HTML (web view)...")
        convert_xml_to_html(
            xml_path,
            web_html_path,
            stylesheet=web_stylesheet,
            get_app_version=get_app_version,
            feedback=feedback,
        )
        inject_diff_summary_into_report_html(web_html_path, diff_summary)

        emit_to_client(sid, "scan_feedback", "Converting XML to HTML (PDF view)...")
        convert_xml_to_html(
            xml_path,
            pdf_html_path,
            stylesheet=pdf_stylesheet,
            get_app_version=get_app_version,
            feedback=feedback,
        )
        inject_diff_summary_into_report_html(pdf_html_path, diff_summary)

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
            details={"target": target, "path": relative_path, "mode": "pdf_only"},
        )
        persist_report_artifact(
            scan_dir=scan_dir,
            customer_id=customer_id,
            target=target,
            files={
                "xml": xml_path,
                "web_html": web_html_path,
                "pdf_html": pdf_html_path,
                "pdf": pdf_path,
            },
            metadata=current_metadata,
            runtime_store=runtime_store,
        )
        emit_job_status(sid, "report")
    except Exception as exc:
        logger.exception("PDF generation from saved scan failed")
        job_registry.complete(sid, "report", status="failed", details={"error": str(exc)})
        emit_job_status(sid, "report")
        emit_to_client(sid, "report_error", {"error": str(exc)})
    finally:
        if on_job_end:
            on_job_end()
        job_registry.clear_if_disconnected(sid, "report")
