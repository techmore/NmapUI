import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

from nmapui.reporting import (
    build_report_diff_summary,
    extract_scan_statistics,
    find_latest_saved_scan_for_pdf,
    find_previous_scan_metadata,
    generate_pdf_from_saved_task,
    get_most_recent_scan_xml,
    inject_diff_summary_into_report_html,
    mark_scan_failure,
    merge_nmap_xml_files,
    parse_scan_xml_for_assets,
    parse_vulners_script,
    render_report_diff_summary_html,
    save_scan_metadata,
    summarize_asset_differences,
)


def test_parse_vulners_script_extracts_vulnerability_fields():
    script = ET.fromstring(
        """
        <script id="vulners">
          <table key="cpe:/a:test:demo">
            <elem key="id">CVE-2026-0001</elem>
            <elem key="type">cve</elem>
            <elem key="cvss">7.5</elem>
            <elem key="is_exploit">false</elem>
          </table>
        </script>
        """
    )

    vulns = parse_vulners_script(script, "443", "https")

    assert vulns[0]["cve_id"] == "CVE-2026-0001"
    assert vulns[0]["url"] == "https://vulners.com/cve/CVE-2026-0001"


def test_extract_scan_statistics_counts_ports_and_cves(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(
        """
        <nmaprun>
          <host>
            <ports>
              <port portid="22">
                <state state="open"/>
                <script id="vulners">
                  <table><elem key="id">CVE-2026-0001</elem></table>
                </script>
              </port>
            </ports>
          </host>
          <runstats>
            <hosts up="1" down="0" total="1"/>
            <finished elapsed="12.5"/>
          </runstats>
        </nmaprun>
        """
    )

    stats = extract_scan_statistics(xml_path)

    assert stats["hosts_up"] == 1
    assert stats["total_ports_found"] == 1
    assert stats["total_cves"] == 1


def test_parse_scan_xml_for_assets_extracts_asset_data(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
            <hostnames><hostname name="router.local"/></hostnames>
            <ports>
              <port portid="80">
                <state state="open"/>
                <service name="http"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )

    assets = parse_scan_xml_for_assets(xml_path)

    assert assets[0]["ip"] == "192.168.1.10"
    assert assets[0]["hostname"] == "router.local"
    assert assets[0]["vendor"] == "Acme"
    assert assets[0]["ports"] == "80 (http)"


def test_save_scan_metadata_persists_customer_id(tmp_path):
    scan_dir = tmp_path / "data" / "scans" / "Acme" / "2026-03-14" / "scan_010000_target"
    scan_dir.mkdir(parents=True)

    save_scan_metadata(
        scan_dir,
        "Acme Customer",
        "192.168.1.0/24",
        {"xml": scan_dir / "scan.xml"},
        network_key={"target": "192.168.1.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=3),
        end_time=datetime.now(),
    )

    metadata = json.loads((scan_dir / "metadata.json").read_text())
    index = json.loads((tmp_path / "data" / "scans" / ".scan_metadata_index.json").read_text())

    assert metadata["customer_id"] == "cust-123"
    assert metadata["customer_name"] == "Acme Customer"
    assert index["entries"][0]["path"] == "Acme/2026-03-14/scan_010000_target"
    assert index["entries"][0]["metadata"]["customer_id"] == "cust-123"


def test_save_scan_metadata_persists_diff_summary_for_followup_scan(tmp_path):
    scans_root = tmp_path / "data" / "scans"
    older = scans_root / "Acme" / "2026-03-13" / "scan_010000_target"
    newer = scans_root / "Acme" / "2026-03-14" / "scan_020000_target"
    older.mkdir(parents=True)
    newer.mkdir(parents=True)
    (older / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="10.0.0.10" addrtype="ipv4"/>
            <ports>
              <port portid="80"><state state="open"/><service name="http"/></port>
            </ports>
          </host>
        </nmaprun>
        """
    )
    (newer / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="10.0.0.10" addrtype="ipv4"/>
            <ports>
              <port portid="443"><state state="open"/><service name="https"/></port>
            </ports>
          </host>
          <host>
            <status state="up"/>
            <address addr="10.0.0.20" addrtype="ipv4"/>
          </host>
        </nmaprun>
        """
    )

    save_scan_metadata(
        older,
        "Acme Customer",
        "10.0.0.0/24",
        {"xml": older / "scan.xml"},
        network_key={"target": "10.0.0.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=4),
        end_time=datetime.now() - timedelta(minutes=3),
    )
    save_scan_metadata(
        newer,
        "Acme Customer",
        "10.0.0.0/24",
        {"xml": newer / "scan.xml"},
        network_key={"target": "10.0.0.0/24"},
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        start_time=datetime.now() - timedelta(minutes=2),
        end_time=datetime.now(),
    )

    newer_metadata = json.loads((newer / "metadata.json").read_text())
    index = json.loads((scans_root / ".scan_metadata_index.json").read_text())
    newer_entry = next(
        entry
        for entry in index["entries"]
        if entry["path"] == "Acme/2026-03-14/scan_020000_target"
    )

    assert newer_metadata["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert newer_metadata["diff_summary"]["added_hosts"] == ["10.0.0.20"]
    assert newer_metadata["diff_summary"]["new_ports"] == ["443 (https)"]
    assert newer_entry["metadata"]["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"


def test_get_most_recent_scan_xml_prefers_customer_id_over_folder_name(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    renamed_customer_dir = scans_dir / "Renamed_Customer" / "2026-03-13" / "scan_010000_target"
    renamed_customer_dir.mkdir(parents=True)
    (renamed_customer_dir / "scan.xml").write_text("<nmaprun/>")
    (renamed_customer_dir / "metadata.json").write_text(
        """
        {
          "customer_id": "cust-123",
          "customer_name": "Renamed Customer",
          "timestamp": "2026-03-13T01:00:00"
        }
        """
    )

    xml_path, metadata = get_most_recent_scan_xml(
        "cust-123",
        customers=[{"id": "cust-123", "name": "Original Customer"}],
        scans_dir=scans_dir,
        sanitize_customer_dir_name=lambda value: value.replace(" ", "_"),
        max_days=30,
    )

    assert xml_path == renamed_customer_dir / "scan.xml"
    assert metadata["customer_id"] == "cust-123"


def test_get_most_recent_scan_xml_ignores_invalid_metadata_files(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    valid_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    invalid_dir = scans_dir / "Broken" / "2026-03-13" / "scan_020000_target"
    valid_dir.mkdir(parents=True)
    invalid_dir.mkdir(parents=True)

    (valid_dir / "scan.xml").write_text("<nmaprun/>")
    (valid_dir / "metadata.json").write_text(
        """
        {
          "customer_id": "cust-123",
          "customer_name": "Acme Customer",
          "timestamp": "2026-03-13T01:00:00"
        }
        """
    )
    (invalid_dir / "scan.xml").write_text("<nmaprun/>")
    (invalid_dir / "metadata.json").write_text("{not-json")

    xml_path, metadata = get_most_recent_scan_xml(
        "cust-123",
        customers=[{"id": "cust-123", "name": "Acme Customer"}],
        scans_dir=scans_dir,
        sanitize_customer_dir_name=lambda value: value.replace(" ", "_"),
        max_days=30,
    )

    assert xml_path == valid_dir / "scan.xml"
    assert metadata["customer_id"] == "cust-123"


def test_mark_scan_failure_persists_incomplete_artifact_metadata(tmp_path):
    scan_dir = tmp_path / "data" / "scans" / "Acme" / "2026-03-14" / "scan_010000_target"
    scan_dir.mkdir(parents=True)

    mark_scan_failure(
        scan_dir,
        target="192.168.1.0/24",
        customer_name="Acme Customer",
        current_customer={"id": "cust-123", "name": "Acme Customer"},
        error="Nmap scan failed on chunk 2",
        stage="scan_chunks",
    )

    metadata = json.loads((scan_dir / "metadata.json").read_text())
    index = json.loads((tmp_path / "data" / "scans" / ".scan_metadata_index.json").read_text())

    assert metadata["status"] == "failed"
    assert metadata["failure_stage"] == "scan_chunks"
    assert metadata["failure_error"] == "Nmap scan failed on chunk 2"
    assert metadata["completed_successfully"] is False
    assert metadata["customer_id"] == "cust-123"
    assert index["entries"][0]["metadata"]["status"] == "failed"
    assert index["entries"][0]["metadata"]["failure_stage"] == "scan_chunks"


def test_merge_nmap_xml_files_combines_hosts_and_updates_runstats(tmp_path):
    first = tmp_path / "first.xml"
    second = tmp_path / "second.xml"
    merged = tmp_path / "merged.xml"

    first.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun args="nmap 192.168.1.1">
  <host starttime="100" endtime="130">
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished summary="first" />
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""
    )
    second.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun args="nmap 192.168.1.2">
  <host starttime="140" endtime="190">
    <status state="up"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished summary="second" />
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""
    )

    merge_nmap_xml_files([first, second], merged)

    root = ET.fromstring(merged.read_text())
    hosts = root.findall("host")
    runstats = root.find("runstats")
    hosts_elem = runstats.find("hosts")

    assert len(hosts) == 2
    assert hosts_elem.get("up") == "2"
    assert hosts_elem.get("down") == "0"
    assert hosts_elem.get("total") == "2"


def test_find_latest_saved_scan_for_pdf_prefers_latest_matching_customer(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    older = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    newer = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    older.mkdir(parents=True)
    newer.mkdir(parents=True)
    (older / "scan.xml").write_text("<nmaprun/>")
    (newer / "scan.xml").write_text("<nmaprun/>")
    (older / "metadata.json").write_text(
        '{"target":"192.168.1.0/24","customer_id":"cust-123","timestamp":"2026-03-13T01:00:00"}'
    )
    (newer / "metadata.json").write_text(
        '{"target":"192.168.1.0/24","customer_id":"cust-123","timestamp":"2026-03-14T02:00:00"}'
    )

    scan_dir, xml_path = find_latest_saved_scan_for_pdf(
        "192.168.1.0/24",
        scans_dir=scans_dir,
        load_json_document=lambda path, default: json.loads(path.read_text()),
        normalize_scan_metadata_document=lambda value: value,
        customer_id="cust-123",
        max_days=30,
    )

    assert scan_dir == newer
    assert xml_path == newer / "scan.xml"


def test_generate_pdf_from_saved_task_completes_report_job(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    previous_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    previous_dir.mkdir(parents=True)
    scan_dir.mkdir(parents=True)
    (previous_dir / "metadata.json").write_text(
        '{"path":"Acme/2026-03-13/scan_010000_target","customer_id":"cust-123","target":"192.168.1.0/24","timestamp":"2026-03-13T01:00:00"}'
    )
    (previous_dir / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port portid="80"><state state="open"/><service name="http"/></port></ports>
          </host>
        </nmaprun>
        """
    )
    xml_path = scan_dir / "scan.xml"
    xml_path.write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port portid="443"><state state="open"/><service name="https"/></port></ports>
          </host>
        </nmaprun>
        """
    )
    (scan_dir / "metadata.json").write_text(
        '{"path":"Acme/2026-03-14/scan_020000_target","customer_id":"cust-123","target":"192.168.1.0/24","timestamp":"2026-03-14T02:00:00"}'
    )
    observed = {"events": []}

    class JobRegistryStub:
        def start(self, sid, job_type, details):
            observed["started"] = (sid, job_type, details)
            return True

        def complete(self, sid, job_type, status="completed", details=None):
            observed["completed"] = (sid, job_type, status, details)

        def clear_if_disconnected(self, sid, job_type):
            observed["cleared"] = (sid, job_type)

    generate_pdf_from_saved_task(
        {
            "job_registry": JobRegistryStub(),
            "emit_job_status": lambda sid, job_type: observed.setdefault("status_calls", []).append((sid, job_type)),
            "emit_to_client": lambda sid, event, data=None: observed["events"].append((sid, event, data)),
            "get_client_state": lambda sid=None: {"current_customer": {"id": "cust-123"}},
            "find_latest_saved_scan_for_pdf": lambda target, **kwargs: (scan_dir, xml_path),
            "convert_xml_to_html": lambda xml_path, html_path, **kwargs: html_path.write_text(
                "<html><body><h1>Report</h1></body></html>",
                encoding="utf-8",
            ) or True,
            "convert_html_to_pdf": lambda *args, **kwargs: True,
            "get_app_version": lambda: "v1.0.0",
            "logger": type("LoggerStub", (), {"exception": lambda self, *args, **kwargs: None})(),
            "scans_dir": scans_dir,
            "socketio_sleep": lambda value: None,
            "web_stylesheet": "web.xsl",
            "pdf_stylesheet": "pdf.xsl",
        },
        "sid-1",
        {"target": "192.168.1.0/24", "customer_name": "Acme Customer"},
    )

    assert observed["started"][1] == "report"
    assert observed["completed"][2] == "completed"
    assert observed["completed"][3]["mode"] == "pdf_only"
    assert observed["cleared"] == ("sid-1", "report")
    report_complete = next(event for event in observed["events"] if event[1] == "report_complete")
    assert report_complete[2]["diff_summary"]["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert 'id="scan-diff-summary"' in (scan_dir / "scan_web.html").read_text(encoding="utf-8")
    assert 'id="scan-diff-summary"' in (scan_dir / "scan_pdf.html").read_text(encoding="utf-8")


def test_find_previous_scan_metadata_matches_customer_and_target():
    current = {
        "path": "Acme/2026-03-14/scan_020000_target",
        "customer_id": "cust-123",
        "target": "192.168.1.0/24",
        "timestamp": "2026-03-14T02:00:00",
    }
    scans = [
        current,
        {
            "path": "Acme/2026-03-13/scan_010000_target",
            "customer_id": "cust-123",
            "target": "192.168.1.0/24",
            "timestamp": "2026-03-13T01:00:00",
        },
        {
            "path": "Other/2026-03-13/scan_010000_target",
            "customer_id": "cust-999",
            "target": "192.168.1.0/24",
            "timestamp": "2026-03-13T03:00:00",
        },
    ]

    previous = find_previous_scan_metadata(current, scans)

    assert previous["path"] == "Acme/2026-03-13/scan_010000_target"


def test_summarize_asset_differences_reports_added_removed_and_changed_hosts():
    previous_assets = [
        {
            "ip": "192.168.1.10",
            "hostname": "router.local",
            "ports": "22 (ssh), 80 (http)",
            "vulnerabilities": [{"cve_id": "CVE-2026-0001"}],
        },
        {
            "ip": "192.168.1.20",
            "hostname": "printer.local",
            "ports": "9100 (jetdirect)",
            "vulnerabilities": [],
        },
    ]
    current_assets = [
        {
            "ip": "192.168.1.10",
            "hostname": "router.local",
            "ports": "22 (ssh), 443 (https)",
            "vulnerabilities": [{"cve_id": "CVE-2026-0002"}],
        },
        {
            "ip": "192.168.1.30",
            "hostname": "camera.local",
            "ports": "554 (rtsp)",
            "vulnerabilities": [],
        },
    ]

    diff = summarize_asset_differences(current_assets, previous_assets)

    assert diff["has_changes"] is True
    assert diff["added_hosts"] == ["192.168.1.30"]
    assert diff["removed_hosts"] == ["192.168.1.20"]
    assert diff["new_ports"] == ["443 (https)", "554 (rtsp)"]
    assert "80 (http)" in diff["removed_ports"]
    assert diff["new_vulnerabilities"] == ["CVE-2026-0002"]
    assert diff["removed_vulnerabilities"] == ["CVE-2026-0001"]
    assert diff["changed_hosts"][0]["host"] == "192.168.1.10"


def test_build_report_diff_summary_uses_previous_matching_scan(tmp_path):
    scans_dir = tmp_path / "data" / "scans"
    previous_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    current_dir = scans_dir / "Acme" / "2026-03-14" / "scan_020000_target"
    previous_dir.mkdir(parents=True)
    current_dir.mkdir(parents=True)

    (previous_dir / "metadata.json").write_text(
        '{"path":"Acme/2026-03-13/scan_010000_target","customer_id":"cust-123","target":"192.168.1.0/24","timestamp":"2026-03-13T01:00:00"}'
    )
    (current_dir / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port portid="443"><state state="open"/><service name="https"/></port></ports>
          </host>
        </nmaprun>
        """
    )
    (previous_dir / "scan.xml").write_text(
        """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port portid="80"><state state="open"/><service name="http"/></port></ports>
          </host>
        </nmaprun>
        """
    )

    diff_summary = build_report_diff_summary(
        {
            "path": "Acme/2026-03-14/scan_020000_target",
            "customer_id": "cust-123",
            "target": "192.168.1.0/24",
            "timestamp": "2026-03-14T02:00:00",
        },
        current_dir / "scan.xml",
        scans_dir=scans_dir,
    )

    assert diff_summary["baseline_path"] == "Acme/2026-03-13/scan_010000_target"
    assert diff_summary["removed_ports"] == ["80 (http)"]
    assert diff_summary["new_ports"] == ["443 (https)"]


def test_inject_diff_summary_into_report_html_adds_summary_section(tmp_path):
    html_path = tmp_path / "scan_web.html"
    html_path.write_text("<html><body><h1>Report</h1></body></html>", encoding="utf-8")

    inject_diff_summary_into_report_html(
        html_path,
        {
            "has_changes": True,
            "baseline_timestamp": "2026-03-13T01:00:00",
            "added_hosts": ["192.168.1.20"],
            "removed_hosts": [],
            "changed_hosts": [{"host": "192.168.1.10"}],
            "new_ports": ["443 (https)"],
            "removed_ports": ["80 (http)"],
            "new_vulnerabilities": ["CVE-2026-0002"],
            "removed_vulnerabilities": [],
        },
    )

    html = html_path.read_text(encoding="utf-8")

    assert 'id="scan-diff-summary"' in html
    assert "Changes Since Previous Scan" in html
    assert "1 new host(s)" in html
    assert "1 changed host(s)" in html
    assert "1 new vulnerabilit" in html


def test_render_report_diff_summary_html_returns_empty_string_without_changes():
    assert render_report_diff_summary_html(None) == ""
    assert render_report_diff_summary_html({"has_changes": False}) == ""
