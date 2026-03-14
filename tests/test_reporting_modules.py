import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

from nmapui.reporting import (
    extract_scan_statistics,
    get_most_recent_scan_xml,
    parse_scan_xml_for_assets,
    parse_vulners_script,
    save_scan_metadata,
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
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()

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

    assert metadata["customer_id"] == "cust-123"
    assert metadata["customer_name"] == "Acme Customer"


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
