import xml.etree.ElementTree as ET

from nmapui.reporting import (
    extract_scan_statistics,
    parse_scan_xml_for_assets,
    parse_vulners_script,
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
