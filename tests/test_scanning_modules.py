from pathlib import Path

import nmapui.scanning as scanning
from nmapui.scanning import create_scan_folder


def test_create_scan_folder_uses_customer_and_target_structure(tmp_path):
    scan_dir = create_scan_folder(
        "Acme Customer",
        "192.168.1.0/24",
        scans_dir=tmp_path,
        sanitize_customer_dir_name=lambda value: value.replace(" ", "_"),
    )

    assert isinstance(scan_dir, Path)
    assert scan_dir.parent.parent == tmp_path / "Acme_Customer"
    assert scan_dir.name.startswith("scan_")
    assert "192.168.1.0_24" in scan_dir.name


def test_get_nmap_scan_technique_uses_connect_scan_without_root(monkeypatch):
    monkeypatch.setattr(scanning.os, "geteuid", lambda: 501, raising=False)
    assert scanning.get_nmap_scan_technique() == "-sT"


def test_get_nmap_scan_technique_uses_syn_scan_as_root(monkeypatch):
    monkeypatch.setattr(scanning.os, "geteuid", lambda: 0, raising=False)
    assert scanning.get_nmap_scan_technique() == "-sS"
