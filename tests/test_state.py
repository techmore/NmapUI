from persistence import iter_scan_metadata_documents
from nmapui.state import get_report_counts


def test_iter_scan_metadata_documents_skips_invalid_entries_and_normalizes(tmp_path):
    scans_dir = tmp_path / "scans"
    valid_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    invalid_dir = scans_dir / "Broken" / "2026-03-13" / "scan_020000_target"
    valid_dir.mkdir(parents=True)
    invalid_dir.mkdir(parents=True)

    (valid_dir / "metadata.json").write_text('{"customer_name":"Acme","timestamp":"2026-03-13T01:00:00"}')
    (invalid_dir / "metadata.json").write_text("{not-json")

    logger_calls = []

    documents = list(
        iter_scan_metadata_documents(
            scans_dir,
            lambda path, default: __import__("json").loads(path.read_text()),
            lambda value: value,
            logger=type(
                "LoggerStub",
                (),
                {"error": lambda self, message, path, exc: logger_calls.append((message, path.name, type(exc).__name__))},
            )(),
        )
    )

    assert len(documents) == 1
    assert documents[0][0] == valid_dir / "metadata.json"
    assert documents[0][1]["customer_name"] == "Acme"
    assert logger_calls == [("Error reading metadata at %s: %s", "metadata.json", "JSONDecodeError")]


def test_get_report_counts_ignores_invalid_metadata_files(tmp_path):
    scans_dir = tmp_path / "scans"
    good_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    bad_dir = scans_dir / "Broken" / "2026-03-13" / "scan_020000_target"
    good_dir.mkdir(parents=True)
    bad_dir.mkdir(parents=True)

    (good_dir / "metadata.json").write_text(
        '{"customer_name":"Acme (0.82)","timestamp":"2026-03-13T01:00:00"}'
    )
    (bad_dir / "metadata.json").write_text("{not-json")

    counts = get_report_counts(
        scans_dir,
        lambda value: value,
        lambda path, default: __import__("json").loads(path.read_text()),
    )

    assert counts["Acme"] == 1
    assert counts["total"] == 1
    assert counts["last_scans"]["Acme"] == "2026-03-13T01:00:00"
