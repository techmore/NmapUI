from datetime import datetime
import re
import shutil

from flask import jsonify, request, send_file
from nmapui.auth import require_auth
from nmapui.reporting import (
    find_previous_scan_metadata,
    parse_scan_xml_for_assets,
    refresh_persisted_diff_summaries,
    summarize_asset_differences,
)
from persistence import iter_scan_metadata_documents, remove_scan_metadata_index_entry


def _normalize_scan_record_from_runtime_artifact(artifact):
    payload = dict(artifact.get("payload", {}) or {})
    if "customer_name" not in payload:
        payload["customer_name"] = payload.get(
            "customer", payload.get("customer_id", "Unknown")
        )

    if payload.get("customer_name"):
        payload["customer_name"] = str(payload["customer_name"]).split(" (")[0]

    payload["path"] = artifact["scan_path"]
    payload["has_html"] = bool(artifact.get("html_path"))
    payload["has_pdf"] = bool(artifact.get("pdf_path"))
    payload["has_xml"] = bool(artifact.get("xml_path"))
    return payload


def _load_artifact_compare_payload(runtime_store, scan_path):
    if runtime_store is None or not hasattr(runtime_store, "get_report_artifact"):
        return None
    artifact = runtime_store.get_report_artifact(scan_path)
    if artifact is None:
        return None
    payload = dict(artifact.get("payload", {}) or {})
    payload["path"] = scan_path
    return payload


def register_scan_routes(app, deps):
    scans_dir = deps["scans_dir"]
    resolve_scan_path = deps["resolve_scan_path"]
    load_json_document = deps["load_json_document"]
    normalize_scan_metadata_document = deps["normalize_scan_metadata_document"]
    logger = deps["logger"]
    runtime_store = deps.get("runtime_store")

    @app.route("/api/scans")
    @require_auth
    def list_scans():
        scans = []
        seen_paths = set()

        if runtime_store is not None:
            for artifact in runtime_store.list_report_artifacts():
                scan = _normalize_scan_record_from_runtime_artifact(artifact)
                scans.append(scan)
                seen_paths.add(scan["path"])

        for metadata_path, data in iter_scan_metadata_documents(
            scans_dir,
            load_json_document,
            normalize_scan_metadata_document,
            logger=logger,
        ):
            if "customer_name" not in data:
                data["customer_name"] = data.get(
                    "customer", data.get("customer_id", "Unknown")
                )

            if data["customer_name"]:
                data["customer_name"] = data["customer_name"].split(" (")[0]

            rel_path = metadata_path.parent.relative_to(scans_dir)
            data["path"] = str(rel_path)
            if data["path"] in seen_paths:
                continue
            data["has_html"] = (metadata_path.parent / "scan_web.html").exists() or (
                metadata_path.parent / "scan.html"
            ).exists()
            data["has_pdf"] = (metadata_path.parent / "scan_report.pdf").exists()
            data["has_xml"] = (metadata_path.parent / "scan.xml").exists()
            scans.append(data)
            seen_paths.add(data["path"])

        scans.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        for scan in scans:
            if scan.get("diff_summary") is not None:
                continue

            previous = find_previous_scan_metadata(scan, scans)
            if previous is None:
                continue

            current_xml = scans_dir / scan["path"] / "scan.xml"
            previous_xml = scans_dir / previous["path"] / "scan.xml"
            if not current_xml.exists() or not previous_xml.exists():
                continue

            try:
                diff_summary = summarize_asset_differences(
                    parse_scan_xml_for_assets(current_xml),
                    parse_scan_xml_for_assets(previous_xml),
                )
            except Exception as exc:
                logger.error("Error building diff summary for %s: %s", scan["path"], exc)
                continue

            if diff_summary.get("has_changes"):
                scan["diff_summary"] = {
                    **diff_summary,
                    "baseline_path": previous["path"],
                    "baseline_timestamp": previous.get("timestamp", ""),
                }
        return jsonify({"scans": scans})

    @app.route("/api/scans/<path:path>/html")
    @require_auth
    def get_scan_html(path):
        scan_dir = resolve_scan_path(path)
        if scan_dir is None:
            return "Invalid path", 400

        html_path = scan_dir / "scan_web.html"
        if not html_path.exists():
            html_path = scan_dir / "scan.html"
        if not html_path.exists():
            return "Report not found", 404
        return send_file(html_path)

    @app.route("/api/scans/<path:path>/pdf")
    @require_auth
    def get_scan_pdf(path):
        scan_dir = resolve_scan_path(path)
        if scan_dir is None:
            return "Invalid path", 400

        pdf_path = scan_dir / "scan_report.pdf"
        if not pdf_path.exists():
            return "PDF not found", 404

        download_name = "Nmap_Audit_Report.pdf"
        metadata_path = scan_dir / "metadata.json"
        if metadata_path.exists():
            try:
                meta = normalize_scan_metadata_document(
                    load_json_document(metadata_path, {})
                )
                customer = meta.get("customer_name", "Unknown").split(" (")[0]
                target = meta.get("target", "scan").replace("/", "_")
                date_str = meta.get("date", datetime.now().strftime("%Y-%m-%d"))
                time_str = meta.get("time", "000000").replace(":", "")
                safe_cust = re.sub(r"[^\w\-]", "_", customer)
                safe_target = re.sub(r"[^\w\.]", "_", target)
                download_name = (
                    f"Nmap_Audit_{safe_cust}_{safe_target}_{date_str}_{time_str}.pdf"
                )
            except Exception as exc:
                logger.error("Error generating download name: %s", exc)

        return send_file(pdf_path, as_attachment=True, download_name=download_name)

    @app.route("/api/scans/<path:path>/xml")
    @require_auth
    def get_scan_xml(path):
        scan_dir = resolve_scan_path(path)
        if scan_dir is None:
            return "Invalid path", 400

        xml_path = scan_dir / "scan.xml"
        if not xml_path.exists():
            return "XML not found", 404

        download_name = "Nmap_Raw_Data.xml"
        metadata_path = scan_dir / "metadata.json"
        if metadata_path.exists():
            try:
                meta = normalize_scan_metadata_document(
                    load_json_document(metadata_path, {})
                )
                customer = meta.get("customer_name", "Unknown").split(" (")[0]
                target = meta.get("target", "scan").replace("/", "_")
                date_str = meta.get("date", datetime.now().strftime("%Y-%m-%d"))
                time_str = meta.get("time", "000000").replace(":", "")
                safe_cust = re.sub(r"[^\w\-]", "_", customer)
                safe_target = re.sub(r"[^\w\.]", "_", target)
                download_name = (
                    f"Nmap_Raw_{safe_cust}_{safe_target}_{date_str}_{time_str}.xml"
                )
            except Exception as exc:
                logger.error("Error generating download name: %s", exc)

        return send_file(xml_path, as_attachment=True, download_name=download_name)

    @app.route("/api/scans/<path:path>", methods=["DELETE"])
    @require_auth
    def delete_scan(path):
        scan_dir = resolve_scan_path(path)
        if scan_dir is None or not scan_dir.exists():
            return jsonify({"success": False, "error": "Invalid path"}), 400

        try:
            metadata_path = scan_dir / "metadata.json"
            metadata = normalize_scan_metadata_document(
                load_json_document(metadata_path, {})
            ) if metadata_path.exists() else {}
            if runtime_store is not None and hasattr(runtime_store, "delete_report_artifact"):
                runtime_store.delete_report_artifact(path)
            shutil.rmtree(scan_dir)
            remove_scan_metadata_index_entry(scans_dir, scan_dir)
            refresh_persisted_diff_summaries(
                scans_dir,
                customer_id=metadata.get("customer_id"),
                target=metadata.get("target"),
                logger=logger,
            )
            return jsonify({"success": True})
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

    @app.route("/api/scans/compare")
    @require_auth
    def compare_scans():
        base_path = str(request.args.get("base_path", "") or "").strip()
        current_path = str(request.args.get("current_path", "") or "").strip()
        if not base_path or not current_path:
            return jsonify({"success": False, "error": "Both base_path and current_path are required"}), 400

        base_dir = resolve_scan_path(base_path)
        current_dir = resolve_scan_path(current_path)
        if base_dir is None or current_dir is None:
            return jsonify({"success": False, "error": "Invalid scan path"}), 400

        base_metadata = _load_artifact_compare_payload(runtime_store, base_path)
        current_metadata = _load_artifact_compare_payload(runtime_store, current_path)

        if base_metadata is None:
            base_metadata_path = base_dir / "metadata.json"
            if not base_metadata_path.exists():
                return jsonify({"success": False, "error": "Scan metadata not found"}), 404
            base_metadata = normalize_scan_metadata_document(load_json_document(base_metadata_path, {}))
            base_metadata["path"] = base_path
        if current_metadata is None:
            current_metadata_path = current_dir / "metadata.json"
            if not current_metadata_path.exists():
                return jsonify({"success": False, "error": "Scan metadata not found"}), 404
            current_metadata = normalize_scan_metadata_document(load_json_document(current_metadata_path, {}))
            current_metadata["path"] = current_path

        if str(base_metadata.get("customer_id", "") or "") != str(current_metadata.get("customer_id", "") or ""):
            return jsonify({"success": False, "error": "Scans must belong to the same customer"}), 400
        if str(base_metadata.get("target", "") or "") != str(current_metadata.get("target", "") or ""):
            return jsonify({"success": False, "error": "Scans must target the same network"}), 400

        try:
            current_assets = current_metadata.get("asset_snapshot")
            base_assets = base_metadata.get("asset_snapshot")
            if not isinstance(current_assets, list) or not isinstance(base_assets, list):
                base_xml = base_dir / "scan.xml"
                current_xml = current_dir / "scan.xml"
                if not base_xml.exists() or not current_xml.exists():
                    return jsonify({"success": False, "error": "Scan XML not found"}), 404
                current_assets = parse_scan_xml_for_assets(current_xml)
                base_assets = parse_scan_xml_for_assets(base_xml)

            diff_summary = summarize_asset_differences(
                current_assets,
                base_assets,
            )
        except Exception as exc:
            logger.error("Error comparing scans %s and %s: %s", base_path, current_path, exc)
            return jsonify({"success": False, "error": "Failed to compare scans"}), 500

        return jsonify(
            {
                "success": True,
                "base_scan": {
                    "path": base_path,
                    "timestamp": base_metadata.get("timestamp"),
                    "customer_name": base_metadata.get("customer_name"),
                    "target": base_metadata.get("target"),
                    "status": base_metadata.get("status"),
                },
                "current_scan": {
                    "path": current_path,
                    "timestamp": current_metadata.get("timestamp"),
                    "customer_name": current_metadata.get("customer_name"),
                    "target": current_metadata.get("target"),
                    "status": current_metadata.get("status"),
                },
                "diff_summary": {
                    **diff_summary,
                    "baseline_path": base_path,
                    "baseline_timestamp": base_metadata.get("timestamp", ""),
                },
            }
        )
