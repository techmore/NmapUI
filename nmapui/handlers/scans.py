from datetime import datetime
import re
import shutil

from flask import jsonify, request, send_file
from nmapui.auth import require_auth
from nmapui.reporting import refresh_persisted_diff_summaries
from nmapui.runtime_history import build_compare_result, build_history_rows
from persistence import remove_scan_metadata_index_entry


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
        scans = build_history_rows(
            runtime_store=runtime_store,
            scans_dir=scans_dir,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
            logger=logger,
        )
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

        payload, error, status_code = build_compare_result(
            runtime_store=runtime_store,
            resolve_scan_path=resolve_scan_path,
            load_json_document=load_json_document,
            normalize_scan_metadata_document=normalize_scan_metadata_document,
            base_path=base_path,
            current_path=current_path,
        )
        if payload is None:
            return jsonify({"success": False, "error": error}), status_code
        return jsonify({"success": True, **payload})
