from datetime import datetime
import re
import shutil

from flask import jsonify, send_file
from nmapui.auth import require_auth


def register_scan_routes(app, deps):
    scans_dir = deps["scans_dir"]
    resolve_scan_path = deps["resolve_scan_path"]
    load_json_document = deps["load_json_document"]
    normalize_scan_metadata_document = deps["normalize_scan_metadata_document"]
    logger = deps["logger"]

    @app.route("/api/scans")
    @require_auth
    def list_scans():
        scans = []
        if not scans_dir.exists():
            return jsonify({"scans": []})

        for metadata_path in scans_dir.glob("**/metadata.json"):
            try:
                data = normalize_scan_metadata_document(
                    load_json_document(metadata_path, {})
                )

                if "customer_name" not in data:
                    data["customer_name"] = data.get(
                        "customer", data.get("customer_id", "Unknown")
                    )

                if data["customer_name"]:
                    data["customer_name"] = data["customer_name"].split(" (")[0]

                rel_path = metadata_path.parent.relative_to(scans_dir)
                data["path"] = str(rel_path)
                data["has_html"] = (metadata_path.parent / "scan_web.html").exists() or (
                    metadata_path.parent / "scan.html"
                ).exists()
                data["has_pdf"] = (metadata_path.parent / "scan_report.pdf").exists()
                data["has_xml"] = (metadata_path.parent / "scan.xml").exists()
                scans.append(data)
            except Exception as exc:
                logger.error("Error reading metadata at %s: %s", metadata_path, exc)

        scans.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
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
            shutil.rmtree(scan_dir)
            return jsonify({"success": True})
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 500
