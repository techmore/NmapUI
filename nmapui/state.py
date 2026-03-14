from datetime import datetime


from persistence import load_json_document, normalize_scan_metadata_document


def get_report_counts(scans_dir):
    """Count reports and find last scan date per customer name."""
    counts = {"total": 0, "last_scans": {}}
    if not scans_dir.exists():
        return counts

    for metadata_path in scans_dir.glob("**/metadata.json"):
        try:
            data = normalize_scan_metadata_document(
                load_json_document(metadata_path, {})
            )

            name = data.get("customer_name")
            if not name:
                customer_info = data.get("customer_info", {})
                name = customer_info.get("name")
            if not name:
                name = data.get("customer", "Unassigned")

            name = name.split(" (")[0]
            key = name if name else "Unassigned"

            counts[key] = counts.get(key, 0) + 1
            counts["total"] = counts.get("total", 0) + 1

            timestamp = data.get("timestamp")
            if timestamp:
                if (
                    key not in counts["last_scans"]
                    or timestamp > counts["last_scans"][key]
                ):
                    counts["last_scans"][key] = timestamp
                if (
                    "total" not in counts["last_scans"]
                    or timestamp > counts["last_scans"]["total"]
                ):
                    counts["last_scans"]["total"] = timestamp
        except Exception:
            continue

    return counts


def save_customers_config(get_customer_fingerprinter, save_yaml_document, logger):
    try:
        customer_fingerprinter = get_customer_fingerprinter()
        config = customer_fingerprinter.config or {}
        config_data = {
            "version": config.get("version", "1.0"),
            "description": config.get(
                "description", "Customer network fingerprinting database"
            ),
            "settings": customer_fingerprinter.settings,
            "customers": customer_fingerprinter.customers,
            "unknown_customer": customer_fingerprinter.unknown_customer,
            "indexing": config.get("indexing", {}),
        }

        save_yaml_document(customer_fingerprinter.config_path, config_data)
        logger.info(f"Customers config saved to {customer_fingerprinter.config_path}")
    except Exception as e:
        logger.error(f"Error saving customers config: {e}")


def save_current_assignment(
    current_assignment_file,
    get_current_customer_state,
    save_json_document,
    logger,
    sid=None,
):
    try:
        assignment_data = {
            "schema_version": 1,
            "timestamp": datetime.now().isoformat(),
            "customer": get_current_customer_state(sid),
        }

        save_json_document(current_assignment_file, assignment_data)
        logger.info(f"Current assignment saved to {current_assignment_file}")
    except Exception as e:
        logger.error(f"Error saving current assignment: {e}")


def merge_customer_metadata(customer_dict, saved_customer):
    if saved_customer and "metadata" in saved_customer:
        if "metadata" not in customer_dict:
            customer_dict["metadata"] = {}
        customer_dict["metadata"].update(saved_customer["metadata"])
    return customer_dict


def load_current_assignment(
    current_assignment_file,
    current_customer,
    normalize_current_assignment_document,
    load_json_document,
    get_customer_fingerprinter,
    merge_customer_metadata,
    client_state_registry,
    logger,
):
    loaded_customer = current_customer
    try:
        if current_assignment_file.exists():
            data = normalize_current_assignment_document(
                load_json_document(current_assignment_file, {})
            )
            loaded_customer = data.get("customer", loaded_customer)

            if loaded_customer.get("id"):
                saved_customer = get_customer_fingerprinter().get_customer_by_id(
                    loaded_customer["id"]
                )
                if saved_customer:
                    loaded_customer = merge_customer_metadata(
                        loaded_customer, saved_customer
                    )

            client_state_registry.set_default_customer(loaded_customer)
            logger.info(
                "Loaded previous customer assignment: %s",
                loaded_customer.get("name", "unknown"),
            )
    except Exception as e:
        logger.error(f"Error loading current assignment: {e}")

    return loaded_customer
