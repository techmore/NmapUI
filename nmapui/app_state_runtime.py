from nmapui.state import (
    get_report_counts as get_report_counts_impl,
    load_current_assignment as load_current_assignment_impl,
    save_current_assignment as save_current_assignment_impl,
    save_customers_config as save_customers_config_impl,
)


def get_report_counts(*, scans_dir, load_json_document, normalize_scan_metadata_document):
    return get_report_counts_impl(
        scans_dir,
        normalize_scan_metadata_document,
        load_json_document,
    )


def save_customers_config(*, get_customer_fingerprinter, save_yaml_document, logger):
    save_customers_config_impl(
        get_customer_fingerprinter,
        save_yaml_document,
        logger,
    )


def save_current_assignment(
    *,
    current_assignment_file,
    get_current_customer_state,
    save_json_document,
    logger,
    sid=None,
):
    save_current_assignment_impl(
        current_assignment_file,
        get_current_customer_state,
        save_json_document,
        logger,
        sid=sid,
    )


def load_current_assignment(
    *,
    current_assignment_file,
    current_customer,
    normalize_current_assignment_document,
    load_json_document,
    get_customer_fingerprinter,
    merge_customer_metadata,
    client_state_registry,
    logger,
):
    return load_current_assignment_impl(
        current_assignment_file,
        current_customer,
        normalize_current_assignment_document,
        load_json_document,
        get_customer_fingerprinter,
        merge_customer_metadata,
        client_state_registry,
        logger,
    )
