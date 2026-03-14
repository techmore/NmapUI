def get_client_state(*, sid=None, client_state_registry, current_customer, network_key, last_scan_target):
    if sid:
        return client_state_registry.get_state(sid)
    return {
        "current_customer": current_customer,
        "network_key": network_key,
        "last_scan_target": last_scan_target,
    }


def get_current_customer_state(*, sid=None, get_client_state):
    return get_client_state(sid=sid)["current_customer"]


def set_current_customer_state(*, value, sid=None, client_state_registry, set_default_customer):
    if sid:
        client_state_registry.set_current_customer(sid, value)
        return value
    set_default_customer(value)
    client_state_registry.set_default_customer(value)
    return value


def set_network_key_state(*, value, sid=None, client_state_registry, set_default_network_key):
    if sid:
        client_state_registry.set_network_key(sid, value)
        return value
    set_default_network_key(value)
    return value


def set_last_scan_target_state(*, value, sid=None, client_state_registry, set_default_last_scan_target):
    if sid:
        client_state_registry.set_last_scan_target(sid, value)
        return value
    set_default_last_scan_target(value)
    return value
