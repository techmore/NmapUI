def append_runtime_log(*, runtime_store, category, level, message, payload=None):
    if runtime_store is None:
        return None
    return runtime_store.append_log(
        category=category,
        level=level,
        message=message,
        payload=payload or {},
    )
