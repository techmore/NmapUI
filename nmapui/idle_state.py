from datetime import datetime


class IdleStateManager:
    """Manage application idle state for auto-update workflows."""

    def __init__(
        self,
        *,
        safe_emit,
        check_for_updates,
        logger,
        update_checks_enabled: bool = True,
    ):
        self.safe_emit = safe_emit
        self.check_for_updates = check_for_updates
        self.logger = logger
        self.update_checks_enabled = update_checks_enabled
        self.active_operations = set()
        self.last_activity = datetime.now()
        self.idle_threshold = 30
        self.idle_check_interval = 5
        self.idle_state = False
        self.update_available = False
        self.auto_update_enabled = True
        self.countdown_active = False

    def start_operation(self, operation_id: str):
        self.active_operations.add(operation_id)
        self.last_activity = datetime.now()
        self._update_idle_state()
        self.logger.debug(
            "Started operation: %s, active operations: %s",
            operation_id,
            len(self.active_operations),
        )

    def end_operation(self, operation_id: str):
        self.active_operations.discard(operation_id)
        self.last_activity = datetime.now()
        self._update_idle_state()
        self.logger.debug(
            "Ended operation: %s, active operations: %s",
            operation_id,
            len(self.active_operations),
        )

    def _update_idle_state(self):
        was_idle = self.idle_state
        self.idle_state = self._is_idle()

        if was_idle != self.idle_state:
            self.logger.info(
                "Idle state changed: %s",
                "idle" if self.idle_state else "active",
            )
            self.safe_emit("idle_state_changed", {"idle": self.idle_state})

            if (
                self.update_checks_enabled
                and self.idle_state
                and self.update_available
                and self.auto_update_enabled
                and not self.countdown_active
            ):
                self._trigger_auto_update_banner()

    def _is_idle(self):
        if self.active_operations:
            return False

        time_since_activity = (datetime.now() - self.last_activity).seconds
        return time_since_activity >= self.idle_threshold

    def set_update_available(self, available: bool, update_info=None):
        if not self.update_checks_enabled:
            self.update_available = False
            self.safe_emit("hide_auto_update_banner")
            return
        self.update_available = available
        if (
            available
            and self.idle_state
            and self.auto_update_enabled
            and not self.countdown_active
        ):
            self._trigger_auto_update_banner()
        elif not available:
            self.safe_emit("hide_auto_update_banner")

    def _trigger_auto_update_banner(self):
        if not self.update_checks_enabled:
            return
        update_info = self.check_for_updates()
        self.logger.info("Auto-update check: %s", update_info)
        if isinstance(update_info, dict) and update_info.get("available"):
            self.countdown_active = True
            self.logger.info("Showing auto-update banner")
            self.safe_emit("show_auto_update_banner", update_info)
        else:
            self.logger.info("No update available or invalid update info")

    def cancel_countdown(self):
        self.countdown_active = False
        self.safe_emit("hide_auto_update_banner")

    def start_countdown(self):
        self.countdown_active = True

    def complete_auto_update(self):
        self.countdown_active = False
        self.update_available = False
