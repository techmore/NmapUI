from datetime import datetime

from nmapui.auto_monitor import (
    build_auto_monitor_rule_status,
    build_default_auto_monitor_rule,
    get_due_auto_monitor_rules,
    get_next_auto_monitor_run,
    normalize_auto_monitor_settings,
)


def test_normalize_auto_monitor_settings_applies_defaults_and_filters_invalid_rules():
    settings = normalize_auto_monitor_settings(
        {
            "defaults": {"recurrence": "weekly", "day_of_week": "sunday", "time": "01:00"},
            "rules": [
                {"customer_id": "cust-1", "customer_name": "Acme", "enabled": True},
                {"customer_id": "", "customer_name": "Missing"},
            ],
        }
    )

    assert settings["defaults"]["recurrence"] == "weekly"
    assert len(settings["rules"]) == 1
    assert settings["rules"][0]["day_of_week"] == "sunday"
    assert settings["rules"][0]["time"] == "01:00"


def test_get_next_auto_monitor_run_supports_weekly_and_biweekly():
    weekly_rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "weekly", "day_of_week": "sunday", "time": "01:00"},
        now=datetime(2026, 3, 15, 0, 0),
    )
    weekly_rule["enabled"] = True

    biweekly_rule = dict(weekly_rule)
    biweekly_rule["recurrence"] = "biweekly"
    biweekly_rule["anchor_date"] = "2026-03-15T00:00:00"

    assert get_next_auto_monitor_run(
        weekly_rule, now=datetime(2026, 3, 15, 0, 30)
    ).isoformat() == "2026-03-15T01:00:00"
    assert get_next_auto_monitor_run(
        biweekly_rule, now=datetime(2026, 3, 16, 0, 0)
    ).isoformat() == "2026-03-29T01:00:00"


def test_get_due_auto_monitor_rules_returns_enabled_rule_when_next_run_has_arrived():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=datetime(2026, 3, 14, 0, 0),
    )
    rule["enabled"] = True

    due = get_due_auto_monitor_rules(
        {"rules": [rule]},
        now=datetime(2026, 3, 14, 1, 0),
        startup_at=datetime(2026, 3, 14, 0, 0),
        startup_grace_seconds=0,
    )

    assert due == [rule]


def test_build_auto_monitor_rule_status_includes_next_run():
    rule = build_default_auto_monitor_rule(
        customer_id="cust-1",
        customer_name="Acme",
        defaults={"recurrence": "daily", "time": "01:00"},
        now=datetime(2026, 3, 14, 0, 0),
    )
    rule["enabled"] = True

    status = build_auto_monitor_rule_status(rule, now=datetime(2026, 3, 14, 0, 30))

    assert status["next_run"] == "2026-03-14T01:00:00"
    assert status["seconds_until_next_run"] == 1800
