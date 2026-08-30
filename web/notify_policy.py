"""
Central policy for browser (and eventually Slack/email/push) notifications.

This is the ONLY place that decides which device events are important
enough to interrupt someone -- app.py just calls classify() per event and
serializes the result; a future dispatcher for another backend can import
and reuse the same policy instead of re-deciding it.
"""
from typing import Optional

# Deliberately conservative first policy: only these device types page
# someone. APs and ordinary Wi-Fi/client churn are visible on the
# dashboard but don't interrupt a background tab.
NOTIFY_DEVICE_TYPES = {"switch", "camera"}

FAILURE_EVENT_TYPES = {"DEVICE_OFFLINE", "DEVICE_MISSING"}
RECOVERY_EVENT_TYPES = {"DEVICE_ONLINE"}


def classify(event_type: str, device_type: Optional[str]) -> dict:
    """
    Pure function: (event_type, device_type) -> notification decision.
    Returns {"notify": bool, "severity": "critical"|"recovery"|"info"}.
    """
    device_type = (device_type or "").lower()

    if event_type in FAILURE_EVENT_TYPES and device_type in NOTIFY_DEVICE_TYPES:
        return {"notify": True, "severity": "critical"}

    if event_type in RECOVERY_EVENT_TYPES and device_type in NOTIFY_DEVICE_TYPES:
        return {"notify": True, "severity": "recovery"}

    return {"notify": False, "severity": "info"}


def poller_dead_severity() -> dict:
    return {"notify": True, "severity": "critical"}
