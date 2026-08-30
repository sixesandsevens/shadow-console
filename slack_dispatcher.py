"""
Slack notification backend.

Consumes the same notify_policy decisions the browser path uses --
shadow_poller.py calls send() right at the moment it detects a
DEVICE_OFFLINE/MISSING/ONLINE transition for a notify-worthy device_type,
which means dedup is inherent: the poller only ever inserts that event
row once per transition, so this only ever fires once per transition too.
No cursor/localStorage-style bookkeeping needed, unlike the browser side.

Configured entirely via env (SHADOW_SLACK_WEBHOOK_URL, optional
SHADOW_DASHBOARD_URL). If the webhook isn't set, send() is a no-op --
this backend is opt-in, not required for the poller to run.
"""
import os
from typing import Optional

import requests

WEBHOOK_URL = os.getenv("SHADOW_SLACK_WEBHOOK_URL")
DASHBOARD_URL = os.getenv("SHADOW_DASHBOARD_URL")

SEVERITY_EMOJI = {"critical": "\U0001F534", "recovery": "✅"}  # 🔴 / ✅


def enabled() -> bool:
    return bool(WEBHOOK_URL)


def send(text: str) -> None:
    """
    Fire-and-forget: never raises. A Slack outage or bad webhook must not
    take down the poller -- the dashboard/browser path is still there.
    """
    if not WEBHOOK_URL:
        return
    try:
        requests.post(WEBHOOK_URL, json={"text": text}, timeout=5)
    except Exception as e:  # noqa: BLE001 -- deliberately broad, see docstring
        print(f"[slack_dispatcher] ERROR: {type(e).__name__}: {e}")


def notify_device_event(severity: str, name: Optional[str], device_type: Optional[str], downtime: Optional[str] = None) -> None:
    label = name or "device"
    emoji = SEVERITY_EMOJI.get(severity, "")

    if severity == "critical":
        text = f"{emoji} {label} is offline ({device_type})"
    elif severity == "recovery":
        text = f"{emoji} Resolved: {label} is back online."
        if downtime:
            text += f"\nDowntime: {downtime}"
    else:
        return

    if DASHBOARD_URL:
        text += f"\n<{DASHBOARD_URL}|Shadow Console>"

    send(text)
