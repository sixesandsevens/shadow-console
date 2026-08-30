"""
Central device lifecycle (MONITORED/MAINTENANCE/IGNORED/RETIRED) policy.

Single source of truth for "should Shadow Console treat this device as
operationally significant right now" -- imported by shadow_poller.py
(gates Slack dispatch at the moment of a state transition) and
web/app.py (dashboard active-incident panel, browser notification
payload, stats aggregation) so lifecycle policy can never drift between
notification backends the way notify_policy.py already prevents browser
vs. Slack from disagreeing on *which event types* matter.

Device *state* (online/offline, from device_snapshot/device_incidents)
and device *lifecycle* (should we currently care) are deliberately
separate concerns -- this module only ever answers the second question,
and never touches historical events/incidents rows.
"""
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

LIFECYCLES = ("monitored", "maintenance", "ignored", "retired")

# Lifecycles excluded from stats aggregation, the dashboard's active
# incident panel, and both notification backends. "monitored" is the
# only lifecycle NOT in this set.
EXCLUDED_LIFECYCLES = ("maintenance", "ignored", "retired")

# Presets offered by the Devices page for temporary maintenance; "indefinite"
# stores no maintenance_until, so it never auto-reverts.
MAINTENANCE_DURATIONS = ("30m", "1h", "4h", "tomorrow", "indefinite")

_DDL = """
CREATE TABLE IF NOT EXISTS device_overrides (
    device_id TEXT PRIMARY KEY,
    lifecycle TEXT NOT NULL DEFAULT 'monitored',
    maintenance_until TEXT,
    note TEXT,
    updated_at TEXT
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Idempotent create-or-migrate. Safe to call on every connection."""
    conn.execute(_DDL)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(device_overrides);").fetchall()}
    if "maintenance_until" not in cols:
        # Table predates maintenance-expiry support (see commit history) --
        # SQLite has no "ADD COLUMN IF NOT EXISTS", hence the guard.
        conn.execute("ALTER TABLE device_overrides ADD COLUMN maintenance_until TEXT;")
    conn.commit()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _reap_expired_maintenance(conn: sqlite3.Connection, now_iso: str) -> None:
    """
    Auto-revert any device whose maintenance window has passed. Called at
    the top of every read so nothing depends on a human remembering to
    flip it back, and so poller/web/CLI paths all self-heal independently
    of each other after a restart.
    """
    conn.execute(
        """
        UPDATE device_overrides
        SET lifecycle='monitored', maintenance_until=NULL, updated_at=?
        WHERE lifecycle='maintenance' AND maintenance_until IS NOT NULL AND maintenance_until <= ?;
        """,
        (now_iso, now_iso),
    )
    conn.commit()


def get_device_lifecycle(conn: sqlite3.Connection, device_id: str) -> str:
    """No override row -> 'monitored'. Expired maintenance is reaped in place."""
    now_iso = _now_iso()
    row = conn.execute(
        "SELECT lifecycle, maintenance_until FROM device_overrides WHERE device_id=?;",
        (device_id,),
    ).fetchone()
    if row is None:
        return "monitored"
    lifecycle, maintenance_until = row[0], row[1]
    if lifecycle == "maintenance" and maintenance_until and maintenance_until <= now_iso:
        _reap_expired_maintenance(conn, now_iso)
        return "monitored"
    return lifecycle


def is_alertable(conn: sqlite3.Connection, device_id: str) -> bool:
    """
    The one function both notification backends (browser + Slack) must
    call before firing a failure OR recovery notification for a device.
    """
    return get_device_lifecycle(conn, device_id) == "monitored"


def excluded_device_ids(conn: sqlite3.Connection) -> set:
    """Device ids currently in a non-monitored lifecycle, for stats/dashboard filtering."""
    now_iso = _now_iso()
    _reap_expired_maintenance(conn, now_iso)
    placeholders = ",".join("?" * len(EXCLUDED_LIFECYCLES))
    rows = conn.execute(
        f"SELECT device_id FROM device_overrides WHERE lifecycle IN ({placeholders});",
        EXCLUDED_LIFECYCLES,
    ).fetchall()
    return {r[0] for r in rows}


def all_overrides(conn: sqlite3.Connection) -> dict:
    """device_id -> {lifecycle, maintenance_until}, after reaping expiries."""
    _reap_expired_maintenance(conn, _now_iso())
    rows = conn.execute("SELECT device_id, lifecycle, maintenance_until FROM device_overrides;").fetchall()
    return {r[0]: {"lifecycle": r[1], "maintenance_until": r[2]} for r in rows}


def resolve_maintenance_until(duration: str, now: Optional[datetime] = None) -> Optional[str]:
    """
    Maps a Devices-page duration preset to a UTC ISO timestamp. Computed
    server-side (not from a client-submitted timestamp) so a browser's
    local clock/timezone can never skew an expiry.

    'tomorrow' is next UTC midnight -- Shadow Console has no per-site
    timezone setting yet (see stats.html's UTC-day caveat), so this is
    UTC-midnight, not local-midnight, until that lands.
    """
    now = now or datetime.now(timezone.utc)
    if duration == "30m":
        until = now + timedelta(minutes=30)
    elif duration == "1h":
        until = now + timedelta(hours=1)
    elif duration == "4h":
        until = now + timedelta(hours=4)
    elif duration == "tomorrow":
        tomorrow = (now + timedelta(days=1)).date()
        until = datetime(tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=timezone.utc)
    elif duration == "indefinite":
        return None
    else:
        raise ValueError(f"invalid maintenance duration: {duration!r}")
    return until.isoformat(timespec="seconds")


def set_device_lifecycle(
    conn: sqlite3.Connection,
    device_id: str,
    lifecycle: str,
    maintenance_duration: Optional[str] = None,
    note: Optional[str] = None,
) -> None:
    if lifecycle not in LIFECYCLES:
        raise ValueError(f"invalid lifecycle: {lifecycle!r}")

    maintenance_until = None
    if lifecycle == "maintenance":
        maintenance_until = resolve_maintenance_until(maintenance_duration or "indefinite")

    conn.execute(
        """
        INSERT INTO device_overrides (device_id, lifecycle, maintenance_until, note, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            lifecycle=excluded.lifecycle,
            maintenance_until=excluded.maintenance_until,
            note=COALESCE(excluded.note, device_overrides.note),
            updated_at=excluded.updated_at;
        """,
        (device_id, lifecycle, maintenance_until, note, _now_iso()),
    )
    conn.commit()
