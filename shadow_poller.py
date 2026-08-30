#!/usr/bin/env python3
import os
import time
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

import notify_policy
import slack_dispatcher

LEFT_CLIENT_GRACE_POLLS = 3
DEVICE_MISSING_GRACE_POLLS = 2
LEFT_CLIENT_STALE_SEC = 3600
ROAM_FLAP_WINDOW_SEC = 10 * 60
ROAM_FLAP_THRESHOLD = 5

# A burst of LEFT_CLIENT events close together is a different story than
# one client leaving -- it's a sign something upstream (an AP, a switch, a
# whole building) took a bunch of clients down with it.
CHURN_SPIKE_WINDOW_SEC = int(os.getenv("SHADOW_CHURN_WINDOW_SEC", str(3 * 60)))
CHURN_SPIKE_THRESHOLD = int(os.getenv("SHADOW_CHURN_THRESHOLD", "10"))

# A churn spike is "correlated" with an infra outage when most of the
# departing clients shared one uplink and that device currently has an
# open incident -- not just a coincidence of timing.
CHURN_CORRELATION_MIN_COUNT = int(os.getenv("SHADOW_CHURN_CORRELATION_MIN_COUNT", "3"))
CHURN_CORRELATION_MIN_SHARE = float(os.getenv("SHADOW_CHURN_CORRELATION_SHARE", "0.5"))

# device_snapshot/client_snapshot are written on every poll regardless of
# change and are only ever read as "latest" or "last 200 rows per client"
# (~3h at a 60s poll interval) -- so they only need a short rolling window.
# events is the real change-log (roam/connect/disconnect) and is kept longer.
SNAPSHOT_RETENTION_HOURS = int(os.getenv("SHADOW_SNAPSHOT_RETENTION_HOURS", "24"))
EVENTS_RETENTION_DAYS = int(os.getenv("SHADOW_EVENTS_RETENTION_DAYS", "90"))
PRUNE_INTERVAL_SEC = int(os.getenv("SHADOW_PRUNE_INTERVAL_SEC", "3600"))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def classify_device_type(features: Optional[List[str]]) -> str:
    """
    Maps a device's UniFi "features" array to a coarse type used by the
    browser-notification policy. Based on inspecting live data: switches
    report features=["switching"], APs report features=["accessPoint"].
    Note a gateway (e.g. UDM Pro Max) also reports "switching" -- the
    Integration API gives no separate signal to distinguish it from a
    plain switch, so it's bucketed as "switch" too (arguably correct:
    a gateway going down is just as notify-worthy).

    "camera" is speculative: UniFi Protect cameras are a separate API this
    poller doesn't currently query, so no device in this dataset has ever
    reported a camera-like feature. This check is a no-op today, kept only
    so classification doesn't need touching if that data ever shows up.
    """
    feats = {f.lower() for f in (features or [])}
    if "accesspoint" in feats:
        return "ap"
    if "camera" in feats:
        return "camera"
    if "switching" in feats:
        return "switch"
    return "other"


def get_env(name: str, default: Optional[str] = None) -> str:
    val = os.getenv(name, default)
    if val is None or val == "":
        raise SystemExit(f"Missing required env var: {name}")
    return val


def fetch_all_pages(
    session: requests.Session,
    base_url: str,
    api_key: str,
    path: str,
    page_limit: int = 200,
) -> List[Dict[str, Any]]:
    """
    UniFi integration API uses offset/limit pagination.
    We'll pull until offset >= totalCount.
    """
    headers = {
        "X-API-KEY": api_key,
        "Accept": "application/json",
    }

    offset = 0
    out: List[Dict[str, Any]] = []

    while True:
        url = f"{base_url}{path}?offset={offset}&limit={page_limit}"
        r = session.get(url, headers=headers, timeout=20, verify=False)
        r.raise_for_status()
        payload = r.json()

        data = payload.get("data", [])
        out.extend(data)

        total = payload.get("totalCount", len(out))
        count = payload.get("count", len(data))

        offset += count
        if count == 0 or offset >= total:
            break

    return out


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    # Lets `PRAGMA incremental_vacuum` reclaim freed pages during pruning
    # without a full-database VACUUM/exclusive lock. Only takes effect on a
    # fresh db or after the one-time VACUUM that converts an existing db.
    conn.execute("PRAGMA auto_vacuum=INCREMENTAL;")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS device_snapshot (
            ts TEXT NOT NULL,
            site_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            name TEXT,
            model TEXT,
            ip TEXT,
            state TEXT,
            mac TEXT,
            device_type TEXT,
            raw_json TEXT NOT NULL,
            PRIMARY KEY (ts, device_id)
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS client_snapshot (
            ts TEXT NOT NULL,
            site_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            type TEXT,
            name TEXT,
            ip TEXT,
            mac TEXT,
            connected_at TEXT,
            uplink_device_id TEXT,
            uplink_device_name TEXT,
            access_type TEXT,
            raw_json TEXT NOT NULL,
            PRIMARY KEY (ts, client_id)
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            ts TEXT NOT NULL,
            site_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            client_id TEXT,
            mac TEXT,
            ip_old TEXT,
            ip_new TEXT,
            uplink_old TEXT,
            uplink_new TEXT,
            device_type TEXT,
            details TEXT
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS client_state (
            client_id TEXT PRIMARY KEY,
            last_seen_ts TEXT,
            miss_count INTEGER NOT NULL DEFAULT 0,
            last_type TEXT,
            last_name TEXT,
            last_ip TEXT,
            last_mac TEXT,
            last_uplink TEXT,
            pending_ip TEXT
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS device_state (
            device_id TEXT PRIMARY KEY,
            last_seen_ts TEXT,
            miss_count INTEGER NOT NULL DEFAULT 0,
            last_name TEXT,
            last_model TEXT,
            last_ip TEXT,
            last_mac TEXT,
            last_state TEXT,
            last_device_type TEXT
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS device_incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            mac TEXT,
            name TEXT,
            model TEXT,
            device_type TEXT,
            opened_ts TEXT NOT NULL,
            opened_reason TEXT NOT NULL,
            closed_ts TEXT,
            closed_reason TEXT
        );
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_device_incidents_active
        ON device_incidents(device_id)
        WHERE closed_ts IS NULL;
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS wifi_roam_state (
            client_id TEXT PRIMARY KEY,
            window_start_ts TEXT,
            roam_count INTEGER NOT NULL DEFAULT 0,
            last_uplink TEXT,
            last_event_ts TEXT
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS churn_spike_state (
            site_id TEXT PRIMARY KEY,
            active INTEGER NOT NULL DEFAULT 0,
            started_ts TEXT,
            last_count INTEGER
        );
        """
    )

    # Only client_snapshot-derived numbers need a daily rollup -- that
    # table is pruned after SNAPSHOT_RETENTION_HOURS (24h), unlike events
    # (90 days) or device_incidents (never pruned), so peak/avg client
    # counts and poller uptime would otherwise be unrecoverable after a
    # day passes. See compute_daily_rollup().
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_network_stats (
            date TEXT PRIMARY KEY,
            peak_clients INTEGER,
            avg_clients REAL,
            poller_downtime_seconds INTEGER
        );
        """
    )

    # CREATE TABLE IF NOT EXISTS above only helps a fresh database -- an
    # existing one (like the live deployment) already has these tables
    # without device_type, so add it explicitly. SQLite has no "ADD COLUMN
    # IF NOT EXISTS", hence the guard.
    for table, column, coltype in (
        ("device_snapshot", "device_type", "TEXT"),
        ("device_state", "last_device_type", "TEXT"),
        ("device_incidents", "device_type", "TEXT"),
        ("events", "device_type", "TEXT"),
    ):
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype};")
        except sqlite3.OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise

    conn.commit()
    return conn


def get_last_two_timestamps(conn: sqlite3.Connection) -> Tuple[Optional[str], Optional[str]]:
    rows = conn.execute(
        "SELECT DISTINCT ts FROM client_snapshot ORDER BY ts DESC LIMIT 2;"
    ).fetchall()
    if not rows:
        return None, None
    if len(rows) == 1:
        return rows[0][0], None
    return rows[0][0], rows[1][0]


def get_last_two_device_timestamps(conn: sqlite3.Connection) -> Tuple[Optional[str], Optional[str]]:
    rows = conn.execute(
        "SELECT DISTINCT ts FROM device_snapshot ORDER BY ts DESC LIMIT 2;"
    ).fetchall()
    if not rows:
        return None, None
    if len(rows) == 1:
        return rows[0][0], None
    return rows[0][0], rows[1][0]


def get_active_incident(conn: sqlite3.Connection, device_id: str) -> Optional[Tuple[int, str, str]]:
    return conn.execute(
        """
        SELECT incident_id, opened_ts, opened_reason
        FROM device_incidents
        WHERE device_id=? AND closed_ts IS NULL
        ORDER BY incident_id DESC LIMIT 1;
        """,
        (device_id,),
    ).fetchone()


def open_device_incident(
    conn: sqlite3.Connection,
    ts: str,
    device_id: str,
    mac: Optional[str],
    name: Optional[str],
    model: Optional[str],
    device_type: Optional[str],
    reason: str,
) -> None:
    # A device can only have one open incident at a time -- e.g. it can go
    # OFFLINE (still adopted) and later vanish from the API entirely without
    # ever recovering; that's still the same outage.
    if get_active_incident(conn, device_id) is not None:
        return
    conn.execute(
        """
        INSERT INTO device_incidents
        (device_id, mac, name, model, device_type, opened_ts, opened_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """,
        (device_id, mac, name, model, device_type, ts, reason),
    )


def close_device_incident(conn: sqlite3.Connection, ts: str, device_id: str, reason: str) -> None:
    conn.execute(
        """
        UPDATE device_incidents
        SET closed_ts=?, closed_reason=?
        WHERE device_id=? AND closed_ts IS NULL;
        """,
        (ts, reason, device_id),
    )


def format_duration(total_seconds: int) -> str:
    m, s = divmod(max(0, total_seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def prune_old_data(conn: sqlite3.Connection) -> None:
    snapshot_cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=SNAPSHOT_RETENTION_HOURS)
    ).replace(microsecond=0).isoformat()
    events_cutoff = (
        datetime.now(timezone.utc) - timedelta(days=EVENTS_RETENTION_DAYS)
    ).replace(microsecond=0).isoformat()

    conn.execute("BEGIN;")
    conn.execute("DELETE FROM device_snapshot WHERE ts < ?;", (snapshot_cutoff,))
    conn.execute("DELETE FROM client_snapshot WHERE ts < ?;", (snapshot_cutoff,))
    conn.execute("DELETE FROM events WHERE ts < ?;", (events_cutoff,))
    conn.commit()

    # Reclaims freed pages incrementally (cheap, no exclusive lock) instead
    # of letting the file grow forever between full VACUUMs.
    conn.execute("PRAGMA incremental_vacuum;")


def compute_daily_rollup(conn: sqlite3.Connection, poll_interval: int) -> None:
    """
    Materializes yesterday's (UTC) client_snapshot data into
    daily_network_stats before it ages out of SNAPSHOT_RETENTION_HOURS.
    Idempotent -- skips if that date already has a row. Must run before
    prune_old_data() in the same cycle, or the data it needs may already
    be gone.
    """
    yesterday = datetime.now(timezone.utc).date() - timedelta(days=1)
    date_str = yesterday.isoformat()

    existing = conn.execute(
        "SELECT 1 FROM daily_network_stats WHERE date=?;", (date_str,)
    ).fetchone()
    if existing is not None:
        return

    day_start = f"{date_str}T00:00:00"
    day_end = f"{date_str}T23:59:59"

    rows = conn.execute(
        "SELECT ts, COUNT(*) AS c FROM client_snapshot WHERE ts >= ? AND ts <= ? GROUP BY ts ORDER BY ts;",
        (day_start, day_end),
    ).fetchall()

    if not rows:
        # No data for that day at all (poller was down the whole day, or
        # this is a fresh deployment) -- nothing to roll up yet.
        return

    counts = [r[1] for r in rows]
    peak_clients = max(counts)
    avg_clients = sum(counts) / len(counts)

    # Poller downtime: sum of gaps between consecutive poll timestamps
    # that exceed 2x the expected interval. Approximate -- there's no
    # dedicated heartbeat log, this just treats unusually large gaps
    # between successful polls as downtime.
    poller_downtime_seconds = 0
    timestamps = [datetime.fromisoformat(r[0]) for r in rows]
    for prev_ts, cur_ts in zip(timestamps, timestamps[1:]):
        gap = (cur_ts - prev_ts).total_seconds()
        if gap > poll_interval * 2:
            poller_downtime_seconds += int(gap - poll_interval)

    conn.execute(
        """
        INSERT INTO daily_network_stats (date, peak_clients, avg_clients, poller_downtime_seconds)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(date) DO NOTHING;
        """,
        (date_str, peak_clients, avg_clients, poller_downtime_seconds),
    )
    conn.commit()


def main() -> None:
    # Read config
    base_url = get_env("SHADOW_UDM_URL")          # e.g. https://192.168.1.1
    api_key  = get_env("SHADOW_API_KEY")          # your UniFi integration API key
    site_id  = get_env("SHADOW_SITE_ID")          # the UUID you pasted
    db_path  = os.getenv("SHADOW_DB", "./shadowconsole.db")
    interval = int(os.getenv("SHADOW_INTERVAL_SEC", "60"))

    # Requests session
    s = requests.Session()
    # Suppress urllib3 warning about verify=False (we're on a trusted LAN)
    requests.packages.urllib3.disable_warnings()  # type: ignore

    conn = init_db(db_path)

    compute_daily_rollup(conn, interval)
    prune_old_data(conn)
    last_prune = time.monotonic()

    while True:
        ts = utc_now_iso()
        try:
            # 1) Devices
            devices = fetch_all_pages(
                s, base_url, api_key, f"/proxy/network/integration/v1/sites/{site_id}/devices"
            )
            device_map = {
                d["id"]: {
                    "name": d.get("name"),
                    "model": d.get("model"),
                    "ip": d.get("ipAddress"),
                    "state": d.get("state"),
                    "mac": d.get("macAddress"),
                    "device_type": classify_device_type(d.get("features")),
                }
                for d in devices
                if "id" in d
            }

            # store device snapshot
            conn.execute("BEGIN;")
            for d in devices:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO device_snapshot
                    (ts, site_id, device_id, name, model, ip, state, mac, device_type, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        ts,
                        site_id,
                        d.get("id"),
                        d.get("name"),
                        d.get("model"),
                        d.get("ipAddress"),
                        d.get("state"),
                        d.get("macAddress"),
                        classify_device_type(d.get("features")),
                        json.dumps(d, separators=(",", ":"), ensure_ascii=False),
                    ),
                )
            conn.commit()

            # 2) Clients
            clients = fetch_all_pages(
                s, base_url, api_key, f"/proxy/network/integration/v1/sites/{site_id}/clients"
            )

            # store client snapshot
            conn.execute("BEGIN;")
            for c in clients:
                uplink_id = c.get("uplinkDeviceId")
                uplink_name = device_map.get(uplink_id, {}).get("name") if uplink_id else None
                access_type = None
                access = c.get("access")
                if isinstance(access, dict):
                    access_type = access.get("type")

                conn.execute(
                    """
                    INSERT OR REPLACE INTO client_snapshot
                    (ts, site_id, client_id, type, name, ip, mac, connected_at,
                     uplink_device_id, uplink_device_name, access_type, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        ts,
                        site_id,
                        c.get("id"),
                        c.get("type"),
                        c.get("name"),
                        c.get("ipAddress"),
                        c.get("macAddress"),
                        c.get("connectedAt"),
                        uplink_id,
                        uplink_name,
                        access_type,
                        json.dumps(c, separators=(",", ":"), ensure_ascii=False),
                    ),
                )
            conn.commit()

            # 2a) Device offline/online detection
            newest_dts, prev_dts = get_last_two_device_timestamps(conn)

            if prev_dts is not None:
                cur_dev_rows = conn.execute(
                    "SELECT device_id, name, model, ip, mac, state, device_type FROM device_snapshot WHERE ts=?;",
                    (newest_dts,),
                ).fetchall()

                prev_dev_rows = conn.execute(
                    "SELECT device_id, name, model, ip, mac, state, device_type FROM device_snapshot WHERE ts=?;",
                    (prev_dts,),
                ).fetchall()

                cur_devs = {
                    r[0]: {"name": r[1], "model": r[2], "ip": r[3], "mac": r[4], "state": r[5], "device_type": r[6]}
                    for r in cur_dev_rows
                }
                prev_devs = {
                    r[0]: {"name": r[1], "model": r[2], "ip": r[3], "mac": r[4], "state": r[5], "device_type": r[6]}
                    for r in prev_dev_rows
                }

                cur_ids = set(cur_devs.keys())

                # Load existing device_state
                ds_rows = conn.execute(
                    "SELECT device_id, miss_count, last_name, last_model, last_ip, last_mac, last_state, last_device_type FROM device_state;"
                ).fetchall()
                ds = {r[0]: r[1:] for r in ds_rows}

                conn.execute("BEGIN;")

                # Tracks devices we've already emitted a DEVICE_ONLINE for
                # this poll, so a device recovering from DEVICE_MISSING
                # doesn't get a second recovery event fired for it below.
                online_emitted = set()

                # Update state for devices we see now
                for did, d in cur_devs.items():
                    conn.execute(
                        """
                        INSERT INTO device_state
                        (device_id, last_seen_ts, miss_count, last_name, last_model, last_ip, last_mac, last_state, last_device_type)
                        VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(device_id) DO UPDATE SET
                            last_seen_ts=excluded.last_seen_ts,
                            miss_count=0,
                            last_name=excluded.last_name,
                            last_model=excluded.last_model,
                            last_ip=excluded.last_ip,
                            last_mac=excluded.last_mac,
                            last_state=excluded.last_state,
                            last_device_type=excluded.last_device_type;
                        """,
                        (did, newest_dts, d["name"], d["model"], d["ip"], d["mac"], d["state"], d["device_type"]),
                    )

                    # Detect state change ONLINE <-> OFFLINE
                    prev_state = (prev_devs.get(did, {}).get("state") or "").upper()
                    cur_state = (d.get("state") or "").upper()

                    if prev_state and cur_state and prev_state != cur_state:
                        if cur_state == "OFFLINE":
                            conn.execute(
                                """INSERT INTO events
                                   (ts, site_id, event_type, client_id, mac, device_type, details)
                                   VALUES (?, ?, 'DEVICE_OFFLINE', NULL, ?, ?, ?);""",
                                (
                                    newest_dts,
                                    site_id,
                                    d["mac"],
                                    d["device_type"],
                                    f'name="{d["name"]}" model="{d["model"]}" ip="{d["ip"]}"',
                                ),
                            )
                            decision = notify_policy.classify("DEVICE_OFFLINE", d["device_type"])
                            if decision["notify"]:
                                slack_dispatcher.notify_device_event("critical", d["name"], d["device_type"])
                        elif cur_state == "ONLINE":
                            # Grab the still-open incident's opened_ts for
                            # downtime *before* it gets closed further down
                            # this same loop iteration (in the incident
                            # open/close block below).
                            prior_incident = get_active_incident(conn, did)
                            conn.execute(
                                """INSERT INTO events
                                   (ts, site_id, event_type, client_id, mac, device_type, details)
                                   VALUES (?, ?, 'DEVICE_ONLINE', NULL, ?, ?, ?);""",
                                (
                                    newest_dts,
                                    site_id,
                                    d["mac"],
                                    d["device_type"],
                                    f'name="{d["name"]}" model="{d["model"]}" ip="{d["ip"]}"',
                                ),
                            )
                            online_emitted.add(did)
                            decision = notify_policy.classify("DEVICE_ONLINE", d["device_type"])
                            if decision["notify"]:
                                downtime = None
                                if prior_incident is not None:
                                    try:
                                        opened_dt = datetime.fromisoformat(prior_incident[1])
                                        now_dt = datetime.fromisoformat(newest_dts)
                                        downtime = format_duration(int((now_dt - opened_dt).total_seconds()))
                                    except (ValueError, TypeError):
                                        pass
                                slack_dispatcher.notify_device_event(
                                    "recovery", d["name"], d["device_type"], downtime
                                )

                    # Incident open/close tracks *current* state, not just
                    # transitions -- so a device that was already OFFLINE
                    # before this feature (or the poller) started still gets
                    # an incident, instead of staying invisible until it
                    # next flaps. open_/close_device_incident are both
                    # idempotent no-ops when there's nothing to do.
                    if cur_state == "OFFLINE":
                        open_device_incident(
                            conn, newest_dts, did, d["mac"], d["name"], d["model"], d["device_type"], "DEVICE_OFFLINE"
                        )
                    elif cur_state == "ONLINE":
                        # A device that vanished from the API entirely
                        # (DEVICE_MISSING) has no "state" field to compare
                        # against, so the transition check above never sees
                        # it -- reappearing here, still ONLINE, is the only
                        # signal we get that it recovered.
                        active = get_active_incident(conn, did)
                        if active is not None and active[2] == "DEVICE_MISSING" and did not in online_emitted:
                            conn.execute(
                                """INSERT INTO events
                                   (ts, site_id, event_type, client_id, mac, device_type, details)
                                   VALUES (?, ?, 'DEVICE_ONLINE', NULL, ?, ?, ?);""",
                                (
                                    newest_dts,
                                    site_id,
                                    d["mac"],
                                    d["device_type"],
                                    f'name="{d["name"]}" model="{d["model"]}" ip="{d["ip"]}" recovered_from="missing"',
                                ),
                            )
                            online_emitted.add(did)
                            decision = notify_policy.classify("DEVICE_ONLINE", d["device_type"])
                            if decision["notify"]:
                                downtime = None
                                try:
                                    opened_dt = datetime.fromisoformat(active[1])
                                    now_dt = datetime.fromisoformat(newest_dts)
                                    downtime = format_duration(int((now_dt - opened_dt).total_seconds()))
                                except (ValueError, TypeError):
                                    pass
                                slack_dispatcher.notify_device_event(
                                    "recovery", d["name"], d["device_type"], downtime
                                )
                        close_device_incident(conn, newest_dts, did, "DEVICE_ONLINE")

                # Handle devices missing from current snapshot (grace)
                missing = set(ds.keys()) - cur_ids
                for did in missing:
                    miss_count, last_name, last_model, last_ip, last_mac, last_state, last_device_type = ds[did]
                    new_miss = int(miss_count) + 1

                    conn.execute("UPDATE device_state SET miss_count=? WHERE device_id=?;", (new_miss, did))

                    if new_miss == DEVICE_MISSING_GRACE_POLLS:
                        # Treat as offline/missing (even if last_state wasn't OFFLINE)
                        conn.execute(
                            """INSERT INTO events
                               (ts, site_id, event_type, client_id, mac, device_type, details)
                               VALUES (?, ?, 'DEVICE_MISSING', NULL, ?, ?, ?);""",
                            (
                                newest_dts,
                                site_id,
                                last_mac,
                                last_device_type,
                                f'name="{last_name}" model="{last_model}" ip="{last_ip}" last_state="{last_state}"',
                            ),
                        )
                        decision = notify_policy.classify("DEVICE_MISSING", last_device_type)
                        if decision["notify"]:
                            slack_dispatcher.notify_device_event("critical", last_name, last_device_type)

                    if new_miss >= DEVICE_MISSING_GRACE_POLLS:
                        # >= (not ==) so a device that was already past the
                        # grace threshold before this feature (or the
                        # poller) started still gets an incident opened --
                        # open_device_incident is a no-op if one's already
                        # active, so this doesn't re-fire on every poll.
                        open_device_incident(
                            conn, newest_dts, did, last_mac, last_name, last_model, last_device_type, "DEVICE_MISSING"
                        )

                conn.commit()

            # 3) Diff against previous snapshot
            newest_ts, prev_ts = get_last_two_timestamps(conn)
            if prev_ts is not None and newest_ts == ts:
                # Load latest + previous into dicts keyed by client_id
                cur_rows = conn.execute(
                    "SELECT client_id, mac, ip, name, uplink_device_id, type FROM client_snapshot WHERE ts=?;",
                    (newest_ts,),
                ).fetchall()
                prev_rows = conn.execute(
                    "SELECT client_id, mac, ip, name, uplink_device_id, type FROM client_snapshot WHERE ts=?;",
                    (prev_ts,),
                ).fetchall()

                cur = {
                    r[0]: {"mac": r[1], "ip": r[2], "name": r[3], "uplink": r[4], "type": r[5]}
                    for r in cur_rows
                }
                prev = {
                    r[0]: {"mac": r[1], "ip": r[2], "name": r[3], "uplink": r[4], "type": r[5]}
                    for r in prev_rows
                }

                cur_ids = set(cur.keys())
                prev_ids = set(prev.keys())

                new_ids = cur_ids - prev_ids
                common = cur_ids & prev_ids

                def devname(dev_id: Optional[str]) -> Optional[str]:
                    if not dev_id:
                        return None
                    return device_map.get(dev_id, {}).get("name") or dev_id

                def devmodel(dev_id: Optional[str]) -> Optional[str]:
                    if not dev_id:
                        return None
                    return device_map.get(dev_id, {}).get("model")

                def devlabel(dev_id: Optional[str]) -> str:
                    """Human-friendly device label: Name (Model) [id]"""
                    if not dev_id:
                        return "None"
                    name = devname(dev_id) or "Unknown"
                    model = devmodel(dev_id)
                    if model:
                        return f"{name} ({model}) [{dev_id}]"
                    return f"{name} [{dev_id}]"

                def is_ap(dev_id: Optional[str]) -> bool:
                    if not dev_id:
                        return False
                    model = (device_map.get(dev_id, {}).get("model") or "").upper()
                    return model.startswith("UAP") or model.startswith("U6")

                # Write events
                conn.execute("BEGIN;")

                for cid in new_ids:
                    c = cur[cid]
                    conn.execute(
                        """INSERT INTO events
                           (ts, site_id, event_type, client_id, mac, ip_new, uplink_new, details)
                           VALUES (?, ?, 'NEW_CLIENT', ?, ?, ?, ?, ?);""",
                        (
                            ts,
                            site_id,
                            cid,
                            c["mac"],
                            c["ip"],
                            devname(c["uplink"]),
                            f'name="{c["name"]}"',
                        ),
                    )

                left_logged = 0

                # Update client_state and apply LEFT_CLIENT grace period
                state_rows = conn.execute(
                    "SELECT client_id, last_seen_ts, miss_count, last_type, last_name, last_ip, last_mac, last_uplink "
                    "FROM client_state;"
                ).fetchall()
                state = {r[0]: r[1:] for r in state_rows}

                for cid, c in cur.items():
                    conn.execute(
                        """
                        INSERT INTO client_state
                        (client_id, last_seen_ts, miss_count, last_type, last_name, last_ip, last_mac, last_uplink)
                        VALUES (?, ?, 0, ?, ?, ?, ?, ?)
                        ON CONFLICT(client_id) DO UPDATE SET
                            last_seen_ts=excluded.last_seen_ts,
                            miss_count=0,
                            last_type=excluded.last_type,
                            last_name=excluded.last_name,
                            last_ip=excluded.last_ip,
                            last_mac=excluded.last_mac,
                            last_uplink=excluded.last_uplink;
                        """,
                        (cid, ts, c["type"], c["name"], c["ip"], c["mac"], c["uplink"]),
                    )

                missing_ids = set(state.keys()) - cur_ids
                for cid in missing_ids:
                    last_seen_ts, miss_count, last_type, last_name, last_ip, last_mac, last_uplink = state[cid]
                    if last_seen_ts:
                        try:
                            last_seen_dt = datetime.fromisoformat(last_seen_ts)
                        except ValueError:
                            last_seen_dt = None
                        if last_seen_dt is not None:
                            age_sec = (datetime.now(timezone.utc) - last_seen_dt).total_seconds()
                            if age_sec > LEFT_CLIENT_STALE_SEC:
                                continue
                    new_miss = int(miss_count) + 1
                    conn.execute(
                        "UPDATE client_state SET miss_count=? WHERE client_id=?;",
                        (new_miss, cid),
                    )
                    if new_miss == LEFT_CLIENT_GRACE_POLLS:
                        conn.execute(
                            """INSERT INTO events
                               (ts, site_id, event_type, client_id, mac, ip_old, uplink_old, details)
                               VALUES (?, ?, 'LEFT_CLIENT', ?, ?, ?, ?, ?);""",
                            (
                                ts,
                                site_id,
                                cid,
                                last_mac,
                                last_ip,
                                devname(last_uplink),
                                f'name="{last_name}"',
                            ),
                        )
                        left_logged += 1

                # Client churn spike: count LEFT_CLIENT events across a
                # rolling window (not just this poll -- 18 clients leaving
                # over 3 polls is the same story as 18 leaving in 1) and
                # fire CLIENT_CHURN_SPIKE once when that count *crosses*
                # the threshold, not on every poll it stays elevated.
                churn_cutoff = (
                    datetime.fromisoformat(ts) - timedelta(seconds=CHURN_SPIKE_WINDOW_SEC)
                ).isoformat()
                churn_count = conn.execute(
                    "SELECT COUNT(*) FROM events WHERE site_id=? AND event_type='LEFT_CLIENT' AND ts >= ?;",
                    (site_id, churn_cutoff),
                ).fetchone()[0]

                churn_row = conn.execute(
                    "SELECT active FROM churn_spike_state WHERE site_id=?;", (site_id,)
                ).fetchone()
                churn_was_active = bool(churn_row and churn_row[0])

                if churn_count >= CHURN_SPIKE_THRESHOLD:
                    if not churn_was_active:
                        conn.execute(
                            """INSERT INTO events
                               (ts, site_id, event_type, details)
                               VALUES (?, ?, 'CLIENT_CHURN_SPIKE', ?);""",
                            (ts, site_id, f"count={churn_count} window={CHURN_SPIKE_WINDOW_SEC}s"),
                        )

                        # Correlate: did most of these clients share the same
                        # uplink, and is that device currently down? That's
                        # the difference between "a bunch of clients left"
                        # and "the AP/switch serving them just went out."
                        top_uplink = conn.execute(
                            """
                            SELECT cs.last_uplink, COUNT(*) AS n
                            FROM events e
                            JOIN client_state cs ON cs.client_id = e.client_id
                            WHERE e.site_id=? AND e.event_type='LEFT_CLIENT' AND e.ts >= ?
                                  AND cs.last_uplink IS NOT NULL
                            GROUP BY cs.last_uplink
                            ORDER BY n DESC
                            LIMIT 1;
                            """,
                            (site_id, churn_cutoff),
                        ).fetchone()

                        if top_uplink is not None:
                            uplink_id, affected = top_uplink
                            active_inc = get_active_incident(conn, uplink_id)
                            if (
                                active_inc is not None
                                and affected >= CHURN_CORRELATION_MIN_COUNT
                                and affected >= churn_count * CHURN_CORRELATION_MIN_SHARE
                            ):
                                kind = "AP" if is_ap(uplink_id) else "device"
                                conn.execute(
                                    """INSERT INTO events
                                       (ts, site_id, event_type, mac, details)
                                       VALUES (?, ?, 'INFRA_OUTAGE_LIKELY', ?, ?);""",
                                    (
                                        ts,
                                        site_id,
                                        device_map.get(uplink_id, {}).get("mac"),
                                        (
                                            f'{kind}="{devlabel(uplink_id)}" affected_clients={affected} '
                                            f'of_churn={churn_count} incident_reason="{active_inc[2]}" '
                                            f'incident_opened="{active_inc[1]}"'
                                        ),
                                    ),
                                )
                    conn.execute(
                        """
                        INSERT INTO churn_spike_state (site_id, active, started_ts, last_count)
                        VALUES (?, 1, ?, ?)
                        ON CONFLICT(site_id) DO UPDATE SET
                            active=1,
                            started_ts=CASE WHEN churn_spike_state.active=1
                                             THEN churn_spike_state.started_ts ELSE excluded.started_ts END,
                            last_count=excluded.last_count;
                        """,
                        (site_id, ts, churn_count),
                    )
                elif churn_was_active:
                    conn.execute(
                        "UPDATE churn_spike_state SET active=0, started_ts=NULL, last_count=? WHERE site_id=?;",
                        (churn_count, site_id),
                    )

                for cid in common:
                    c = cur[cid]
                    p = prev[cid]

                    if (p["ip"] or "") != (c["ip"] or ""):
                        conn.execute(
                            """INSERT INTO events
                               (ts, site_id, event_type, client_id, mac, ip_old, ip_new, details)
                               VALUES (?, ?, 'IP_CHANGED', ?, ?, ?, ?, ?);""",
                            (ts, site_id, cid, c["mac"], p["ip"], c["ip"], f'name="{c["name"]}"'),
                        )

                    if (p["uplink"] or "") != (c["uplink"] or ""):
                        client_type = (c["type"] or "").upper()

                        # Actionable: physical changes (wired only)
                        if client_type == "WIRED":
                            conn.execute(
                                """INSERT INTO events
                                   (ts, site_id, event_type, client_id, mac, uplink_old, uplink_new, details)
                                   VALUES (?, ?, 'MOVED_UPLINK', ?, ?, ?, ?, ?);""",
                                (
                                    ts,
                                    site_id,
                                    cid,
                                    c["mac"],
                                    devname(p["uplink"]),
                                    devname(c["uplink"]),
                                    f'name="{c["name"]}"',
                                ),
                            )
                        else:
                            # Wireless: only log if it looks abnormal (flapping)
                            # Only consider AP-to-AP roams
                            if is_ap(p["uplink"]) and is_ap(c["uplink"]):
                                # Track roam frequency within a time window
                                row = conn.execute(
                                    "SELECT window_start_ts, roam_count, last_uplink, last_event_ts "
                                    "FROM wifi_roam_state WHERE client_id=?;",
                                    (cid,),
                                ).fetchone()

                                def parse_ts(s: Optional[str]) -> Optional[datetime]:
                                    if not s:
                                        return None
                                    return datetime.fromisoformat(s.replace("Z", "+00:00"))

                                now_dt = datetime.fromisoformat(ts)
                                if row is None:
                                    window_start = ts
                                    roam_count = 1
                                    last_event_ts = None
                                else:
                                    window_start, roam_count, last_uplink, last_event_ts = row
                                    ws_dt = parse_ts(window_start) or now_dt
                                    age = (now_dt - ws_dt).total_seconds()

                                    # If window expired, reset
                                    if age > ROAM_FLAP_WINDOW_SEC:
                                        window_start = ts
                                        roam_count = 1
                                    else:
                                        roam_count = int(roam_count) + 1

                                # Update roam state
                                conn.execute(
                                    """
                                    INSERT INTO wifi_roam_state (client_id, window_start_ts, roam_count, last_uplink, last_event_ts)
                                    VALUES (?, ?, ?, ?, ?)
                                    ON CONFLICT(client_id) DO UPDATE SET
                                        window_start_ts=excluded.window_start_ts,
                                        roam_count=excluded.roam_count,
                                        last_uplink=excluded.last_uplink,
                                        last_event_ts=wifi_roam_state.last_event_ts;
                                    """,
                                    (cid, window_start, roam_count, c["uplink"], row[3] if row else None),
                                )

                                # Log only once when threshold is *reached*
                                if roam_count == ROAM_FLAP_THRESHOLD:
                                    old_id = p["uplink"]
                                    new_id = c["uplink"]
                                    conn.execute(
                                        """INSERT INTO events
                                           (ts, site_id, event_type, client_id, mac, uplink_old, uplink_new, details)
                                           VALUES (?, ?, 'ROAMING_FLAP', ?, ?, ?, ?, ?);""",
                                        (
                                            ts,
                                            site_id,
                                            cid,
                                            c["mac"],
                                            devname(old_id),
                                            devname(new_id),
                                            (
                                                f'name="{c["name"]}" '
                                                f'window={ROAM_FLAP_WINDOW_SEC}s count={roam_count} '
                                                f'old_ap="{devlabel(old_id)}" new_ap="{devlabel(new_id)}"'
                                            ),
                                        ),
                                    )

                    if (p["name"] or "") != (c["name"] or ""):
                        conn.execute(
                            """INSERT INTO events
                               (ts, site_id, event_type, client_id, mac, details)
                               VALUES (?, ?, 'NAME_CHANGED', ?, ?, ?);""",
                            (ts, site_id, cid, c["mac"], f'old="{p["name"]}" new="{c["name"]}"'),
                        )

                conn.commit()

                # Print a summary line (keeps terminal readable)
                print(
                    f"[{ts}] devices={len(devices)} clients={len(clients)} "
                    f"new={len(new_ids)} left={left_logged} db={db_path}"
                )
            else:
                print(f"[{ts}] devices={len(devices)} clients={len(clients)} db={db_path}")

        except Exception as e:
            # don't die; log and continue
            print(f"[{ts}] ERROR: {type(e).__name__}: {e}")

        if time.monotonic() - last_prune >= PRUNE_INTERVAL_SEC:
            try:
                # Must run before prune_old_data -- it reads client_snapshot
                # rows that prune is about to delete.
                compute_daily_rollup(conn, interval)
            except Exception as e:
                print(f"[{ts}] ROLLUP ERROR: {type(e).__name__}: {e}")
            try:
                prune_old_data(conn)
            except Exception as e:
                print(f"[{ts}] PRUNE ERROR: {type(e).__name__}: {e}")
            last_prune = time.monotonic()

        time.sleep(interval)


if __name__ == "__main__":
    main()
