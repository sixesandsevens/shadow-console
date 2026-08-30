#!/usr/bin/env python3
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import re
from flask import Flask, g, render_template, request, abort, redirect, url_for

try:
    import notify_policy
    import device_lifecycle
except ImportError:
    # Direct-run mode (`python3 web/app.py`) without PYTHONPATH set won't
    # see notify_policy.py/device_lifecycle.py in the parent dir otherwise --
    # the systemd unit always sets PYTHONPATH=/opt/shadow-console, so this
    # only matters for ad-hoc manual runs.
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import notify_policy
    import device_lifecycle

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.getenv("SHADOW_DB") or os.path.abspath(os.path.join(APP_DIR, "..", "shadowconsole.db"))


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = os.getenv("SHADOW_DB", DEFAULT_DB)

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(app.config["DB_PATH"])
            conn.row_factory = sqlite3.Row
            # Written from this web app (Devices page), not the poller, so
            # ensure it exists here too rather than depending on the poller
            # having been restarted since device_overrides was added.
            device_lifecycle.ensure_schema(conn)
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(_exc: Optional[BaseException]) -> None:
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def q(sql: str, args: tuple = ()) -> List[sqlite3.Row]:
        return get_db().execute(sql, args).fetchall()

    def q1(sql: str, args: tuple = ()) -> Optional[sqlite3.Row]:
        return get_db().execute(sql, args).fetchone()

    def parse_ts(ts: str) -> datetime:
        # stored like 2026-02-05T16:27:38+00:00
        return datetime.fromisoformat(ts)

    def extract_name(details: Optional[str]) -> Optional[str]:
        if not details:
            return None
        m = re.search(r'name="([^"]+)"', details)
        return m.group(1) if m else None

    def human_age(ts: str) -> str:
        dt = parse_ts(ts)
        now = datetime.now(timezone.utc)
        delta = now - dt
        s = int(delta.total_seconds())
        if s < 60:
            return f"{s}s"
        m = s // 60
        if m < 60:
            return f"{m}m"
        h = m // 60
        if h < 48:
            return f"{h}h"
        d = h // 24
        return f"{d}d"

    def human_duration(total_seconds: int) -> str:
        m, s = divmod(total_seconds, 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"

    def excluded_macs() -> set:
        # events/device_incidents identify a device by mac, not device_id,
        # so alerting/notification filtering has to go through device_state
        # (the only table that keeps a current device_id -> mac mapping).
        ids = device_lifecycle.excluded_device_ids(get_db())
        if not ids:
            return set()
        rows = q(
            f"SELECT last_mac FROM device_state WHERE device_id IN ({','.join('?' * len(ids))});",
            tuple(ids),
        )
        return {r["last_mac"] for r in rows if r["last_mac"]}

    def human_until(ts: Optional[str]) -> str:
        """Inverse of human_age: relative time remaining until a future ts."""
        if not ts:
            return "indefinitely"
        delta = parse_ts(ts) - datetime.now(timezone.utc)
        s = int(delta.total_seconds())
        if s <= 0:
            return "expired"
        m = s // 60
        if m < 60:
            return f"in {m}m"
        h = m // 60
        if h < 48:
            return f"in {h}h"
        d = h // 24
        return f"in {d}d"

    def extract_building(name: Optional[str]) -> Optional[str]:
        # No structured building field exists anywhere in the UniFi API --
        # this is the same "Building N" naming convention already visible
        # in device names (e.g. "GRC-GAIN-SW22 - Building 4"), just parsed
        # instead of hardcoded. Devices without it (gateways, a few APs)
        # come back None and get grouped as "Unknown" at render time.
        if not name:
            return None
        m = re.search(r"Building\s+(\d+)", name, re.IGNORECASE)
        return f"Building {m.group(1)}" if m else None

    def window_bounds(window: str):
        now = datetime.now(timezone.utc)
        if window == "24h":
            start = now - timedelta(hours=24)
        elif window == "30d":
            start = now - timedelta(days=30)
        else:
            window = "7d"
            start = now - timedelta(days=7)
        return window, start, now

    app.jinja_env.filters["age"] = human_age
    app.jinja_env.filters["until"] = human_until

    @app.route("/")
    def index():
        def parse_iso(ts: str) -> datetime:
            # supports "2026-02-05T20:45:46+00:00"
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))

        poll_interval = int(os.getenv("SHADOW_INTERVAL_SEC", "60"))

        snapshot_age_sec = None
        stale_level = "unknown"  # live|stale|dead|unknown
        stale_label = "UNKNOWN"

        # Latest snapshot times
        latest = q1("SELECT ts FROM client_snapshot ORDER BY ts DESC LIMIT 1;")
        latest_ts = latest["ts"] if latest else None

        if latest_ts:
            dt = parse_iso(latest_ts)
            snapshot_age_sec = int((datetime.now(timezone.utc) - dt).total_seconds())

            if snapshot_age_sec <= poll_interval * 2:
                stale_level = "live"
                stale_label = "LIVE"
            elif snapshot_age_sec <= poll_interval * 5:
                stale_level = "stale"
                stale_label = "STALE"
            else:
                stale_level = "dead"
                stale_label = "DEAD"

        # Counts in latest snapshot
        client_count = 0
        device_count = 0
        if latest_ts:
            client_count = q1("SELECT COUNT(*) AS c FROM client_snapshot WHERE ts=?;", (latest_ts,))["c"]
            device_count = q1("SELECT COUNT(*) AS c FROM device_snapshot WHERE ts=?;", (latest_ts,))["c"]

        # Find most recent event rowid (for cursor)
        latest_event = q1("SELECT MAX(rowid) AS max_id FROM events;")
        latest_event_id = int(latest_event["max_id"] or 0)

        # Cursor from query param (?since=123)
        since = int(request.args.get("since", "0") or 0)

        # Recent events (default: show more actionable types)
        # You can change this later; this is the “no noise by default” stance.
        events = q(
            """
            SELECT rowid, ts, event_type, mac, client_id, ip_old, ip_new, uplink_old, uplink_new, device_type, details
            FROM events
            WHERE event_type IN (
                'NEW_CLIENT','LEFT_CLIENT','MOVED_UPLINK','ROAMING_FLAP',
                'DEVICE_OFFLINE','DEVICE_ONLINE','DEVICE_MISSING',
                'CLIENT_CHURN_SPIKE','INFRA_OUTAGE_LIKELY'
            )
            ORDER BY rowid DESC
            LIMIT 50;
            """
        )

        # Quick breakdown of event types last hour
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
        breakdown = q(
            """
            SELECT event_type, COUNT(*) AS c
            FROM events
            WHERE ts >= ?
            GROUP BY event_type
            ORDER BY c DESC;
            """,
            (one_hour_ago,),
        )

        anomalies = []

        # System health anomaly
        if stale_level == "dead":
            anomalies.append(
                {
                    "level": "critical",
                    "text": f"Poller appears DEAD (last update {snapshot_age_sec}s ago)",
                    "age": f"{snapshot_age_sec}s",
                }
            )
        elif stale_level == "stale":
            anomalies.append(
                {
                    "level": "warning",
                    "text": f"Poller is STALE ({snapshot_age_sec}s since last update)",
                    "age": f"{snapshot_age_sec}s",
                }
            )

        # Recent wired client loss (last 5 minutes)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        recent_losses = q(
            """
            SELECT e.ts, e.mac, e.details, cs.last_type
            FROM events e
            LEFT JOIN client_state cs ON cs.client_id = e.client_id
            WHERE e.event_type = 'LEFT_CLIENT'
            ORDER BY e.rowid DESC
            LIMIT 20;
            """
        )

        seen = set()

        for loss in recent_losses:
            loss_ts = parse_iso(loss["ts"])
            if loss_ts < cutoff:
                continue
            if (loss["last_type"] or "").upper() != "WIRED":
                continue
            mac = loss["mac"]
            if mac in seen:
                continue
            seen.add(mac)
            name = extract_name(loss["details"])
            label = f"{name} ({mac})" if name else mac
            anomalies.append(
                {
                    "level": "critical",
                    "text": f"Wired client left: {label}",
                    "age": human_age(loss["ts"]),
                }
            )

        # Active device incidents: opened when a device goes DEVICE_OFFLINE
        # or DEVICE_MISSING, closed the moment it comes back (DEVICE_ONLINE).
        # Unlike a fixed time window, this disappears exactly when the
        # device recovers instead of lingering for N more minutes.
        excluded_ids = device_lifecycle.excluded_device_ids(get_db())
        active_incidents = [
            inc
            for inc in q(
                """
                SELECT device_id, mac, name, model, opened_ts, opened_reason
                FROM device_incidents
                WHERE closed_ts IS NULL
                ORDER BY opened_ts ASC;
                """
            )
            if inc["device_id"] not in excluded_ids
        ]
        for inc in active_incidents:
            label = inc["mac"] or inc["device_id"]
            if inc["name"]:
                label = f"{inc['name']} ({label})"

            # If a churn spike was correlated to this device while the
            # incident's been open, that's a stronger, more actionable
            # signal than "device offline" alone -- surface it instead.
            outage = q1(
                """
                SELECT details FROM events
                WHERE event_type='INFRA_OUTAGE_LIKELY' AND mac=? AND ts >= ?
                ORDER BY rowid DESC LIMIT 1;
                """,
                (inc["mac"], inc["opened_ts"]),
            )
            if outage:
                m = re.search(r"affected_clients=(\d+)", outage["details"] or "")
                affected = f" ({m.group(1)} clients affected)" if m else ""
                text = f"Outage likely: {label}{affected}"
            else:
                kind = "Device offline" if inc["opened_reason"] == "DEVICE_OFFLINE" else "Device missing"
                text = f"{kind}: {label}"

            anomalies.append(
                {
                    "level": "critical",
                    "text": text,
                    "age": human_age(inc["opened_ts"]),
                }
            )

        # Client churn spike: active means the rolling LEFT_CLIENT count is
        # still at/above threshold right now, not just that it crossed it
        # at some point in the past.
        churn = q1("SELECT last_count, started_ts FROM churn_spike_state WHERE active=1 LIMIT 1;")
        if churn:
            anomalies.append(
                {
                    "level": "critical",
                    "text": f"Client churn spike: {churn['last_count']} clients left recently",
                    "age": human_age(churn["started_ts"]),
                }
            )

        new_count = sum(1 for e in events if e["rowid"] > since)

        # Browser-notification payload: queried SEPARATELY from `events`
        # above (the ticker's curated, LIMIT-50 list) -- a single switch
        # outage can spawn dozens of LEFT_CLIENT rows right behind it,
        # which would push the actual DEVICE_OFFLINE past position 50
        # before the next page refresh and silently bury the one event
        # that must never be missed. This query only ever looks at the
        # narrow slice notify_policy actually cares about, so a large
        # client-churn burst can't crowd it out. Still embedded as JSON
        # for notify.js to read, still riding the page's existing 10s
        # auto-refresh -- no second polling loop.
        notify_event_types = tuple(notify_policy.FAILURE_EVENT_TYPES | notify_policy.RECOVERY_EVENT_TYPES)
        notify_device_types = tuple(notify_policy.NOTIFY_DEVICE_TYPES)
        notify_source = q(
            f"""
            SELECT rowid, ts, event_type, mac, device_type, details
            FROM events
            WHERE event_type IN ({",".join("?" * len(notify_event_types))})
              AND device_type IN ({",".join("?" * len(notify_device_types))})
            ORDER BY rowid DESC
            LIMIT 500;
            """,
            notify_event_types + notify_device_types,
        )

        muted_macs = excluded_macs()
        notify_events = []
        for e in notify_source:
            if e["mac"] in muted_macs:
                continue
            decision = notify_policy.classify(e["event_type"], e["device_type"])
            if not decision["notify"]:
                continue

            entry = {
                "id": e["rowid"],
                "event_type": e["event_type"],
                "device_type": e["device_type"],
                "mac": e["mac"],
                "name": extract_name(e["details"]),
                "ts": e["ts"],
                "severity": decision["severity"],
            }

            if decision["severity"] == "critical":
                active_inc = q1(
                    "SELECT 1 FROM device_incidents WHERE mac=? AND closed_ts IS NULL LIMIT 1;",
                    (e["mac"],),
                )
                entry["active"] = active_inc is not None
            else:
                entry["active"] = False
                # Downtime, if we can find the incident this recovery closed.
                # If not found cleanly, leave it out rather than guessing.
                closed_inc = q1(
                    """
                    SELECT opened_ts, closed_ts FROM device_incidents
                    WHERE mac=? AND closed_ts IS NOT NULL
                    ORDER BY incident_id DESC LIMIT 1;
                    """,
                    (e["mac"],),
                )
                if closed_inc:
                    try:
                        opened_dt = parse_ts(closed_inc["opened_ts"])
                        closed_dt = parse_ts(closed_inc["closed_ts"])
                        downtime_sec = int((closed_dt - opened_dt).total_seconds())
                        if downtime_sec >= 0:
                            entry["downtime"] = human_duration(downtime_sec)
                    except (ValueError, TypeError):
                        pass

            notify_events.append(entry)

        notify_payload = {
            "events": notify_events,
            "poller_dead": stale_level == "dead",
        }

        return render_template(
            "index.html",
            latest_ts=latest_ts,
            client_count=client_count,
            device_count=device_count,
            events=events,
            breakdown=breakdown,
            since=since,
            notify_payload=notify_payload,
            new_count=new_count,
            latest_event_id=latest_event_id,
            poll_interval=poll_interval,
            snapshot_age_sec=snapshot_age_sec,
            stale_level=stale_level,
            stale_label=stale_label,
            anomalies=anomalies,
        )

    @app.route("/events")
    def events():
        limit = min(int(request.args.get("limit", "200")), 2000)
        etype = request.args.get("type", "").strip()

        where = ""
        args: List[Any] = []
        if etype:
            where = "WHERE event_type = ?"
            args.append(etype)

        rows = q(
            f"""
            SELECT rowid, ts, event_type, mac, client_id, ip_old, ip_new, uplink_old, uplink_new, details
            FROM events
            {where}
            ORDER BY rowid DESC
            LIMIT ?;
            """,
            tuple(args + [limit]),
        )

        types = q("SELECT DISTINCT event_type FROM events ORDER BY event_type;")
        return render_template("events.html", events=rows, types=types, selected_type=etype, limit=limit)

    @app.route("/clients")
    def clients():
        # Show latest snapshot clients with resolved uplink name, sortable.
        latest = q1("SELECT ts FROM client_snapshot ORDER BY ts DESC LIMIT 1;")
        if not latest:
            return render_template("clients.html", ts=None, clients=[])

        ts = latest["ts"]
        ctype = request.args.get("type", "").strip().upper()  # WIRED / WIRELESS
        search = request.args.get("q", "").strip()

        where = ["ts = ?"]
        args: List[Any] = [ts]

        if ctype in ("WIRED", "WIRELESS"):
            where.append("UPPER(type) = ?")
            args.append(ctype)

        if search:
            where.append("(LOWER(name) LIKE ? OR LOWER(mac) LIKE ? OR LOWER(ip) LIKE ?)")
            s = f"%{search.lower()}%"
            args.extend([s, s, s])

        sql = f"""
        SELECT client_id, type, name, ip, mac, connected_at, uplink_device_name
        FROM client_snapshot
        WHERE {' AND '.join(where)}
        ORDER BY
            CASE WHEN type='WIRED' THEN 0 ELSE 1 END,
            LOWER(COALESCE(name, mac)) ASC
        LIMIT 1000;
        """
        rows = q(sql, tuple(args))
        return render_template("clients.html", ts=ts, clients=rows, ctype=ctype, search=search)

    @app.route("/clients/<client_id>")
    def client_detail(client_id: str):
        # Latest known record (from client_state)
        state = q1(
            """
            SELECT client_id, last_seen_ts, miss_count, last_type, last_name, last_ip, last_mac, last_uplink
            FROM client_state
            WHERE client_id = ?;
            """,
            (client_id,),
        )
        if not state:
            abort(404)

        # Recent events for this client
        ev = q(
            """
            SELECT rowid, ts, event_type, mac, ip_old, ip_new, uplink_old, uplink_new, details
            FROM events
            WHERE client_id = ?
            ORDER BY rowid DESC
            LIMIT 200;
            """,
            (client_id,),
        )

        # History (last N snapshots) for this client
        hist = q(
            """
            SELECT ts, type, name, ip, mac, uplink_device_name
            FROM client_snapshot
            WHERE client_id = ?
            ORDER BY ts DESC
            LIMIT 200;
            """,
            (client_id,),
        )

        return render_template("client_detail.html", state=state, events=ev, history=hist)

    @app.route("/devices")
    def devices():
        latest = q1("SELECT ts FROM device_snapshot ORDER BY ts DESC LIMIT 1;")
        if not latest:
            return render_template(
                "devices.html", ts=None, devices=[],
                lifecycles=device_lifecycle.LIFECYCLES,
                maintenance_durations=device_lifecycle.MAINTENANCE_DURATIONS,
            )

        ts = latest["ts"]
        rows = q(
            """
            SELECT device_id, name, model, ip, state, mac
            FROM device_snapshot
            WHERE ts = ?
            ORDER BY
                CASE WHEN state='OFFLINE' THEN 0 ELSE 1 END,
                LOWER(COALESCE(name, device_id)) ASC;
            """,
            (ts,),
        )
        overrides = device_lifecycle.all_overrides(get_db())
        devices_out = [
            dict(
                r,
                lifecycle=overrides.get(r["device_id"], {}).get("lifecycle", "monitored"),
                maintenance_until=overrides.get(r["device_id"], {}).get("maintenance_until"),
            )
            for r in rows
        ]
        return render_template(
            "devices.html", ts=ts, devices=devices_out,
            lifecycles=device_lifecycle.LIFECYCLES,
            maintenance_durations=device_lifecycle.MAINTENANCE_DURATIONS,
        )

    @app.route("/devices/<device_id>/lifecycle", methods=["POST"])
    def set_device_lifecycle(device_id: str):
        lifecycle = request.form.get("lifecycle", "monitored")
        maintenance_duration = request.form.get("maintenance_duration", "indefinite")
        if lifecycle not in device_lifecycle.LIFECYCLES:
            abort(400)
        if maintenance_duration not in device_lifecycle.MAINTENANCE_DURATIONS:
            abort(400)
        try:
            device_lifecycle.set_device_lifecycle(get_db(), device_id, lifecycle, maintenance_duration)
        except ValueError:
            abort(400)
        return redirect(url_for("devices"))

    @app.route("/settings")
    def settings():
        return render_template("settings.html")

    @app.route("/stats")
    def stats():
        window, start, now = window_bounds(request.args.get("window", "7d"))
        window_seconds = (now - start).total_seconds()

        # device_incidents is never pruned (see shadow_poller.py), so any
        # window here -- even 30d -- is a plain query against it, not a
        # rollup. Only client_snapshot-derived numbers (client trend,
        # poller uptime) need daily_network_stats, since that source table
        # is pruned after 24h.
        excluded_ids = device_lifecycle.excluded_device_ids(get_db())
        incident_rows = [
            r
            for r in q(
                """
                SELECT device_id, mac, name, model, device_type, opened_ts, closed_ts
                FROM device_incidents
                WHERE opened_ts <= ?
                  AND (closed_ts IS NULL OR closed_ts >= ?)
                ORDER BY opened_ts ASC;
                """,
                (now.isoformat(), start.isoformat()),
            )
            if r["device_id"] not in excluded_ids
        ]

        device_agg: Dict[str, Dict[str, Any]] = {}
        building_agg: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"incidents": 0, "downtime_seconds": 0.0})
        total_downtime_seconds = 0.0

        for r in incident_rows:
            opened_dt = parse_ts(r["opened_ts"])
            closed_dt = parse_ts(r["closed_ts"]) if r["closed_ts"] else now
            overlap_start = max(opened_dt, start)
            overlap_end = min(closed_dt, now)
            overlap_seconds = max(0.0, (overlap_end - overlap_start).total_seconds())
            total_downtime_seconds += overlap_seconds

            agg = device_agg.setdefault(
                r["device_id"],
                {
                    "name": r["name"],
                    "device_type": r["device_type"],
                    "incidents": 0,
                    "downtime_seconds": 0.0,
                    "recovery_durations": [],
                },
            )
            agg["incidents"] += 1
            agg["downtime_seconds"] += overlap_seconds
            if r["closed_ts"]:
                agg["recovery_durations"].append((parse_ts(r["closed_ts"]) - opened_dt).total_seconds())

            building = extract_building(r["name"]) or "Unknown"
            building_agg[building]["incidents"] += 1
            building_agg[building]["downtime_seconds"] += overlap_seconds

        # Device universe = currently-known devices (latest snapshot), so a
        # clean device shows up as 100% uptime / 0 incidents instead of
        # being omitted entirely.
        latest_dev_ts = q1("SELECT MAX(ts) AS ts FROM device_snapshot;")
        known_devices = (
            [
                d
                for d in q(
                    "SELECT device_id, name, device_type FROM device_snapshot WHERE ts=?;",
                    (latest_dev_ts["ts"],),
                )
                if d["device_id"] not in excluded_ids
            ]
            if latest_dev_ts and latest_dev_ts["ts"]
            else []
        )
        known_ids = {d["device_id"] for d in known_devices}

        def build_entry(device_id: str, name: Optional[str], device_type: Optional[str]) -> Dict[str, Any]:
            agg = device_agg.get(device_id)
            incidents = agg["incidents"] if agg else 0
            downtime_seconds = agg["downtime_seconds"] if agg else 0.0
            recovery_durations = agg["recovery_durations"] if agg else []
            uptime_pct = (max(0.0, 1 - downtime_seconds / window_seconds) * 100) if window_seconds > 0 else 100.0
            mean_recovery = sum(recovery_durations) / len(recovery_durations) if recovery_durations else None
            mtbf_days = (window_seconds / incidents / 86400) if incidents > 0 else None
            return {
                "device_id": device_id,
                "name": name or device_id,
                "device_type": device_type,
                "building": extract_building(name),
                "incidents": incidents,
                "downtime": human_duration(int(downtime_seconds)),
                "downtime_seconds": downtime_seconds,
                "uptime_pct": round(uptime_pct, 2),
                "mean_recovery": human_duration(int(mean_recovery)) if mean_recovery is not None else None,
                "mtbf_days": round(mtbf_days, 1) if mtbf_days is not None else None,
            }

        leaderboard = [build_entry(d["device_id"], d["name"], d["device_type"]) for d in known_devices]
        # Devices with incidents in-window that have since dropped out of
        # the latest snapshot (renamed/decommissioned) -- still worth
        # showing, just not claimed as "currently known."
        for device_id, agg in device_agg.items():
            if device_id not in known_ids:
                leaderboard.append(build_entry(device_id, agg["name"], agg["device_type"]))

        most_troublesome = sorted(
            [e for e in leaderboard if e["incidents"] > 0],
            key=lambda e: (-e["incidents"], -e["downtime_seconds"]),
        )[:5]
        most_reliable = sorted(
            [e for e in leaderboard if (e["device_type"] or "") in ("switch", "ap", "camera")],
            key=lambda e: (-e["uptime_pct"], e["incidents"]),
        )[:5]

        buildings = sorted(
            (
                {"building": b, "incidents": v["incidents"], "downtime": human_duration(int(v["downtime_seconds"]))}
                for b, v in building_agg.items()
            ),
            key=lambda x: x["incidents"],
            reverse=True,
        )
        max_building_incidents = max((b["incidents"] for b in buildings), default=1)

        uplink_rows = q(
            """
            SELECT uplink_new, COUNT(*) AS c
            FROM events
            WHERE event_type='MOVED_UPLINK' AND uplink_new IS NOT NULL AND ts >= ?
            GROUP BY uplink_new
            ORDER BY c DESC
            LIMIT 15;
            """,
            (start.isoformat(),),
        )
        max_uplink_flaps = max((r["c"] for r in uplink_rows), default=1)

        churn_spike_count = q1(
            "SELECT COUNT(*) AS c FROM events WHERE event_type='CLIENT_CHURN_SPIKE' AND ts >= ?;",
            (start.isoformat(),),
        )["c"]

        new_clients_rows = q(
            """
            SELECT substr(ts,1,10) AS day, COUNT(*) AS c
            FROM events
            WHERE event_type='NEW_CLIENT' AND ts >= ?
            GROUP BY day
            ORDER BY day ASC;
            """,
            (start.isoformat(),),
        )

        # Client trend: completed days from the rollup (see
        # shadow_poller.compute_daily_rollup) plus today, computed live
        # the same way the dashboard already does -- today doesn't have a
        # rollup row yet since that only materializes at day-end.
        daily_rows = q(
            "SELECT date, peak_clients, avg_clients FROM daily_network_stats WHERE date >= ? ORDER BY date ASC;",
            (start.date().isoformat(),),
        )
        trend = [{"date": r["date"], "peak": r["peak_clients"], "avg": round(r["avg_clients"], 1)} for r in daily_rows]

        today_str = now.date().isoformat()
        today_rows = q(
            "SELECT ts, COUNT(*) AS c FROM client_snapshot WHERE ts >= ? GROUP BY ts;",
            (f"{today_str}T00:00:00",),
        )
        if today_rows:
            today_counts = [r["c"] for r in today_rows]
            trend.append(
                {"date": today_str, "peak": max(today_counts), "avg": round(sum(today_counts) / len(today_counts), 1)}
            )
        max_trend_peak = max((t["peak"] for t in trend), default=1)

        # Poller downtime only reflects completed days (rollup-sourced) --
        # today's partial downtime isn't included, same caveat as the
        # trend chart above.
        poller_downtime_row = q1(
            "SELECT SUM(poller_downtime_seconds) AS s FROM daily_network_stats WHERE date >= ?;",
            (start.date().isoformat(),),
        )
        poller_downtime_seconds = poller_downtime_row["s"] or 0 if poller_downtime_row else 0

        latest_client_ts = q1("SELECT MAX(ts) AS ts FROM client_snapshot;")
        composition = (
            q(
                "SELECT UPPER(COALESCE(type,'UNKNOWN')) AS type, COUNT(*) AS c FROM client_snapshot WHERE ts=? GROUP BY type;",
                (latest_client_ts["ts"],),
            )
            if latest_client_ts and latest_client_ts["ts"]
            else []
        )

        return render_template(
            "stats.html",
            window=window,
            total_incidents=len(incident_rows),
            total_downtime=human_duration(int(total_downtime_seconds)),
            most_troublesome=most_troublesome,
            most_reliable=most_reliable,
            buildings=buildings,
            max_building_incidents=max_building_incidents,
            uplink_rows=uplink_rows,
            max_uplink_flaps=max_uplink_flaps,
            churn_spike_count=churn_spike_count,
            new_clients_rows=new_clients_rows,
            trend=trend,
            max_trend_peak=max_trend_peak,
            poller_downtime=human_duration(int(poller_downtime_seconds)),
            composition=composition,
        )

    return app


if __name__ == "__main__":
    app = create_app()
    # Safe default: bind localhost only
    host = os.getenv("SHADOW_WEB_HOST", "127.0.0.1")
    port = int(os.getenv("SHADOW_WEB_PORT", "5000"))
    debug = os.getenv("SHADOW_WEB_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
