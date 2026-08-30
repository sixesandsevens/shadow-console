#!/usr/bin/env python3
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import re
from flask import Flask, g, render_template, request, abort

try:
    from web import notify_policy
except ImportError:
    import notify_policy

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.getenv("SHADOW_DB") or os.path.abspath(os.path.join(APP_DIR, "..", "shadowconsole.db"))


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = os.getenv("SHADOW_DB", DEFAULT_DB)

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(app.config["DB_PATH"])
            conn.row_factory = sqlite3.Row
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

    app.jinja_env.filters["age"] = human_age

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
        active_incidents = q(
            """
            SELECT device_id, mac, name, model, opened_ts, opened_reason
            FROM device_incidents
            WHERE closed_ts IS NULL
            ORDER BY opened_ts ASC;
            """
        )
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

        # Browser-notification payload: only the notify_policy-approved
        # subset of `events` (already fetched above, same curated list the
        # ticker renders) -- embedded as JSON for notify.js to read. This
        # rides the page's existing 10s auto-refresh instead of a second
        # polling loop; see notify_policy.py for the actual policy.
        notify_events = []
        for e in events:
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
            return render_template("devices.html", ts=None, devices=[])

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
        return render_template("devices.html", ts=ts, devices=rows)

    return app


if __name__ == "__main__":
    app = create_app()
    # Safe default: bind localhost only
    host = os.getenv("SHADOW_WEB_HOST", "127.0.0.1")
    port = int(os.getenv("SHADOW_WEB_PORT", "5000"))
    debug = os.getenv("SHADOW_WEB_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
