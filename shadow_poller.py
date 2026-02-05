#!/usr/bin/env python3
import os
import time
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

LEFT_CLIENT_GRACE_POLLS = 3
DEVICE_MISSING_GRACE_POLLS = 2
LEFT_CLIENT_STALE_SEC = 3600
ROAM_FLAP_WINDOW_SEC = 10 * 60
ROAM_FLAP_THRESHOLD = 5


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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
            last_state TEXT
        );
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
                    (ts, site_id, device_id, name, model, ip, state, mac, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                    "SELECT device_id, name, model, ip, mac, state FROM device_snapshot WHERE ts=?;",
                    (newest_dts,),
                ).fetchall()

                prev_dev_rows = conn.execute(
                    "SELECT device_id, name, model, ip, mac, state FROM device_snapshot WHERE ts=?;",
                    (prev_dts,),
                ).fetchall()

                cur_devs = {
                    r[0]: {"name": r[1], "model": r[2], "ip": r[3], "mac": r[4], "state": r[5]}
                    for r in cur_dev_rows
                }
                prev_devs = {
                    r[0]: {"name": r[1], "model": r[2], "ip": r[3], "mac": r[4], "state": r[5]}
                    for r in prev_dev_rows
                }

                cur_ids = set(cur_devs.keys())

                # Load existing device_state
                ds_rows = conn.execute(
                    "SELECT device_id, miss_count, last_name, last_model, last_ip, last_mac, last_state FROM device_state;"
                ).fetchall()
                ds = {r[0]: r[1:] for r in ds_rows}

                conn.execute("BEGIN;")

                # Update state for devices we see now
                for did, d in cur_devs.items():
                    conn.execute(
                        """
                        INSERT INTO device_state
                        (device_id, last_seen_ts, miss_count, last_name, last_model, last_ip, last_mac, last_state)
                        VALUES (?, ?, 0, ?, ?, ?, ?, ?)
                        ON CONFLICT(device_id) DO UPDATE SET
                            last_seen_ts=excluded.last_seen_ts,
                            miss_count=0,
                            last_name=excluded.last_name,
                            last_model=excluded.last_model,
                            last_ip=excluded.last_ip,
                            last_mac=excluded.last_mac,
                            last_state=excluded.last_state;
                        """,
                        (did, newest_dts, d["name"], d["model"], d["ip"], d["mac"], d["state"]),
                    )

                    # Detect state change ONLINE <-> OFFLINE
                    prev_state = (prev_devs.get(did, {}).get("state") or "").upper()
                    cur_state = (d.get("state") or "").upper()

                    if prev_state and cur_state and prev_state != cur_state:
                        if cur_state == "OFFLINE":
                            conn.execute(
                                """INSERT INTO events
                                   (ts, site_id, event_type, client_id, mac, details)
                                   VALUES (?, ?, 'DEVICE_OFFLINE', NULL, ?, ?);""",
                                (
                                    newest_dts,
                                    site_id,
                                    d["mac"],
                                    f'name="{d["name"]}" model="{d["model"]}" ip="{d["ip"]}"',
                                ),
                            )
                        elif cur_state == "ONLINE":
                            conn.execute(
                                """INSERT INTO events
                                   (ts, site_id, event_type, client_id, mac, details)
                                   VALUES (?, ?, 'DEVICE_ONLINE', NULL, ?, ?);""",
                                (
                                    newest_dts,
                                    site_id,
                                    d["mac"],
                                    f'name="{d["name"]}" model="{d["model"]}" ip="{d["ip"]}"',
                                ),
                            )

                # Handle devices missing from current snapshot (grace)
                missing = set(ds.keys()) - cur_ids
                for did in missing:
                    miss_count, last_name, last_model, last_ip, last_mac, last_state = ds[did]
                    new_miss = int(miss_count) + 1

                    conn.execute("UPDATE device_state SET miss_count=? WHERE device_id=?;", (new_miss, did))

                    if new_miss == DEVICE_MISSING_GRACE_POLLS:
                        # Treat as offline/missing (even if last_state wasn't OFFLINE)
                        conn.execute(
                            """INSERT INTO events
                               (ts, site_id, event_type, client_id, mac, details)
                               VALUES (?, ?, 'DEVICE_MISSING', NULL, ?, ?);""",
                            (
                                newest_dts,
                                site_id,
                                last_mac,
                                f'name="{last_name}" model="{last_model}" ip="{last_ip}" last_state="{last_state}"',
                            ),
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

        time.sleep(interval)


if __name__ == "__main__":
    main()
