# Shadow Console

Shadow Console polls the UniFi Integration API on an interval, stores snapshots in SQLite, and generates small, actionable "diff" events (new clients, uplink moves, offline devices, roam flapping, etc.).

It is built for "what just changed?" troubleshooting, not long-term metrics.

## What You Get

- `shadow_poller.py`: polling + diffing loop, writes snapshots and events to SQLite
- `web/app.py`: tiny Flask dashboard for recent events + basic health/anomaly checks
- `shadowconsole.db`: local SQLite database (WAL mode)

## Requirements

- Python 3.10+
- `requests` (poller)
- `flask` (web dashboard)

## Configure

Environment variables used by the poller:

- `SHADOW_UDM_URL` (required): e.g. `https://192.168.1.1`
- `SHADOW_API_KEY` (required): your UniFi Integration API key
- `SHADOW_SITE_ID` (required): site UUID
- `SHADOW_DB` (optional): path to DB (default `./shadowconsole.db`)
- `SHADOW_INTERVAL_SEC` (optional): poll interval seconds (default `60`)

Note: the poller currently uses `verify=False` for HTTPS requests (LAN/trusted environment assumption).

## Run

Poller:

```bash
python3 shadow_poller.py
```

Dashboard:

```bash
python3 web/app.py
```

By default the dashboard reads `../shadowconsole.db` (relative to `web/`). Override with `SHADOW_DB`.

## Useful Queries

Recent uplink moves:

```sh
sqlite3 ./shadowconsole.db "SELECT ts, event_type, mac, uplink_old, uplink_new, details
 FROM events
 WHERE event_type='MOVED_UPLINK'
 ORDER BY rowid DESC
 LIMIT 25;"
```

Recent device offline/missing events:

```sh
sqlite3 ./shadowconsole.db "SELECT ts, event_type, mac, details
 FROM events
 WHERE event_type IN ('DEVICE_OFFLINE','DEVICE_MISSING')
 ORDER BY rowid DESC
 LIMIT 25;"
```

## Notes

- This is intentionally "low ceremony": SQLite, a single poll loop, and a simple UI.
- If you want to reset history, stop the poller and move `shadowconsole.db*` out of the way.
