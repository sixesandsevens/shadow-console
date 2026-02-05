# Shadow Console

Simple polling + diffing for UniFi Integration API snapshots.

## Useful Queries

```sh
sqlite3 ~/Projects/shadow-console/shadowconsole.db \
"SELECT ts, event_type, mac, uplink_old, uplink_new, details
 FROM events
 WHERE event_type='MOVED_UPLINK'
 ORDER BY rowid DESC
 LIMIT 10;"
```
