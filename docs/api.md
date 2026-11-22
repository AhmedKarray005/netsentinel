# REST API

Start it:

```powershell
netsentinel serve                 # http://127.0.0.1:8000, interactive docs at /docs
netsentinel serve --port 8765
```

It listens on `127.0.0.1` (this computer only) by default. Exposing it to a network needs
authentication and TLS first (not implemented, see Limitations).

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `NETSENTINEL_DB_PATH` | `data/netsentinel.db` | SQLite database file |
| `NETSENTINEL_UPLOAD_DIR` | `data/uploads` | temporary upload files (deleted after analysis) |
| `NETSENTINEL_MAX_UPLOAD_MB` | `50` | upload size limit |
| `NETSENTINEL_RULES_FILE` | none | TOML thresholds (see `config/rules.example.toml`); invalid file = server refuses to start |
| `NETSENTINEL_CORS_ORIGINS` | `http://localhost:5173` | comma-separated origins allowed to call the API from a browser (dashboard) |

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness + database check |
| GET | `/api/rules` | the 3 rules, MITRE technique, enabled flag, current thresholds |
| POST | `/api/analyses` | upload a capture (multipart field `file`), analyze, store; returns 201 + the analysis |
| GET | `/api/analyses?limit&offset` | analyses, newest first |
| GET | `/api/analyses/{id}` | one analysis with its overview (packet summary, flow rankings) |
| DELETE | `/api/analyses/{id}` | delete it with all its flows and alerts |
| GET | `/api/analyses/{id}/flows` | flows; filters `protocol`, `ip`, `port`, `tcp_state`; `sort` = start / bytes / packets |
| GET | `/api/alerts` | alerts of all analyses; filters `analysis_id`, `severity`, `rule_id`, `ip` |

Lists return `{"items": [...], "total": N, "limit": L, "offset": O}`. `total` is the number of
matching rows, so a client can build page controls. `limit` is 1-500.

Example:

```powershell
curl.exe -F "file=@lab/04_loopback_scan/scan.pcapng" http://127.0.0.1:8000/api/analyses
curl.exe "http://127.0.0.1:8000/api/alerts?severity=high"
curl.exe "http://127.0.0.1:8000/api/analyses/1/flows?tcp_state=REJECTED&limit=10&offset=10"
```

## Status codes

| Code | When |
|---|---|
| 201 | analysis created |
| 204 | analysis deleted |
| 404 | unknown analysis id |
| 413 | upload larger than the limit |
| 415 | extension not `.pcap`, `.pcapng` or `.cap` |
| 422 | file signature is not a capture, file cannot be parsed, or invalid query parameter (bad IP, port > 65535, unknown severity...) |

## Untrusted input handling

- **Extension, size and file signature** (first 4 bytes, the "magic number") are checked
  before parsing. Size is checked twice: from the `Content-Length` header before reading,
  and while copying (a client can lie about or omit the header).
- The upload is saved under a **random name**; the client's filename is only cleaned and
  stored for display (`..\..\windows\system32\scan.pcap` becomes `scan.pcap`).
- The raw capture is **deleted right after analysis**; only metadata (counts, IPs, ports,
  flags, timings) is stored. Packet payloads are never stored or logged. A SHA-256 hash of the
  file is kept to recognise the same file uploaded twice.
- **SQL injection:** every user value goes through `?` placeholders; sort columns come from a
  whitelist. Parameters are also validated by type before reaching SQL (an IP must parse as an
  IP, a TCP state must be one of six values).
- Parsing errors return a generic 422; details stay in the server log.

## Storage

SQLite, 3 tables: `analyses` (one row per upload + JSON overview), `flows`, `alerts`
(foreign keys with `ON DELETE CASCADE`). Columns are `start_ts`/`end_ts` because `end` is
an SQL keyword; the API exposes them as `start`/`end`.

## Measured (2026-11-20)

`netsentinel serve` + `curl` upload of `lab/04_loopback_scan/scan.pcapng` (660 packets):
201 in 0.18 s, 200 flows, 1 alert (NS-001 high); fake capture and SQL-like IP filter -> 422;
no temporary file left.

## Limitations

- No authentication, no TLS, no rate limiting: local use only for now.
- Analysis is synchronous: a large capture blocks one worker thread until done (Scapy reads
  about 5 000 packets/s). A job queue would be the next step if uploads get large.
- Uploads sent without `Content-Length` (chunked) are fully received by the framework before
  the size check runs; a reverse proxy body limit is the real protection (Phase 7).
- Application log lines are not printed yet under `netsentinel serve` (logging is configured
  in Phase 7).
