# Dashboard

React 19 + TypeScript, built with Vite, charts with Recharts. Source in `frontend/`.

## Run it (development)

Two terminals, both from the repository root:

```powershell
# 1. API (Python venv active)
netsentinel serve
```

```powershell
# 2. Dashboard
cd frontend
npm install        # first time only
npm run dev        # http://localhost:5173
```

The dev server forwards `/api/*` to `http://127.0.0.1:8000`, so the browser talks to one
address only.

Other commands: `npm test` (Vitest), `npm run typecheck`, `npm run build` (static files in
`frontend/dist/`).

## Pages

| Page | What it shows | Screenshot |
|---|---|---|
| Overview | packets, flows, average/peak rate, alert count; traffic over time; protocol distribution; latest alerts; TCP states; most active hosts; top ports; top conversations; top DNS names | `docs/screenshots/overview_scan_dark.jpg`, `overview_web_light.jpg` |
| Traffic | flow table with filters (protocol, TCP state, IP, port, time window relative to capture start), sort by start / bytes / packets, pagination | `traffic_flows_by_bytes.jpg` |
| Alerts | alerts of the selected capture or all captures, filter by severity and rule; each alert opens to its evidence and the thresholds that fired; rule catalogue | `alerts_portscan_evidence.jpg` |
| Analyze a capture | upload with clear error messages (413 / 415 / 422), list of analyzed captures, select / delete | `upload_captures_light.jpg` |

## Design choices

- **One API module** (`src/api.ts`): pages never call `fetch` directly; HTTP errors become
  `ApiError` with the server's message, and "server not running" has its own message.
- **Selected capture** is shared app-wide (React context) and remembered in `localStorage`
  (wrapped in try/catch: private mode can block storage).
- **Colours** are CSS tokens for light and dark mode (follows the OS setting). Series colours
  come from a colour-blind-checked palette; severity uses reserved status colours and is
  always shown as **icon + text label**, never colour alone.
- **Rankings are HTML bars** with the name and value written next to each bar (readable
  without colour or hover). The traffic timeline has a hover crosshair and a
  "show as table" fallback. Silent intervals are filled with zeros so the line does not
  connect over gaps.
- Responsive: checked at 375 px wide (no horizontal page scroll; wide tables scroll inside
  their panel).

## Tests

`npm test`: 15 tests (format helpers, API client query building and error handling,
alert card rendering, upload error flow with a mocked server).

## Verified on 2026-11-22

API with a demo database + `npm run dev`, 6 captures uploaded (the 5 lab captures and the
synthetic UDP flood): all four pages loaded real data in the browser, light and dark mode,
375 px width. Found and fixed during this run:

- **HTTP 500 on the overview**: under uvicorn, FastAPI opened the SQLite connection in one
  worker thread and closed it in another (`sqlite3.ProgrammingError`). TestClient did not
  show it. Fixed with `check_same_thread=False` (each connection still serves one request);
  regression test added; 60 consecutive requests then returned 0 errors.
- Timeline axis showed `+-0.3 s` (a time bucket can start just before the first packet).

## Known limitations

- Production bundle is 695 kB (205 kB gzipped), mostly Recharts; Vite warns above 500 kB.
  Code-splitting the Overview page would fix it if load time matters.
- Synthetic scenarios use timestamps around 1 000 s after 1970, so their alerts show 1970 dates.
- Very long captures: the timeline is only densified up to 2 000 intervals; beyond that only
  non-empty intervals are drawn.
- No authentication (same as the API: local use only).
