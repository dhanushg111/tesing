# Browser-Based DLP Platform (Centralized Policy Control) – v1.0.1

This repository provides an MVP foundation for a centralized browser DLP platform with three major building blocks:

1. **Central Server (Backend API)** for policy management, user/device registration, event ingestion, metrics, and alert retrieval.
2. **Browser Extension Agent** (WebExtensions-style) for polling policies, monitoring browser actions, enforcing rules, and retrying log delivery.
3. **Admin Dashboard** for login, policy CRUD, alert monitoring, and platform metrics.

## Architecture

```text
Dashboard (admin)  -> Backend API -> In-memory store (replace with PostgreSQL)
Extension agents   -> Backend API -> Policies / Events / Alerts / Metrics
```

## Current MVP Scope

- Policy management APIs (`GET/POST/PUT/DELETE /api/policies`)
- Auth with signed token + expiry (`POST /api/auth/login`)
- Device registration (`POST /api/devices/register`)
- Policy polling for extension (`GET /api/extension/policies`)
- Event ingestion with detection + enforcement decision (`POST /api/events`)
- Alert retrieval (`GET /api/alerts`)
- Metrics endpoint (`GET /api/metrics`)
- Dashboard policy + alert + metrics views
- Extension hooks for paste/input/upload monitoring

## Project Structure

- `backend/server.js` – Express API and policy/event logic
- `shared/detection.js` – reusable data detection engine
- `extension/` – browser extension files (`manifest.json`, `background.js`, `content.js`, `popup.html`, `popup.js`)
- `dashboard/` – admin UI (`index.html`, `app.js`, `styles.css`)

## Quick Start

```bash
npm install
npm run start
```

By default the backend now binds to `127.0.0.1` for local-only testing (override with `HOST`).

```bash
HOST=127.0.0.1 npm run start
```

In a second terminal, serve the dashboard:

```bash
python3 -m http.server 8080
```

- Open dashboard at: `http://localhost:8080/dashboard/`
- Login with seeded admin credentials:
  - username: `admin`
  - password: `admin123`
- Load the extension folder `extension/` in Chrome/Edge/Firefox developer mode.
- In extension popup, set API base + login to register device and enable policy/event flows.

## Security + NFR Alignment (MVP)

- Signed token with expiry validation
- Input validation for policy/event payloads
- Extension retry logic for event submission
- Extension polling interval centrally controlled by server response
- Debounced input monitoring to reduce browser overhead

## Enterprise Hardening Next

- move users/policies/devices/events to PostgreSQL
- replace custom token signer with production JWT library + rotation
- add RBAC and immutable audit retention
- add WebSocket/SSE push for near real-time policy/alert delivery
- add tamper protections and extension health attestations
