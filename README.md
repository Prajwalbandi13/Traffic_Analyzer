# Intelligent Network Traffic Analyzer Handbook

This repository contains a Flask-based network traffic monitoring and analysis system with a live operations dashboard, incident triage workflow, host inventory, packet inspection, and a historical reporting view.

This README is written as a handbook rather than a short project summary. Its goal is to explain:

- what the system does
- how the UI is organized
- how to use every UI component
- what happens behind the scenes when a user clicks something
- how packet capture, detection, storage, analytics, and reporting fit together

## 1. System Overview

At a high level, the application does five things:

1. Captures live packets from the local machine or network interface using Scapy.
2. Converts raw packets into structured records and stores them in SQLite.
3. Builds short-lived traffic flows and time-windowed feature vectors from stored packets.
4. Runs multiple detection layers:
   - rule-based detection
   - statistical anomaly detection
   - ML anomaly detection with Isolation Forest
5. Presents the results in a browser-based operational UI and a separate reporting page.

The application is designed around a backend-first model:

- the backend owns capture, storage, analysis, risk scoring, alert enrichment, and host profiling
- the frontend consumes JSON APIs and renders dashboards, details, and workflow actions

## 2. Main Screens

The product currently has two main browser pages:

1. `/`
   This is the live dashboard used for operations.

2. `/analysis`
   This is the historical reporting page used for summaries and trend review.

## 3. UI Handbook: Main Dashboard

The dashboard is intentionally split into four tabs to reduce overload:

- `Overview`
- `Incidents`
- `Hosts`
- `Packets`

The top header, control bar, filters, and KPI cards are shared across all tabs.

### 3.1 Header Area

The header shows:

- product title
- short description
- capture status panel

The capture status panel includes:

- status dot
  - greenish glow means capture is running
  - gray means capture is stopped
- status text
  - `Capturing` or `Stopped`
- packet count
  - total number of packets stored in the database
- started timestamp
  - when capture began

How it works:

- the frontend calls `/api/dashboard`
- the response includes `status`
- that data comes from `capture/controller.py`
- the packet count is read from SQLite using `get_packet_count()`

### 3.2 Control Toolbar

The main control bar has these buttons:

- `Start Capture`
- `Stop Capture`
- `Restart`
- `Clear History`
- `Run Live Analysis`
- `Reporting`

#### Start Capture

Purpose:
Starts background packet capture.

What the user sees:

- capture status changes to active
- packet count starts increasing as packets arrive

Backend flow:

1. UI sends `POST /api/start`
2. Flask calls `start_capture()`
3. `AsyncSniffer` starts in the background
4. every captured packet is sent to `process_packet()`

Important behavior:

- if capture is already running, the backend returns `started: false`
- the UI simply refreshes status and data

#### Stop Capture

Purpose:
Stops background packet capture.

What happens behind the scenes:

1. UI sends `POST /api/stop`
2. Flask calls `stop_capture()`
3. the sniffer is stopped
4. automatic ML training is triggered through `auto_train_ml_with_terminal_report()`

Why that matters:

- the user does not manually manage model training
- when a capture session ends, the backend tries to build/update the ML model from collected traffic features

#### Restart

Purpose:
Stops capture and starts it again.

Backend flow:

1. UI sends `POST /api/restart`
2. backend stops capture
3. backend optionally clears history if requested
4. backend starts capture again

Current UI behavior:

- restart does not clear history by default

#### Clear History

Purpose:
Removes stored packet history and alert history.

What it clears:

- `packets`
- `alerts`
- `traffic_features` when `clear_features=true`

What it does not clear:

- `host_profiles`

Why:

- packet and alert history are session-like operational data
- host metadata is treated as analyst-maintained context

#### Run Live Analysis

Purpose:
Runs full analysis immediately on currently stored traffic.

What it does:

- builds current flows
- runs rule-based detectors
- runs statistical detector
- builds feature windows
- persists features for ML
- automatically trains or refreshes the ML model if enough data exists
- runs ML anomaly detection on recent feature windows
- stores newly detected alerts
- recomputes risk score and live alert summary

Important distinction:

- the passive dashboard auto-refresh does not retrain ML every few seconds
- only explicit analysis flow uses backend auto-training

#### Reporting

Purpose:
Opens the historical reporting screen at `/analysis`.

### 3.3 Global Filters

The filter bar applies to the main dashboard data views.

Components:

- `Range`
- `Search`
- `Protocol`
- `Severity`
- `Alert Status`
- `Refresh`

#### Range

Controls how much recent history the dashboard uses.

Options:

- 30 min
- 1 hour
- 6 hours
- 24 hours

What it affects:

- summary cards
- alerts table
- host inventory
- packet table
- traffic timeline
- alert timeline
- protocol mix
- top domains

Backend behavior:

- sent as `range` query parameter to `/api/dashboard`
- minimum accepted value is 300 seconds

#### Search

Purpose:
Filters dashboard records by a free-text query.

Typical use cases:

- search by IP
- search by domain
- search by protocol name
- search by alert owner

How it works:

- debounce in frontend delays refresh slightly while typing
- query is passed to `/api/dashboard`
- backend uses SQL `LIKE` matching against relevant fields

#### Protocol

Purpose:
Filters packet results to a protocol.

Options:

- `All`
- `TCP`
- `UDP`
- `OTHER`

What it mainly affects:

- packet feed
- dashboard packet subset

#### Severity

Purpose:
Filters the incident queue by alert severity.

Options:

- `All`
- `High`
- `Medium`
- `Low`

#### Alert Status

Purpose:
Filters the incident queue by analyst workflow state.

Options:

- `All`
- `New`
- `Acknowledged`
- `Investigating`
- `Resolved`
- `False Positive`

#### Refresh

Purpose:
Manually refreshes all dashboard data.

Also note:

- the dashboard auto-refreshes every 5 seconds
- manual refresh is useful after user edits or if auto-refresh is temporarily behind

### 3.4 KPI Cards

The four KPI cards summarize the selected time range.

#### Live Risk

Displays:

- numeric risk score
- qualitative risk level

Source:

- generated by `analyze_current_flows()`

How it is computed:

- rule alerts contribute highest weight
- traffic spike alerts contribute medium influence
- ML anomalies contribute supportive influence
- score is capped differently depending on what kinds of alerts exist

Risk levels:

- `Low`
- `Moderate`
- `Elevated`
- `High`

#### Packets In Range

Displays:

- number of packets in selected range
- total bytes in selected range

Source:

- `fetch_dashboard_summary()`

#### Open Alerts

Displays:

- grouped incident count
- workflow breakdown summary

Source:

- alert count from `fetch_dashboard_summary()`
- workflow totals from `fetch_alert_status_breakdown()`

#### Hosts / Domains

Displays:

- host touch count
- unique domain count

Interpretation note:

- host touch count is based on distinct source plus distinct destination IP references in the packet set
- this is a high-level activity metric, not a deduplicated asset inventory

## 4. Tab Handbook: Overview

The `Overview` tab is the monitoring summary tab.

It contains:

- Traffic Trend
- Alert Trend
- Protocol Mix
- Top Domains

### 4.1 Traffic Trend

Purpose:
Shows how packet volume changes across time buckets.

Data source:

- `/api/dashboard`
- backend calls `fetch_traffic_timeline()`

How it works:

- packets are grouped into dynamic bucket sizes
- shorter ranges use smaller buckets
- longer ranges use larger buckets

Bucket logic:

- up to 1 hour: 60-second buckets
- up to 6 hours: 300-second buckets
- up to 24 hours: 900-second buckets
- beyond that: 3600-second buckets

The chart in the UI is rendered as horizontal bar rows rather than canvas charts.

### 4.2 Alert Trend

Purpose:
Shows how grouped alerts change over time.

Data source:

- `/api/dashboard`
- backend calls `fetch_alert_timeline()`

How it works:

- alerts are grouped by `last_seen` or `timestamp`
- bucket counts are returned
- severity subtotals are also computed in the backend

### 4.3 Protocol Mix

Purpose:
Shows which protocols dominate current traffic.

Data source:

- `fetch_protocol_mix()`

How it works:

- packets in the selected time range are grouped by protocol
- counts are displayed as compact horizontal bars

### 4.4 Top Domains

Purpose:
Shows the most active domains seen in recent traffic.

Data source:

- `fetch_top_domains()`

Where domain values come from:

- DNS answers
- DNS query names
- TLS SNI extraction
- HTTP `Host` header parsing
- QUIC/TLS handshake heuristics

Important note:

- domain names are best-effort enrichment
- not every packet will have a domain

## 5. Tab Handbook: Incidents

The `Incidents` tab is the operational triage workspace.

It contains:

- Incident Queue
- Alert Detail panel

### 5.1 Incident Queue

This table shows grouped alerts rather than raw detector outputs.

Columns:

- `Type`
- `Pair`
- `Severity`
- `Status`
- `Owner`
- `Events`
- `Last Seen`

What each column means:

- `Type`
  The detector label, such as `Possible Port Scan`.
- `Pair`
  Source IP to destination IP pair associated with the alert.
- `Severity`
  Backend-assigned priority.
- `Status`
  Analyst workflow state.
- `Owner`
  Analyst or team currently responsible.
- `Events`
  Number of grouped occurrences merged into the alert record.
- `Last Seen`
  Most recent time this grouped alert was observed.

How grouping works:

- alerts of the same type with the same `src_ip` and `dst_ip`
- within the configured lookback period
- and not already resolved or marked false positive
- are updated as one rolling incident instead of creating endless duplicates

### 5.2 Alert Detail Panel

When the user clicks a row in the incident table, the detail panel loads the full alert record.

Fields shown:

- Type
- First Seen
- Last Seen
- Events
- Reason
- What
- Likely Cause
- Impact
- editable Status
- editable Owner
- editable Notes
- editable Resolution

How it works:

1. user clicks an alert row
2. frontend calls `GET /api/alerts/<id>`
3. backend returns full alert record
4. panel is rendered
5. on save, frontend calls `PATCH /api/alerts/<id>`
6. backend updates workflow fields in SQLite

Practical workflow:

- move `new` alerts to `acknowledged` or `investigating`
- assign an owner
- store notes during analysis
- set a resolution before moving to `resolved`
- mark obvious benign cases as `false_positive`

## 6. Tab Handbook: Hosts

The `Hosts` tab is the asset-centric investigation workspace.

It contains:

- Host Inventory
- Host Detail panel

### 6.1 Host Inventory

This table is derived from packet activity and host profiles.

Columns:

- `Host`
- `Role`
- `Packets`
- `Peers`
- `Top Protocol`
- `Alerts`
- `Last Seen`

How the inventory is built:

- every packet contributes to both its source IP and destination IP
- per-host counters are assembled in memory
- packet counts, byte totals, peer sets, domains, and protocols are aggregated
- host profile metadata is merged in
- alert counts per host are merged in
- results are sorted primarily by alert count, then packet count

Role of host profiles:

- display name
- role
- owner
- notes
- allowlist flag

These values are analyst-maintained metadata stored in `host_profiles`.

### 6.2 Host Detail Panel

When the user selects a host, the detail panel loads:

- host summary
- editable metadata
- top peers
- top domains
- recent alerts tied to that host

Summary fields:

- packet count
- peer count
- total bytes
- last seen

Editable fields:

- Display Name
- Role
- Owner
- Notes
- Allowlist checkbox

How it works:

1. user clicks a host row
2. frontend calls `GET /api/hosts/<ip>`
3. backend builds host detail using packet history and profile data
4. user edits fields
5. frontend sends `PATCH /api/hosts/<ip>`
6. backend upserts the host profile into SQLite

Important note:

- allowlisting is currently stored and shown in UI metadata
- there is no detector suppression logic tied to allowlisting yet

## 7. Tab Handbook: Packets

The `Packets` tab is the raw drill-down table.

Columns:

- Time
- Domain
- Source
- Destination
- Protocol
- Src Port
- Dst Port
- Size

Purpose:

- inspect raw recent traffic records
- verify whether a suspicious pair actually appears in the packet stream
- correlate domains with IPs
- validate ports and protocols involved in an incident

How it works:

- frontend consumes the packet list returned by `/api/dashboard`
- backend gets data from `fetch_recent_packets()`
- SQL filters apply range, protocol, and search query

This view is best used after identifying something interesting in `Overview`, `Incidents`, or `Hosts`.

## 8. UI Handbook: Historical Reporting Page

The reporting page at `/analysis` is designed for summarized review rather than live triage.

It contains:

- Dashboard link
- Refresh Report button
- Copy Summary button
- Report Range selector
- KPI cards
- Executive Summary narrative
- Traffic Timeline
- Protocol Mix
- Top Alerts
- Top Hosts

### 8.1 Refresh Report

Purpose:
Rebuilds the report from current stored history.

Backend flow:

1. frontend calls `/api/report/summary?range=<seconds>`
2. backend assembles a report object using:
   - dashboard summary
   - status breakdown
   - top alerts
   - top hosts
   - traffic timeline
   - protocol mix
   - top domains

### 8.2 Copy Summary

Purpose:
Copies the generated narrative summary to the clipboard.

How it works:

- the frontend generates a text narrative from the report payload
- clicking the button copies that text via `navigator.clipboard.writeText`

### 8.3 Executive Summary

This is a plain-language narrative generated in the frontend from report values.

It combines:

- report window size
- packet count
- total bytes
- grouped incident count
- workflow state
- highest priority recent alert
- most active host

This is useful for quick handoff summaries or management updates.

### 8.4 Top Alerts and Top Hosts

These are simplified report tables.

They do not expose the full triage editing workflow. Instead, they provide a compact historical summary of:

- most important alert groups
- most active hosts in the selected report range

## 9. Backend Flow: End-to-End Data Pipeline

This is the full system flow from wire data to UI.

### 9.1 Packet Capture

Module:

- `backend/capture/live_capture.py`
- `backend/capture/controller.py`

Flow:

1. `start_capture()` starts `AsyncSniffer`
2. Scapy captures packets
3. each packet is passed to `process_packet()`

### 9.2 Packet Normalization

Inside `process_packet()`:

1. non-IP packets are ignored
2. DNS response parsing updates IP-to-domain mapping
3. TLS SNI extraction attempts to identify HTTPS hostnames
4. HTTP `Host` parsing attempts to identify plaintext HTTP hostnames
5. QUIC heuristics attempt to identify hostnames carried in QUIC/TLS handshake data
6. a structured packet record is built
7. packet is stored in SQLite
8. coordinated detection cycle may run

Structured packet fields:

- timestamp
- src_ip
- dst_ip
- protocol
- src_port
- dst_port
- size
- domain
- tcp_flags

### 9.3 Detection Cycle During Live Capture

After each stored packet, `run_detection_cycle()` may execute.

Important guardrail:

- it does not run on every packet in full
- it runs at most once per `TIME_WINDOW` unless forced

This avoids excessive re-analysis and duplicate spam.

### 9.4 Flow Building

Module:

- `backend/preprocessing/flow_builder.py`

How flows are defined:

- packets are grouped into 5-second windows
- key = `(src_ip, dst_ip, window_start)`

Flow stats include:

- packet count
- unique destination ports
- SYN count
- ACK count
- RST count
- start and end time

### 9.5 Rule-Based Detection

Module:

- `backend/detection/rule_based.py`

Implemented detectors:

- `Possible Port Scan`
  - triggered when unique destination ports in a flow reach at least 10
- `Possible DoS Burst`
  - triggered when packet count in a flow reaches at least 400
- `Repeated Failed Connections`
  - triggered by repeated SYN without ACK, or high RST count

Why this layer exists:

- fast
- interpretable
- useful for obvious operational patterns

### 9.6 Statistical Detection

Module:

- `backend/detection/statistical.py`

Implemented detector:

- `Traffic Spike`

Logic:

- compute average packet count across current flows
- require at least 5 flows to form a baseline
- flag flows above a minimum absolute threshold
- also require them to exceed average traffic by a multiplier

Why this layer exists:

- catches volume anomalies that are not explicit signatures

### 9.7 Feature Extraction for ML

Module:

- `backend/preprocessing/feature_extractor.py`

How it works:

- packets are grouped into 10-second windows
- each window becomes a numerical feature vector

Features include:

- packet count
- packet rate
- byte rate
- average packet size
- max packet size
- packet size variance
- unique source IPs
- unique destination IPs
- unique destination ports
- protocol counts and ratios
- TCP flag counts
- average inter-arrival time
- inter-arrival variance

These are stored in the `traffic_features` table.

### 9.8 ML Detection

Module:

- `backend/detection/ml_based.py`

Model:

- Isolation Forest

Training behavior:

- no user-facing train button exists now
- the backend auto-trains when analysis runs and enough samples exist
- capture stop also triggers a backend-side training pass

Minimum training data:

- 30 feature windows

ML outputs:

- anomaly alerts
- anomaly score
- top abnormal features based on z-score comparison
- weak-label evaluation against non-ML alert windows

Important limitation:

- the weak-label evaluation is not ground truth
- it is monitoring/diagnostic feedback, not a security benchmark

### 9.9 Alert Enrichment and Risk Scoring

Module:

- `backend/analysis/engine.py`

What happens after detectors run:

1. alerts are deduplicated in-memory per `(type, src_ip, dst_ip, time_window)`
2. alerts are enriched with:
   - what
   - possible causes
   - impact
   - where
3. recent alerts are filtered into the active window
4. risk score is computed
5. detector breakdown and threat insights are built

Threat insights summarize alert families by:

- type
- count
- explanation
- likely causes
- impact
- affected pair

### 9.10 Alert Storage and Grouping

Module:

- `backend/storage/database.py`

Alert records are grouped in SQLite to reduce noise.

Grouping behavior:

- match by alert type
- match by source and destination IP
- require recency within configured lookback
- do not group into already resolved or false-positive incidents

If a matching incident exists:

- severity is updated
- reason is updated
- `last_seen` is refreshed
- `event_count` increments

If not:

- a new alert row is inserted

### 9.11 Host Inventory and Reporting

The host and reporting features are built from stored packet and alert history rather than from live in-memory state.

That means:

- a page refresh does not lose the view
- report generation works over historical ranges
- host profiles survive packet/alert clearing

## 10. API Map

The UI is powered by these main endpoints:

- `GET /`
  Main dashboard HTML

- `GET /analysis`
  Reporting page HTML

- `GET /api/status`
  Capture state summary

- `POST /api/start`
  Start capture

- `POST /api/stop`
  Stop capture

- `POST /api/restart`
  Restart capture

- `POST /api/history/reset`
  Clear stored history

- `GET /api/packets`
  Packet list with filters

- `POST /api/analyze`
  Run explicit analysis and automatic ML training flow

- `GET /api/dashboard`
  Main dashboard data bundle

- `GET /api/alerts`
  Alert list

- `GET /api/alerts/<id>`
  Alert detail

- `PATCH /api/alerts/<id>`
  Update alert workflow fields

- `GET /api/hosts`
  Host inventory

- `GET /api/hosts/<ip>`
  Host detail

- `PATCH /api/hosts/<ip>`
  Update host profile

- `GET /api/trends`
  Trend-oriented data

- `GET /api/report/summary`
  Reporting payload

## 11. Database Model

The main SQLite database file is:

- `backend/storage/network_traffic.db`

Tables:

- `packets`
  Stores normalized packet records.

- `alerts`
  Stores grouped incidents plus triage metadata.

- `traffic_features`
  Stores per-window feature vectors for ML.

- `host_profiles`
  Stores analyst-curated metadata about hosts.

### 11.1 packets

Key fields:

- timestamp
- src_ip
- dst_ip
- protocol
- src_port
- dst_port
- size
- domain
- tcp_flags

### 11.2 alerts

Key fields:

- alert_type
- severity
- reason
- timestamp
- src_ip
- dst_ip
- time_window
- status
- owner
- notes
- resolution
- first_seen
- last_seen
- event_count
- what
- possible_causes
- impact

### 11.3 traffic_features

Stores numerical window features used by Isolation Forest.

### 11.4 host_profiles

Key fields:

- ip
- display_name
- role
- owner
- notes
- is_allowlisted
- updated_at

## 12. How the Frontend Works

Frontend files:

- `backend/web/templates/index.html`
- `backend/web/templates/analysis.html`
- `backend/web/static/app.js`
- `backend/web/static/analysis.js`
- `backend/web/static/styles.css`

The frontend is plain HTML, CSS, and JavaScript.

It does not use a frontend framework.

Main frontend patterns:

- `fetch()` for API calls
- DOM rendering via `innerHTML`
- periodic auto-refresh on the dashboard
- detail-on-click behavior for alerts and hosts
- lightweight client-side narrative generation for reporting

## 13. CLI Behavior

There is also a terminal entrypoint:

- `backend/main.py`

What it does:

- initializes the database
- runs `analyze_current_flows(store_alerts=True)`
- prints alert and risk summary to the terminal

This is useful for quick backend-only analysis runs without opening the web UI.

## 14. Typical User Workflows

### 14.1 Live Monitoring Workflow

1. Open the dashboard.
2. Click `Start Capture`.
3. Watch `Overview` for traffic and alert changes.
4. Use filters to narrow the time window or query specific IPs/domains.
5. Run `Run Live Analysis` when you want a full immediate analysis pass.

### 14.2 Incident Triage Workflow

1. Go to the `Incidents` tab.
2. Sort mentally by severity, ownership, and freshness.
3. Click an alert row.
4. Read `Reason`, `What`, `Likely Cause`, and `Impact`.
5. Set workflow status.
6. Add notes and resolution details.
7. Save the triage update.

### 14.3 Host Investigation Workflow

1. Go to the `Hosts` tab.
2. Select a host with high packet activity or alert count.
3. Review top peers and domains.
4. Assign a meaningful display name or role.
5. Add owner and notes.
6. Mark allowlisted if the host is a known trusted system.

### 14.4 Packet Drill-Down Workflow

1. Go to the `Packets` tab.
2. Search by IP or domain from a suspicious alert.
3. Use protocol filtering if needed.
4. inspect timestamps, ports, and directionality.

### 14.5 Reporting Workflow

1. Open `/analysis`.
2. Select the report range.
3. Click `Refresh Report`.
4. Review summary cards and executive summary.
5. Copy the narrative when you need a concise written summary.

## 15. Current Design Characteristics and Limitations

- The system stores packets before analyzing them, so dashboards and reports are history-driven.
- Domain enrichment is heuristic and best-effort.
- ML training depends on having enough feature windows.
- ML evaluation is weak-label based, not ground-truth validated.
- Host allowlisting is metadata only today; it does not yet suppress alerts.
- The charts are DOM-rendered bar views, not advanced interactive visualizations.
- There is no authentication or role-based access control in the current code.
- `backend/alerting/alerts.py` is currently empty and not part of the active flow.

## 16. Suggested Run Entry Points

The repository does not currently include a dependency or startup guide, so the commands below are based on the code structure.

Web UI:

```bash
python backend/web/app.py
```

Terminal-only analysis:

```bash
python backend/main.py
```

Likely runtime dependencies inferred from imports:

- Flask
- Scapy
- scikit-learn

## 17. File-by-File Reference

- `backend/web/app.py`
  Flask routes and API composition layer.

- `backend/web/templates/index.html`
  Main dashboard structure.

- `backend/web/templates/analysis.html`
  Historical reporting page structure.

- `backend/web/static/app.js`
  Dashboard behavior, rendering, refresh, and user actions.

- `backend/web/static/analysis.js`
  Reporting page behavior and narrative generation.

- `backend/web/static/styles.css`
  Shared UI styling.

- `backend/capture/controller.py`
  Start/stop/restart capture lifecycle.

- `backend/capture/live_capture.py`
  Packet normalization, domain enrichment, storage trigger, detection trigger.

- `backend/preprocessing/flow_builder.py`
  5-second flow construction.

- `backend/preprocessing/feature_extractor.py`
  10-second feature extraction for ML.

- `backend/detection/rule_based.py`
  Signature-like traffic heuristics.

- `backend/detection/statistical.py`
  Traffic spike detector.

- `backend/detection/ml_based.py`
  Isolation Forest training, loading, anomaly scoring, model metadata.

- `backend/analysis/engine.py`
  Detector coordination, enrichment, risk scoring, ML orchestration.

- `backend/storage/database.py`
  SQLite schema, inserts, queries, summaries, host inventory, reporting.

- `backend/main.py`
  terminal entrypoint.

## 18. Quick Mental Model

If you need to remember the whole project in one sentence:

The system captures packets, stores normalized traffic in SQLite, derives flows and features, detects suspicious behavior through rules, statistics, and ML, groups those detections into triage-friendly incidents, and exposes everything through a tabbed live dashboard plus a separate historical reporting screen.
