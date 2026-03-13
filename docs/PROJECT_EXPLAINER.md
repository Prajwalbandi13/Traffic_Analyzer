# Traffic Analyzer Project Explainer

## 1. What this product is

This project is an intelligent network traffic monitoring and analysis system. It captures live packets from the machine or network interface, stores normalized traffic records in SQLite, analyzes the captured data with multiple detection layers, groups suspicious findings into manageable incidents, and exposes the results through a Flask dashboard and reporting UI.

At a practical level, it is a network detection and investigation tool.

It helps answer questions like:

- What traffic is happening right now?
- Which hosts are most active?
- Which domains are being contacted?
- Is any host scanning ports?
- Is there burst traffic that looks like denial-of-service behavior?
- Are there repeated failed connections that suggest brute force or blocked access attempts?
- Is the current traffic pattern unusual compared to previously observed windows?

The codebase does not currently implement automatic traffic blocking, host quarantine, or firewall enforcement. So this is primarily a detect, explain, triage, and report product rather than a prevention product.

## 2. Why we need this product

Modern networks produce too much traffic for a human to inspect manually. Looking at raw packets one by one is slow, noisy, and hard to scale. This product helps by turning raw traffic into operationally useful views.

It is needed for several reasons:

- To provide visibility into real network activity.
- To detect suspicious patterns early.
- To give security or operations teams a usable incident queue instead of raw packet spam.
- To preserve historical data so investigations are not lost on refresh.
- To create summaries and reports for operations, handoffs, and review.
- To surface unknown or unusual behavior through anomaly detection even when no simple signature exists.

In short, the product reduces blind spots and turns network telemetry into actionable investigation data.

## 3. End-to-end architecture and flow

The complete flow is:

1. Live capture starts.
2. Packets are captured using Scapy.
3. Each packet is normalized into structured fields.
4. Best-effort domain enrichment is attempted.
5. The packet record is stored in SQLite.
6. Packets are grouped into short-lived flows.
7. Feature windows are built for machine learning.
8. Rule-based, statistical, and ML detectors run.
9. Detections are enriched with human-readable explanations.
10. Alerts are deduplicated and grouped into incidents.
11. A risk score is calculated.
12. The Flask API sends the data to the dashboard and reporting pages.

## 4. Detailed module flow

### 4.1 Capture lifecycle

The live capture controller manages when sniffing starts and stops.

- `capture/controller.py`
  - starts `AsyncSniffer`
  - stops it safely
  - reports running state and packet count
  - triggers automatic ML training when capture stops

When capture starts, Scapy runs in the background and forwards each observed packet to `process_packet()`.

### 4.2 Packet normalization

Raw packets are handled in `capture/live_capture.py`.

This module:

- ignores non-IP packets
- extracts source and destination IPs
- extracts protocol, source port, destination port, size, and TCP flags
- tries to enrich traffic with domain names
- stores the structured packet record in SQLite
- periodically triggers detection

### 4.3 Domain enrichment and protocol-aware parsing

The system tries to make network records more human-readable by attaching domain names to traffic.

It uses several methods:

- DNS response parsing
  - maps returned IP addresses back to domain names
- TLS SNI extraction
  - reads the Server Name Indication from a TLS ClientHello
- HTTP Host parsing
  - reads the `Host` header for plaintext HTTP traffic
- QUIC/TLS heuristics
  - attempts to infer hostnames from QUIC handshake data

This is useful because investigators often think in terms of domains rather than raw IPs.

Important limitation:

- This is best-effort enrichment, not guaranteed attribution.
- Encrypted payload content is not decrypted.
- Some traffic will remain IP-only.

### 4.4 Storage layer

All persistent data lives in `storage/network_traffic.db`.

The main tables are:

- `packets`
  - normalized packet records
- `alerts`
  - grouped incidents and analyst workflow fields
- `traffic_features`
  - numerical per-window features for ML
- `host_profiles`
  - analyst-maintained metadata such as display name, role, owner, notes, and allowlist status

This design is useful because the UI is history-driven rather than purely in-memory.

That means:

- page refresh does not lose context
- reports can be built from stored history
- host metadata survives packet clearing

### 4.5 Flow building

The project does not run detection directly on individual packets. Instead, it first groups traffic into short windows in `preprocessing/flow_builder.py`.

Current flow design:

- packets are bucketed into 5-second windows
- a flow key is `(src_ip, dst_ip, window_start)`

Each flow tracks:

- packet count
- unique destination ports
- SYN count
- ACK count
- RST count
- start and end time

This gives detectors a summarized view of behavior rather than isolated packet events.

### 4.6 Feature extraction for ML

In `preprocessing/feature_extractor.py`, packets are also grouped into 10-second windows to create machine learning features.

Each feature window includes:

- packet count
- packet rate
- byte rate
- average packet size
- max packet size
- packet size variance
- unique source IPs
- unique destination IPs
- unique destination ports
- TCP count
- UDP count
- ICMP count
- TCP ratio
- UDP ratio
- ICMP ratio
- SYN count
- ACK count
- FIN count
- RST count
- average inter-arrival time
- inter-arrival variance

These are stored in `traffic_features` and later used for model training and anomaly scoring.

### 4.7 Detection engine

`analysis/engine.py` coordinates the entire analysis layer.

It performs four important jobs:

- runs detectors
- enriches alerts with human-readable explanations
- deduplicates alerts
- calculates a risk score and threat insights

It also controls ML orchestration such as auto-training and anomaly evaluation.

## 5. What threats the system identifies

The project is currently built to identify these categories:

### 5.1 Port scanning

Rule: if a source contacts many different destination ports in the same short window, the system raises `Possible Port Scan`.

Current threshold:

- 10 or more unique destination ports in a 5-second flow window

Why it matters:

- reconnaissance is often the first step before exploitation
- attackers scan to discover exposed services

### 5.2 DoS burst behavior

Rule: if a flow sees a very large number of packets in a short time, the system raises `Possible DoS Burst`.

Current threshold:

- 400 or more packets in a 5-second flow window

Why it matters:

- can indicate flooding
- can degrade availability
- can also reveal retry storms or malfunctioning systems

### 5.3 Repeated failed connections

Rule: if many SYN packets appear without ACKs, or there are many RST packets, the system raises `Repeated Failed Connections`.

Current thresholds:

- 30 or more SYN packets with no ACK in a 5-second window
- 20 or more RST packets in a 5-second window

Why it matters:

- may indicate brute-force behavior
- may indicate blocked or unreachable services
- may reveal firewall rejection or unstable systems

### 5.4 Traffic spikes

Statistical detector logic:

- requires at least 5 flows to establish a baseline
- computes average packet count across current flows
- flags flows that are both:
  - at least 60 packets
  - more than 3 times the flow average

Why it matters:

- catches abnormal volume shifts not captured by simple rules
- helps surface suspicious bursts, transfers, or abnormal surges

### 5.5 ML anomalies

The ML detector flags behavior windows that differ from the learned normal pattern.

Why it matters:

- not all suspicious activity matches a simple threshold
- some threats look like combinations of subtle feature shifts
- anomaly detection can surface rare patterns even without explicit signatures

## 6. What threats are being nullified versus only identified

This is an important distinction.

What the current product does well:

- identifies suspicious traffic behavior
- groups repeated detections into incidents
- supports investigation with context
- preserves history
- helps prioritize with risk scoring

What it does not currently do:

- automatically block malicious traffic
- modify firewall rules
- isolate hosts
- terminate sockets
- revoke access
- suppress allowlisted hosts at detector level

So the threats are mostly being:

- identified
- surfaced
- explained
- tracked

They are not automatically nullified by the current code.

If the product were extended later, it could integrate with:

- firewalls
- IDS/IPS tools
- SIEM platforms
- SOAR playbooks
- ticketing systems
- notification systems like Slack or email

But those integrations are not implemented in the current repository.

## 7. Integrations in the current code

There are two kinds of integrations in this project: runtime integrations and architectural integrations.

### 7.1 Runtime integrations already present

- Scapy
  - used for live packet capture
  - core integration for packet collection
- Flask
  - used to expose web pages and JSON APIs
- SQLite
  - persistent local datastore
- scikit-learn
  - used for the Isolation Forest ML model

### 7.2 Architectural integrations across modules

The modules are internally integrated in a clear pipeline:

- capture layer integrates with analysis by calling the detection cycle
- preprocessing integrates with detection by creating flows and feature windows
- storage integrates with all layers by persisting packets, features, alerts, and profiles
- web API integrates with analysis and storage to expose the dashboard and reporting pages

### 7.3 Missing external integrations

Currently absent:

- no authentication provider integration
- no SIEM export
- no email or Slack alerting
- no webhook pipeline
- no firewall or NAC integration
- no cloud logging integration
- no packet broker integration

There is an `alerting/alerts.py` file, but it is not active in the current flow.

## 8. Machine learning in detail

### 8.1 Why there is an ML layer at all

Rule-based logic is great when we already know what suspicious behavior looks like. But real network behavior is messy. Some harmful or abnormal activity may not look like a simple threshold breach.

Examples:

- unusual combinations of protocols
- odd packet-size patterns
- strange timing behavior
- unexpected host diversity in a short window
- bursts that are not quite large enough to trip a hard-coded rule

The ML layer exists to complement rules and statistics, not replace them.

That design choice is visible in the risk logic:

- rule-based alerts have highest weight
- statistical alerts have meaningful but lower influence
- ML alerts are treated as supportive evidence unless corroborated

This is a healthy design because anomaly detectors can produce false positives if used alone.

### 8.2 Why Isolation Forest was chosen

The model in use is `IsolationForest`.

This choice makes sense for the current project because:

- the dataset is unsupervised
  - there is no strong labeled dataset of normal vs attack traffic in the repo
- anomaly detection fits the goal better than classification
  - we want to learn normal behavior and spot outliers
- it works reasonably well on tabular numerical features
- it is easy to train locally
- it is available in scikit-learn
- it does not require deep learning infrastructure
- it can perform well on small-to-medium datasets
- it is simple to persist as a pickle and reload in the Flask app

Why not a supervised classifier?

- there is no ground-truth labeled training dataset in the project
- supervised models would need labeled attack classes
- maintaining those labels would add significant data engineering overhead

Why not deep learning?

- too heavy for this project stage
- harder to explain
- more training complexity
- unnecessary for the current feature scale

So Isolation Forest is a practical, lightweight, unsupervised anomaly detector for this architecture.

### 8.3 How Isolation Forest works conceptually

Isolation Forest works by randomly partitioning feature space. Anomalies are easier to isolate than normal points because they are rarer and more different, so they tend to end up separated with fewer splits.

That means:

- normal windows tend to blend into the larger population
- abnormal windows get isolated quickly

The model returns:

- a prediction
  - `-1` means anomaly
  - `1` means normal
- an anomaly score
  - lower values are more suspicious

### 8.4 What data the ML model trains on

The model is trained on rows from the `traffic_features` table.

Each row represents a 10-second traffic window summarized into numerical features.

So the model does not see raw packets directly.

It sees structured statistics such as:

- volume
- rates
- protocol mix
- TCP flag patterns
- port diversity
- host diversity
- timing irregularity

This is the correct pattern for classical tabular ML on network telemetry.

### 8.5 Exactly how training happens

Training logic lives in `detection/ml_based.py`.

The training process is:

1. Fetch feature rows from SQLite.
2. Check whether scikit-learn is installed.
3. Check whether there are enough training samples.
4. Convert feature rows into a numerical matrix.
5. Create an Isolation Forest model.
6. Fit the model on all available feature rows.
7. Compute weak-label evaluation metrics if possible.
8. Save the model and metadata as a pickle file.

Current training settings:

- minimum samples: 30
- estimator count: 120 trees
- contamination: 0.1
- random state: 42

These settings come directly from the code.

Interpretation:

- `MIN_TRAIN_SAMPLES = 30`
  - the model will not train unless at least 30 feature windows exist
- `n_estimators = 120`
  - the forest uses 120 trees
- `contamination = 0.1`
  - the model assumes roughly 10 percent of samples may be anomalous
- `random_state = 42`
  - training is reproducible

### 8.6 When training happens

Training is backend-driven and mostly automatic.

It can happen in two ways:

1. During an explicit analysis run
   - `analyze_current_flows(store_alerts=True)` can persist features and auto-train if enough samples exist

2. When live capture stops
   - `stop_capture()` triggers `auto_train_ml_with_terminal_report()`

This means the user does not manually operate a train button in the current UI.

### 8.7 How inference happens

After training:

- the model is loaded from `detection/models/isolation_forest.pkl`
- recent feature rows are selected
- the most recent 12 windows are evaluated
- anomalous rows become `ML Anomaly (Isolation Forest)` alerts

Each ML alert currently contains:

- type
- severity
- reason with anomaly score
- time window
- top abnormal features

One limitation:

- ML alerts do not currently map back to a specific `src_ip` and `dst_ip`
- they use `N/A` for those fields because the model runs on time-window aggregates, not per-flow identity

### 8.8 How the system explains ML alerts

The code computes the top abnormal features by z-score comparison against the evaluated rows.

This gives human-readable clues such as:

- packet count was unusually high
- unique destination ports were unusually high
- byte rate or inter-arrival behavior was unusual

This makes the model more explainable than a raw anomaly flag alone.

### 8.9 ML evaluation in the current system

The project tries to evaluate the ML model, but the evaluation is weak-label based.

This means:

- it uses existing non-ML alert windows as proxy labels
- these proxy labels are not true ground truth

The computed metrics can include:

- precision
- recall
- F1 score
- support

This is useful for monitoring model behavior, but it is not enough to claim real-world security accuracy.

So the honest interpretation is:

- useful diagnostic signal
- not a benchmark-grade validation

## 9. Training, testing, and validation

### 9.1 Current training state

The training path exists and works conceptually, but it is still lightweight.

Strengths:

- automated
- local
- reproducible
- integrated into capture and analysis flow
- stores metadata with the model

Limitations:

- no train/validation/test split
- no versioned training datasets
- no explicit concept drift handling
- no periodic retraining scheduler beyond current triggers
- no robust experiment tracking
- no true labeled evaluation

### 9.2 Current testing state

There do not appear to be automated tests in the repository.

That means several parts should ideally be tested but currently are not verified by a test suite:

- packet normalization correctness
- DNS/SNI/HTTP/QUIC enrichment logic
- flow construction
- rule threshold behavior
- statistical detector baselines
- ML training skip/train behavior
- model persistence and reload
- database grouping logic
- API responses and filtering
- host inventory aggregation

### 9.3 What should be tested next

Recommended tests:

- unit tests for rule-based detectors
- unit tests for feature extraction output
- unit tests for alert grouping and deduplication
- API tests for Flask endpoints
- integration tests for packet -> database -> analysis -> alert flow
- ML tests for:
  - insufficient sample handling
  - successful model save/load
  - anomaly result schema

### 9.4 How to think about model quality here

In this project, ML should be viewed as:

- a secondary detector
- a behavior outlier signal
- an investigator aid

It should not yet be marketed as:

- highly accurate attack classification
- validated threat intelligence
- autonomous decision-maker

That is why the risk scoring code treats ML as supportive rather than dominant.

## 10. Risk scoring and triage

The engine builds a risk score from recent alerts.

Broad logic:

- rule-based alerts add the strongest weight
- traffic spikes add moderate weight
- ML anomalies add small supportive weight
- final score is capped depending on which alert families are present

The result is mapped to:

- Low
- Moderate
- Elevated
- High

This helps analysts avoid reading every alert as equally important.

## 11. Incidents, grouping, and workflow

The system avoids endless duplicate alerts by grouping incidents in SQLite.

Alerts are grouped when they match on:

- alert type
- source IP
- destination IP
- recent lookback period
- unresolved workflow state

Instead of inserting a new row every time, the existing incident gets:

- updated severity and reason
- refreshed last seen time
- incremented event count

This is operationally valuable because it reduces alert fatigue.

The UI also allows workflow management:

- new
- acknowledged
- investigating
- resolved
- false positive

Plus:

- owner
- notes
- resolution

That turns the tool into an incident triage workspace rather than a raw detector console.

## 12. Host view and reporting

The project also gives an asset-centric view of the network.

For each host, the system can summarize:

- packet count
- byte volume
- peers
- protocol mix
- top domains
- alerts related to that host

This is useful because investigations often begin with:

- which host is noisy?
- which host is talking to many peers?
- which host triggered alerts?

The reporting page provides a broader historical summary for operational review and handoff.

## 13. Current limitations and risks

The codebase has several honest limitations:

- no automatic prevention
- no authentication or RBAC on the web UI
- best-effort domain enrichment only
- ML is weakly evaluated
- no full external integrations
- host allowlisting is metadata only
- no automated tests in repo
- ML anomalies are not mapped to specific host pairs
- features are derived from packet history already stored, not streamed into a high-scale pipeline
- SQLite is fine for local or demo-scale use but not ideal for large production telemetry volumes

## 14. Why the design still makes sense

Despite the limitations, the design is reasonable for a practical project because it shows a clear layered detection strategy:

- packet visibility
- structured storage
- interpretable rules
- baseline-aware statistics
- unsupervised anomaly detection
- risk scoring
- incident grouping
- analyst workflow

That combination is much stronger than having only one detector type.

Rules catch obvious patterns.
Statistics catch contextual volume shifts.
ML catches unusual combinations and outliers.

Together, they produce better operational visibility than any one layer alone.

## 15. Simple summary

If we reduce the whole project to one compact explanation:

This product watches live network traffic, converts raw packets into structured history, analyzes them using rules, statistics, and machine learning, groups suspicious findings into incidents, scores the current level of risk, and presents everything in a dashboard so a human can investigate faster and more effectively.

And if we reduce the ML part to one compact explanation:

The model is an unsupervised Isolation Forest trained on 10-second traffic feature windows stored in SQLite. It learns what normal traffic usually looks like, then flags recent windows that are unusually different. It is used as a supporting anomaly signal, not as the sole decision-maker.
