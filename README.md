# NetScope AI — Network Security & Threat Monitoring Platform

> **Detect. Analyze. Replay.**

NetScope AI is a full-stack network traffic monitoring and intrusion detection system (NIDS) designed for Security Operations Centers (SOCs) and incident response investigators. It integrates a Python 3.12 FastAPI backend with a high-performance React 19 + TypeScript + Vite frontend.

---

## 🚀 Quick Start (Windows)

### Option 1: 1-Click Launch (Recommended)
Double-click **`run.bat`** in this folder. It will:
1. Verify Python 3.12 and Node.js environments.
2. Install Python dependencies (`backend/requirements.txt`) and Node packages if needed.
3. Launch the FastAPI backend on `http://127.0.0.1:8000`.
4. Launch the Vite frontend dev server on `http://localhost:5173` and open your default browser.

---

## 💻 Manual Setup & Execution

### 1. Prerequisites
- **Python**: Version 3.10+ (Python 3.12 recommended)
- **Node.js**: Version 18+ (Node 20+ recommended)
- *(Optional)* **Npcap**: For live promiscuous packet capture on Windows ([npcap.com](https://npcap.com/)). If Npcap or admin privileges are not present, the application automatically transitions to an explicitly labeled **Synthetic Demonstration Mode** while keeping 100% of offline PCAP analysis, replay, ML inference, and topology features fully functional.

### 2. Backend Setup
```bash
# 1. Activate Python environment
.venv\Scripts\activate   # Windows
# source .venv/bin/activate # macOS/Linux

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Start the FastAPI backend server
python backend/run_backend.py
```
The backend API runs at `http://127.0.0.1:8000` (Swagger docs at `http://127.0.0.1:8000/docs`).

### 3. Frontend Setup
In a new terminal:
```bash
# 1. Install Node dependencies
npm install

# 2. Start the Vite development server
npm run dev
```
Open `http://localhost:5173` in your browser. All API (`/api`) and WebSocket (`/ws`) requests are proxied directly to FastAPI.

---

## 🏗 Key Innovations & Architectural Components

### 1. Dedicated Notification Center (Phase 1)
- **Zero Toast Spam**: Eliminated repeating screen-obscuring toast stacks. Alerts are recorded in a dedicated SQLite `notifications` table.
- **Bell Icon & Live Badge**: Header bell with animated unread badge, accessible from any page.
- **Slide-Over SOC Drawer**: Inspect notifications with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), detection source (`RULE_ENGINE` vs `ML_ANOMALY`), timestamps, and endpoints.
- **Triage Actions**: Mark as read, mark all read, dismiss, clear read, and click-to-investigate.
- **Critical Alert Toast**: Only high-priority, deduplicated critical security alerts generate a brief, non-intrusive notification.

### 2. Dynamic Network Topology (Phase 2)
- **Evidence-Based Topology**: Built from actual observed traffic in uploaded PCAPs or live buffers — replacing fixed mock demonstration graphs.
- **Host Role Classification**: Assigns labels strictly based on traffic evidence:
  - `Confirmed Attacker`: Hosts matching deterministic attack rules (e.g. port scan, SYN flood).
  - `Suspicious Host`: Hosts generating statistical ML anomalies or elevated connection rates.
  - `Server`: Hosts listening on well-known ports (HTTP, HTTPS, SSH, DNS).
  - `Default Gateway`: Network router/gateway identified via broadcast or ARP.
  - `Workstation`: Internal client endpoints.
  - `Unknown`: Endpoints with insufficient observation.
- **Interactive SVG Canvas**: Zoom in/out, pan, reset view, role filtering, protocol filtering.
- **Node & Edge Inspection**: Click any host or link to inspect IP, MAC, bytes transferred, packet counts, open ports, protocols, and associated security findings.
- **Simulated Host Isolation**: SOC analysts can isolate compromised endpoints with simulated 802.1X quarantine.

### 3. Synchronized Attack Replay (Phase 3)
- **Chronological Packet & Flow Stream**: Replays real parsed packet sequences from analyzed PCAPs.
- **Interactive Playback Controls**: Play, pause, step forward, step backward, restart, timeline scrubber, and speed multiplier (`0.5x`, `1x`, `2x`, `4x`).
- **Synchronized Vector Animation**: Highlights active source and destination endpoints on an animated topological stage with transmission pulses.
- **Detection Trigger Highlighting**: Clearly marks the exact packet step (`isThreatTrigger: true`) where a rule threshold or ML anomaly score was breached.
- **Incident Brief**: Summarizes observed activity, involved hosts, time window, matched rules, ML findings, known evidence, and residual uncertainties.

### 4. Anomaly Detection & Explainability (Phase 4)
- **Dual-Source Detection**: Clearly distinguishes deterministic security rules from statistical machine learning anomalies.
- **Explainable Findings**: ML findings present anomaly scores, decision thresholds, and heuristic feature contributions (e.g., elevated flow byte rate, packet rate, asymmetric duration).
- **False-Positive Mitigation**: Deduplication windows and calibrated thresholds reduce noisy duplicate detections without suppressing distinct incidents.

### 5. Measurable & Reproducible ML Training (Phase 5 & Phase 6)
NetScope AI features an end-to-end ML pipeline trained on 56,661 curated network flows from the CIC-IDS2017 benchmark dataset across a 17-feature schema:

| Metric | Baseline Isolation Forest (v1.0.0) | Candidate HistGradientBoosting (v2.0.0) |
|---|---|---|
| **Model Type** | Unsupervised (Benign baseline) | Supervised Gradient Boosted Trees |
| **Split Strategy** | 70% Train / 30% Held-out Test | Stratified 60% Train / 15% Val / 25% Test |
| **Threshold Selection** | Fixed 0.50 | Validation-Tuned (0.50) |
| **Held-Out Test ROC-AUC** | **0.7154** | **0.9960** (+28.1%) |
| **Held-Out Test PR-AUC** | — | **0.9972** |
| **Held-Out Test Precision** | **0.9019** (90.2%) | **0.9681** (96.8%) |
| **Held-Out Test Recall** | **0.3659** (36.6%) | **0.9776** (97.8%) |
| **Held-Out Test F1-Score** | **0.5206** | **0.9728** (+45.2%) |
| **False Positive Rate (FPR)**| **0.0594** (5.9%) | **0.0480** (4.8%) |
| **Inference Latency** | ~15.2 µs / flow | ~9.4 µs / flow |
| **Artifact Size** | ~185 KB | ~385 KB |

#### Category-Specific Recall (HistGradientBoosting Held-Out Test Set):
- **PortScan**: 99.9% (791 / 792 detected)
- **DoS**: 99.4% (3,788 / 3,810 detected)
- **Web Attack**: 94.1% (352 / 374 detected)
- **Brute Force**: 90.3% (130 / 144 detected)
- **Botnet**: 88.2% (172 / 195 detected)
- **Infiltration**: 77.8% (7 / 9 detected)
- **Benign Baseline Specificity**: 95.2% (8,416 / 8,842 normal flows correctly classified as benign)

#### Model Management in UI (`/settings`):
- View active model metadata, held-out metrics, confusion matrix, and per-category recall.
- Hot-swap between **Baseline Isolation Forest** and **HistGradientBoosting** runtime artifacts with zero server restart.
- Trigger asynchronous background retraining via `POST /api/v1/system/ml/train` without blocking active packet capture.

---

## 🧪 Verification & Automated Testing

### Backend Unit & Integration Tests (32 Passing)
Run the full test suite with pytest:
```bash
python -m pytest backend/tests -v
```
Results: **32 passed in 9.85s (100% pass rate)**.
Covers:
- `test_notifications_endpoints`: Notification retrieval, unread count, read state, mark-all-read, dismiss.
- `test_dynamic_topology_endpoint`: Dynamic node and edge reconstruction from PCAP traffic and live buffers.
- `test_replay_and_scenario_ordering`: Chronological packet event ordering, trigger flagging, and scenario generation.
- `test_ml_performance_and_switching`: ML performance metrics, active model retrieval, dynamic model switching.
- `test_empty_and_malformed_pcap`: Robust error handling for corrupt and empty PCAPs.
- `test_rules.py`: Port scan, SYN flood, ARP spoof, ICMP flood, brute force detection rules.
- `test_ml_pipeline.py`: Feature schema validation, preprocessor NaN/Inf handling, model manager loading, fallback handling.

### Frontend Production Build
```bash
npm run build
```
Result: **Zero TypeScript errors, production bundle built in 3.94s (`dist/`)**.

---

## 🔒 Safe Passive Monitoring Principles

NetScope AI adheres strictly to non-intrusive SOC security standards:
- **Zero Active Probing**: Never transmits hostile packets or scans external networks.
- **Safe Isolation Simulation**: Switch port quarantine in the topology canvas is simulated for administrative drills without modifying operating system firewall rules.
- **Header-Only Inspection**: Flow features are extracted strictly from packet headers; payload contents are not retained.
