# Mini SIEM System (Python)

A practical, real-world inspired Security Information and Event Management (SIEM) system built using Python.

This project simulates how a Security Operations Center (SOC) monitors logs, detects threats, prioritizes incidents, and investigates suspicious activity.

---

## 🚀 Why this project?

Most beginner SIEM projects stop at basic log parsing and detection.

This system goes further by focusing on:
- realistic log handling
- intelligent alerting
- risk-based prioritization
- analyst investigation workflow

---

## 🧠 Key Features

### 1. Log Ingestion & Parsing
- Parses raw authentication logs (SSH logs)
- Extracts structured fields: timestamp, IP, user, status

### 2. Log Normalization
- Handles inconsistent log formats
- Prepares data for reliable detection
- Improves robustness against messy real-world logs

### 3. Threat Detection
- Brute force attack detection (multiple failed logins)
- Suspicious behavior detection (multiple usernames per IP)

### 4. Time-Based Anomaly Detection
- Detects rapid login bursts within short time windows
- Identifies automated attack patterns

### 5. Threat Intelligence Integration
- Uses AbuseIPDB API to enrich IP reputation
- Includes caching to avoid excessive API calls

### 6. Risk Scoring Engine
- Combines:
  - behavior (failed attempts)
  - anomalies (burst activity)
  - threat intelligence
- Produces a unified risk score per IP

### 7. Alert Generation & Deduplication
- Generates alerts based on risk score
- Deduplicates alerts to reduce noise
- Merges repeated signals into a single actionable alert

### 8. Event Correlation
- Combines multiple weak signals into high-confidence incidents

### 9. Analyst Investigation Layer
- Add and store investigation notes per IP
- Simulates real SOC analyst workflow

### 10. Incident-Centric Dashboard (Streamlit)
- Risk-based ranking of threats
- Focused incident investigation view
- Timeline analysis of attacks
- Alert and log visualization
- CSV export for alerts

---

## 🏗️ Project Structure
mini-siem/
│
├── ingestion/ # Log parsing
├── detection/ # Detection logic (brute force, suspicious, risk scoring)
├── analysis/ # Timeline & anomaly detection
├── alerts/ # Alert generation & deduplication
├── correlation/ # Event correlation
├── utils/ # Helpers (normalization, threat intel, notes)
├── dashboard/ # Streamlit dashboard
│
├── data/ # Log files & notes storage
├── main.py # CLI execution
├── requirements.txt
└── README.md


---

## ⚙️ Installation

```bash
git clone https://github.com/aakritiij/mini-siem.git
cd mini-siem

pip install -r requirements.txt

▶️ Running the Project
Run backend analysis:
python main.py
Run dashboard:
streamlit run dashboard/app.py
