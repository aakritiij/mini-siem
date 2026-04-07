# Mini SIEM - Security Monitoring & Threat Detection System

A Python-based Mini SIEM (Security Information and Event Management) system that simulates real-world SOC (Security Operations Center) workflows including log ingestion, threat detection, risk scoring, and attack investigation.

---

## 🚀 Features

### 🔹 Log Ingestion
- Parses raw Linux SSH authentication logs (`auth.log`)
- Converts unstructured logs into structured security events

### 🔹 Threat Detection
- Brute force attack detection (multiple failed login attempts)
- Suspicious behavior detection (multiple username attempts)

### 🔹 Risk Scoring Engine
- Assigns dynamic risk scores based on multiple behavioral indicators
- Replaces static severity with intelligent prioritization

### 🔹 Event Correlation
- Aggregates multiple signals into high-confidence security incidents
- Reduces alert noise

### 🔹 Attack Timeline (Investigation Feature)
- Reconstructs attacker activity for a given IP
- Helps analyze behavior patterns over time

### 🔹 Interactive Dashboard
- Built using Streamlit
- Displays logs, alerts, risk rankings, and critical incidents
- Supports filtering and CSV export

### 🔹 Near Real-Time Monitoring
- Simulates real-time log processing using periodic refresh

---

## 🧠 Architecture
Log Ingestion → Detection → Risk Scoring → Correlation → Dashboard → Investigation


---

## 🛠️ Tech Stack

- Python
- Pandas
- Streamlit
- Regex (log parsing)

---

## 📂 Project Structure

mini-siem/
│
├── ingestion/ # Log parsing
├── detection/ # Detection rules + risk scoring
├── alerts/ # Alert generation
├── correlation/ # Event correlation
├── analysis/ # Timeline investigation
├── dashboard/ # Streamlit UI
├── data/ # Sample logs
│
├── main.py
└── requirements.txt


---

## ⚙️ How to Run

### 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/mini-siem.git

cd mini-siem

### 2. Install dependencies
pip install -r requirements.txt

### 3. Run the dashboard
streamlit run dashboard/app.py


---

## 📊 Key Highlights

- Implements risk-based threat prioritization instead of static severity
- Supports investigation through attack timeline reconstruction
- Simulates real SOC workflows in a simplified environment

---

## 🔍 Future Improvements

- Threat intelligence integration (IP reputation APIs)
- Real-time streaming using Kafka or sockets
- Anomaly detection using behavioral baselines

---

## 👩‍💻 Author

Aakriti Jaketia
