import sys
import os
import time

# ---------------- PATH FIX ----------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

LOG_PATH = os.path.join(BASE_DIR, "data", "auth.log")

import streamlit as st
import pandas as pd

from ingestion.log_parser import parse_auth_log
from detection.brute_force import detect_brute_force
from detection.suspicious_behavior import detect_suspicious_behavior
from detection.risk_scoring import calculate_risk_scores
from alerts.alert_manager import generate_alerts
from correlation.correlator import correlate_alerts
from analysis.timeline import generate_timeline

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Mini SIEM", layout="wide")

# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>
.block-container { padding-top: 1rem; }

.metric-card {
    background-color: #1c1f26;
    padding: 15px;
    border-radius: 10px;
    text-align: center;
}

.section {
    background-color: #1c1f26;
    padding: 15px;
    border-radius: 10px;
    margin-bottom: 15px;
}
</style>
""", unsafe_allow_html=True)

st.title("Security Monitoring Dashboard")

# ---------------- SIDEBAR ----------------
st.sidebar.header("Controls")
refresh_rate = st.sidebar.slider("Refresh Interval (seconds)", 1, 10, 2)

# ---------------- LOAD ----------------
logs = parse_auth_log(LOG_PATH)
logs_df = pd.DataFrame(logs)

# ---------------- DETECTION ----------------
brute_force_results = detect_brute_force(logs)
suspicious_results = detect_suspicious_behavior(logs)

# ---------------- RISK ENGINE ----------------
risk_scores = calculate_risk_scores(brute_force_results, suspicious_results)

# ---------------- ALERTS ----------------
alerts = generate_alerts(risk_scores)
alerts_df = pd.DataFrame(alerts)

# ---------------- CORRELATION ----------------
correlated_alerts = correlate_alerts(risk_scores)
correlated_df = pd.DataFrame(correlated_alerts)

# ---------------- FILTER ----------------
st.sidebar.header("Filters")

selected_ip = st.sidebar.selectbox(
    "Filter by IP",
    ["All"] + sorted(logs_df["ip"].unique().tolist())
)

if selected_ip != "All":
    logs_df = logs_df[logs_df["ip"] == selected_ip]
    alerts_df = alerts_df[alerts_df["ip"] == selected_ip]
    correlated_df = correlated_df[correlated_df["ip"] == selected_ip]

# ---------------- KPI ----------------
st.subheader("Overview")

col1, col2, col3 = st.columns(3)

col1.markdown(f"<div class='metric-card'>Logs<br><h2>{len(logs_df)}</h2></div>", unsafe_allow_html=True)
col2.markdown(f"<div class='metric-card'>Alerts<br><h2>{len(alerts_df)}</h2></div>", unsafe_allow_html=True)
col3.markdown(f"<div class='metric-card'>High Risk<br><h2>{len(correlated_df)}</h2></div>", unsafe_allow_html=True)

# ---------------- RISK RANKING ----------------
st.subheader("Top Threats (Risk Ranking)")

risk_data = [{"ip": ip, "risk_score": data["score"]} for ip, data in risk_scores.items()]
risk_df = pd.DataFrame(risk_data).sort_values(by="risk_score", ascending=False)

if not risk_df.empty:
    top_ip = risk_df.iloc[0]
    st.error(f"⚠️ Highest Risk: {top_ip['ip']} (Score: {top_ip['risk_score']})")

st.dataframe(risk_df, use_container_width=True)

# ---------------- CRITICAL INCIDENTS ----------------
st.subheader("High Priority Incidents")

if not correlated_df.empty:
    correlated_df = correlated_df.sort_values(by="risk_score", ascending=False)
    st.dataframe(correlated_df, use_container_width=True)
else:
    st.warning("No high-risk incidents detected")

# ---------------- TIMELINE ----------------
st.subheader("Attack Timeline Investigation")

if selected_ip == "All":
    st.info("Select an IP from the sidebar to investigate")
else:
    timeline_data = generate_timeline(logs_df.to_dict("records"), selected_ip)
    timeline_df = pd.DataFrame(timeline_data)

    if not timeline_df.empty:
        st.write(f"Activity for IP: {selected_ip}")
        st.dataframe(timeline_df, use_container_width=True)

        timeline_counts = timeline_df["timestamp"].value_counts().reset_index()
        timeline_counts.columns = ["timestamp", "count"]

        st.bar_chart(timeline_counts.set_index("timestamp"))
    else:
        st.info("No activity found")

# ---------------- ATTACK ANALYSIS ----------------
st.subheader("Failed Login Attempts by IP")

failed_logs = logs_df[logs_df["status"] == "Failed"]

if not failed_logs.empty:
    ip_counts = failed_logs["ip"].value_counts()
    st.bar_chart(ip_counts)

# ---------------- ALERTS ----------------
st.subheader("All Alerts")

if not alerts_df.empty:
    alerts_df = alerts_df.sort_values(by="risk_score", ascending=False)
    st.dataframe(alerts_df, use_container_width=True)

# ---------------- EXPORT ----------------
st.subheader("Export Alerts")

if not alerts_df.empty:
    csv = alerts_df.to_csv(index=False).encode("utf-8")
    st.download_button("Download Alerts as CSV", csv, "alerts.csv", "text/csv")

# ---------------- LOGS ----------------
st.subheader("Raw Logs")
st.dataframe(logs_df, use_container_width=True)

# ---------------- AUTO REFRESH ----------------
time.sleep(refresh_rate)
st.rerun()