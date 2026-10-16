import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="Cybersecurity Log Analyzer",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Cybersecurity Log Analyzer")
st.caption("Security Monitoring Dashboard")

# Load the security report
try:
    alerts = pd.read_csv("reports/alerts.csv")
except FileNotFoundError:
    st.error("Report not found. Run analyzer.py first.")
    st.stop()

# Summary metrics
total_alerts = len(alerts)
high_alerts = len(alerts[alerts["Severity"] == "HIGH"])
medium_alerts = len(alerts[alerts["Severity"] == "MEDIUM"])

col1, col2, col3 = st.columns(3)

col1.metric("Total Alerts", total_alerts)
col2.metric("High Severity", high_alerts)
col3.metric("Medium Severity", medium_alerts)

st.divider()

# Filter alerts
st.subheader("🚨 Security Alerts")

if not alerts.empty:
    severities = alerts["Severity"].unique().tolist()

    selected_severity = st.selectbox(
        "Filter by Severity",
        ["All"] + severities
    )

    if selected_severity != "All":
        filtered_alerts = alerts[
            alerts["Severity"] == selected_severity
        ]
    else:
        filtered_alerts = alerts

    st.dataframe(
        filtered_alerts,
        use_container_width=True,
        hide_index=True
    )

    st.subheader("📊 Alerts by Severity")

    severity_counts = alerts["Severity"].value_counts()
    st.bar_chart(severity_counts)

else:
    st.success("No suspicious activity detected.")