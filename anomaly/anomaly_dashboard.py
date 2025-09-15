import pandas as pd
import streamlit as st
import time
import os
import re
import matplotlib.pyplot as plt

LOG_FILE = "ids_logs.txt"  # IDS Log file path

# Function to parse logs
def load_logs():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame(columns=["Timestamp", "Label", "Probability"])  # Empty DataFrame
    
    data = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ - (.*?)$", line)
            if match:
                timestamp, message = match.groups()
                if "Anomaly detected" in message:
                    proba_match = re.search(r"Proba: ([0-9.]+)", message)
                    probability = float(proba_match.group(1)) if proba_match else None
                    data.append([timestamp, 1, probability])  # 1 = Anomaly
                else:
                    data.append([timestamp, 0, None])  # 0 = Normal
    
    df = pd.DataFrame(data, columns=["Timestamp", "Label", "Probability"])
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
    return df

# Streamlit UI
st.title("🚀 Real-Time IDS Anomaly Dashboard")
st.write("📡 Monitoring live IDS logs...")

# Main loop for live updates
while True:
    df = load_logs()  # Load latest logs

    # Display last 10 log entries
    st.subheader("📜 Latest Logs")
    st.dataframe(df.tail(10))

    # 📊 **Anomaly Detection Over Time (Scatter Plot)**
    st.subheader("📈 Anomaly Detection Over Time")
    fig, ax = plt.subplots(figsize=(12, 5))

    # Scatter plot with colors (0=Green, 1=Red)
    ax.scatter(df.loc[df["Label"] == 0, "Timestamp"], [0] * sum(df["Label"] == 0), 
               color='green', label="Normal (Green)", s=80, edgecolors='black')
    ax.scatter(df.loc[df["Label"] == 1, "Timestamp"], [1] * sum(df["Label"] == 1), 
               color='red', label="Anomaly (Red)", s=80, edgecolors='black')

    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Normal (0)", "Anomaly (1)"])
    ax.set_title("Anomaly Detection Over Time", fontsize=14, fontweight="bold")
    ax.set_xlabel("Timestamp", fontsize=12)
    ax.set_ylabel("Status", fontsize=12)
    ax.grid(True, linestyle="--", alpha=0.6)
    ax.legend()
    st.pyplot(fig)  # Show the updated plot

    # 📊 **Custom Colored Bar Chart**
    st.subheader("📊 Anomaly Count")

    label_counts = df["Label"].value_counts().sort_index()
    labels = ["Normal (0)", "Anomaly (1)"]
    colors = ["green", "red"]  # Custom colors

    fig_bar, ax_bar = plt.subplots()
    ax_bar.bar(labels, label_counts, color=colors)
    ax_bar.set_ylabel("Count")
    ax_bar.set_title("Anomaly vs. Normal Traffic")
    ax_bar.grid(axis="y", linestyle="--", alpha=0.6)

    st.pyplot(fig_bar)  # Show the bar chart

    # Show detected anomalies with probability
    anomalies = df[df["Label"] == 1]
    if not anomalies.empty:
        st.subheader("⚠️ Detected Anomalies")
        st.write(anomalies[["Timestamp", "Probability"]])

    time.sleep(2)  # Refresh every 2 seconds
    st.rerun()  # Force Streamlit to reload
