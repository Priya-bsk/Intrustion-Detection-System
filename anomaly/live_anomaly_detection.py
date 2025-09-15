import scapy.all as scapy
from scapy.layers.inet import IP, TCP
import joblib
import numpy as np
import warnings
import logging
import threading
import time
from collections import deque
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score
import pandas as pd

import os

LOG_FILE = "logs.csv"
# Create the log file with headers if it doesn't exist
if not os.path.exists(LOG_FILE):
    df = pd.DataFrame(columns=["Timestamp", "Prediction", "Actual"])
    df.to_csv(LOG_FILE, index=False)
    
# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Configure logging for real-time analysis
logging.basicConfig(filename="ids_logs.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# Load trained model
model = joblib.load("anomaly_detection_model.pkl")

# Define categorical mappings (must match training)
protocol_map = {6: 0, 17: 1, 1: 2}  # TCP, UDP, ICMP
flag_map = {"OTH": 0, "REJ": 1, "RSTO": 2, "RSTOS0": 3, "RSTR": 4, "S0": 5, 
            "S1": 6, "S2": 7, "S3": 8, "SF": 9, "SH": 10}
service_map = {"http": 0, "ftp": 1, "smtp": 2, "dns": 3, "ssh": 4, "other": 99}

# Store recent predictions & timestamps
predictions = deque(maxlen=100)
timestamps = deque(maxlen=100)

# Extract TCP flags
def get_tcp_flag(packet):
    if TCP in packet:
        flags = packet[TCP].flags
        return {
            0x04: "RSTR", 0x02: "S0", 0x10: "S1", 0x18: "SF"
        }.get(flags, "OTH")
    return "OTH"

# Function to preprocess network packet into features
def preprocess_packet(packet):
    protocol = packet[IP].proto if IP in packet else 6  # Default TCP
    service = "other"  # Placeholder (requires deeper analysis)
    flag = get_tcp_flag(packet)  

    src_bytes = len(packet.payload) if packet.payload else 0
    dst_bytes = len(packet[TCP].payload) if TCP in packet and packet[TCP].payload else 0  # Ensure safe extraction

    # Encode categorical features
    protocol_encoded = protocol_map.get(protocol, -1)  
    service_encoded = service_map.get(service, 99)  
    flag_encoded = flag_map.get(flag, -1)  

    # Construct feature vector (41 features, placeholders used)
    features = np.array([
        0, protocol_encoded, service_encoded, flag_encoded, src_bytes, dst_bytes,  # Main features
        *[0] * 35  # Fill remaining 41 features
    ]).reshape(1, -1)  

    return features

def log_prediction(timestamp, prediction, actual):
    new_data = pd.DataFrame([[timestamp, prediction, actual]], columns=["Timestamp", "Prediction", "Actual"])
    
    # Check if the log file is empty
    if os.stat(LOG_FILE).st_size == 0:
        new_data.to_csv(LOG_FILE, index=False)  # Overwrite file with new data
    else:
        df = pd.read_csv(LOG_FILE)

        # Ensure the DataFrame is not empty before concatenating
        if not df.empty:
            df = pd.concat([df, new_data], ignore_index=True)
        else:
            df = new_data  # Directly assign if the existing DataFrame is empty

        df.to_csv(LOG_FILE, index=False)

def packet_callback(packet):
    if IP in packet:
        try:
            # Preprocess packet
            features = preprocess_packet(packet)
            
            # Make prediction
            prediction = model.predict(features)[0]
            proba = model.predict_proba(features)[0][1]  

            # Determine actual label (assume threshold 0.3)
            actual = 1 if proba > 0.3 else 0

            # Log Data
            log_prediction(time.time(), prediction, actual)


            # Print Detection
            if actual:
                print("🚨 Anomaly detected!")
            else:
                print("✅ Normal traffic")

        except Exception as e:
            print(f"Error processing packet: {e}")

            
            

# Function to compute real-time performance metrics
def compute_metrics():
    if len(predictions) > 10:
        y_pred = list(predictions)
        y_true = [1 if pred == 1 else 0 for pred in y_pred]  # Assume binary classification

        print("\n📊 Real-time Performance Metrics:")
        print(classification_report(y_true, y_pred))

        cm = confusion_matrix(y_true, y_pred)
        print("🌀 Confusion Matrix:")
        print(cm)

        precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary")
        print(f"🎯 Precision: {precision:.4f}")
        print(f"📈 Recall: {recall:.4f}")
        print(f"📊 F1-score: {f1:.4f}")

        roc_auc = roc_auc_score(y_true, y_pred)
        print(f"🚀 ROC-AUC Score: {roc_auc:.4f}")

        # Log metrics
        logging.info(f"Precision: {precision:.4f}, Recall: {recall:.4f}, F1-score: {f1:.4f}, ROC-AUC: {roc_auc:.4f}")

    threading.Timer(30, compute_metrics).start()  # Run every 30 seconds

# Start real-time performance monitoring
compute_metrics()

# Start sniffing (Admin/root required)
print("🔍 Listening for network traffic (Press Ctrl+C to stop)...")
scapy.sniff(prn=packet_callback, store=False)
