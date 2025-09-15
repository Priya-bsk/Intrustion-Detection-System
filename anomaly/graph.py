import pandas as pd
import matplotlib.pyplot as plt

# Load the logs.csv file
LOG_FILE = "logs.csv"

try:
    df = pd.read_csv(LOG_FILE)

    # Convert Timestamp to datetime format
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], unit='s')

    # Create scatter plot
    plt.figure(figsize=(12, 6))
    plt.scatter(df.loc[df["Label"] == 0, "Timestamp"], [0] * sum(df["Label"] == 0), 
                color='green', label="Normal (Green)", s=80, edgecolors='black')
    plt.scatter(df.loc[df["Label"] == 1, "Timestamp"], [1] * sum(df["Label"] == 1), 
                color='red', label="Anomaly (Red)", s=80, edgecolors='black')

    # Improve styling
    plt.xticks(rotation=30, ha="right")  # Rotate X-axis labels
    plt.yticks([0, 1], labels=["Normal (0)", "Anomaly (1)"])  # Better Y-axis labels
    plt.title("Improved Anomaly Detection Over Time", fontsize=14, fontweight="bold")
    plt.xlabel("Timestamp", fontsize=12)
    plt.ylabel("Anomaly Status", fontsize=12)
    plt.grid(True, linestyle="--", alpha=0.6)  # Light grid for better readability
    plt.legend()

    # Show the plot 
    plt.show()

except FileNotFoundError:
    print("🚨 Error: logs.csv not found! Make sure the file is in the same directory.")
