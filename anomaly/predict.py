import pandas as pd
import numpy as np
import joblib  # Add this at the beginning of your script

# Load the test data again (for consistency)
new_data = pd.read_csv("X_test.csv")  # Ensure this has the same columns as X_train

# Load the trained model
model = joblib.load("anomaly_detection_model.pkl")

# Predict anomalies
predictions = model.predict(new_data)

# Count anomalies
num_anomalies = np.sum(predictions == 1)
num_normal = np.sum(predictions == 0)

print(f"Total Samples: {len(predictions)}")
print(f"Anomalies Detected: {num_anomalies}")
print(f"Normal Samples: {num_normal}")

# Save results
results = pd.DataFrame({'Prediction': predictions})
results.to_csv("predictions.csv", index=False)
print(" Predictions saved to predictions.csv")
