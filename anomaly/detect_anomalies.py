import pandas as pd
import joblib

# Load the trained model
model = joblib.load("anomaly_detection_model.pkl")
print("Model loaded successfully.")

# Load new test data
new_data = pd.read_csv("X_test.csv")  # Ensure this has the same columns as X_train

# Ensure correct number of features
expected_features = model.n_features_in_
actual_features = new_data.shape[1]

if actual_features != expected_features:
    print(f" Feature mismatch! Model expects {expected_features}, but got {actual_features}.")
    new_data = new_data.iloc[:, :expected_features]  # Trim extra columns

# Predict anomalies
predictions = model.predict(new_data)

print("Predictions:", predictions)
for i, pred in enumerate(predictions):
    print(f"Sample {i+1}: {'Anomaly' if pred == 1 else 'Normal'}")

