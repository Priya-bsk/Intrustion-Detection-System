import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Load training and testing labels
y_train = pd.read_csv("y_train.csv")
y_test = pd.read_csv("y_test.csv")

# Initialize LabelEncoder
encoder = LabelEncoder()

# Fit encoder and transform labels into numerical format
y_train_encoded = encoder.fit_transform(y_train.values.ravel())  # Convert to 1D array
y_test_encoded = encoder.transform(y_test.values.ravel())  # Use the same encoder for test data

# Convert back to DataFrame
y_train_encoded_df = pd.DataFrame(y_train_encoded, columns=["label"])
y_test_encoded_df = pd.DataFrame(y_test_encoded, columns=["label"])

# Save the encoded labels
y_train_encoded_df.to_csv("y_train_encoded.csv", index=False)
y_test_encoded_df.to_csv("y_test_encoded.csv", index=False)

# Print unique classes for verification
print("Labels encoded successfully!")
print(f"Unique classes: {encoder.classes_}")
