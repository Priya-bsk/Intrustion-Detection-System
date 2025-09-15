import pandas as pd

from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Define column names for NSL-KDD Dataset
column_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
                "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
                "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
                "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
                "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
                "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
                "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
                "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
                "dst_host_srv_rerror_rate", "attack_type", "difficulty_level"]

# Load dataset
def load_nsl_kdd(filepath):
    df = pd.read_csv(filepath, names=column_names)
    return df

# Encode categorical features
def preprocess_data(df):
    categorical_cols = ["protocol_type", "service", "flag"]
    encoder = LabelEncoder()

    for col in categorical_cols:
        df[col] = encoder.fit_transform(df[col])

    # Convert attack labels to binary (0: Normal, 1: Attack)
    df["attack_type"] = df["attack_type"].apply(lambda x: 0 if x == "normal" else 1)

    # Drop 'difficulty_level' as it's not useful for detection
    df.drop(columns=["difficulty_level"], inplace=True)

    # Normalize features
    scaler = MinMaxScaler()
    df = df.astype(float)
    df.iloc[:, :-1] = scaler.fit_transform(df.iloc[:, :-1])


    return df

if __name__ == "__main__":
    

    df = load_nsl_kdd("KDDTrain+.txt") 
    df = preprocess_data(df)
    df.to_csv("processed_data.csv", index=False)
    print("✅ Data Preprocessing Complete!")
