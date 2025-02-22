import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Embedding, Dropout
from tensorflow.keras.utils import to_categorical
import re

# 1. Data Loading and Preprocessing
def parse_log_line(line):
    """Parse a single log line into components"""
    pattern = r'([\d\.]+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    match = re.match(pattern, line)
    if match:
        ip, timestamp, request, status, bytes_sent, referrer, user_agent = match.groups()
        method, path, protocol = request.split(' ') if len(request.split(' ')) >= 3 else (request, "", "")
        return {
            'ip': ip,
            'timestamp': timestamp,
            'method': method,
            'path': path,
            'protocol': protocol,
            'status': int(status),
            'bytes_sent': int(bytes_sent),
            'referrer': referrer,
            'user_agent': user_agent
        }
    return None

def create_sequence_features(df, window_size=5):
    """Create sequence features from the dataframe"""
    sequences = []
    for i in range(len(df) - window_size + 1):
        sequence = df.iloc[i:i + window_size]
        sequences.append(sequence.values)
    return np.array(sequences)

# 2. Feature Engineering
def extract_features(df):
    """Extract and engineer features from the log data"""
    # First ensure we have method, path, protocol by splitting requestmethod if not already done
    if 'method' not in df.columns:
        df[['method', 'path', 'protocol']] = df['requestmethod'].str.strip('"').str.split(' ', n=2, expand=True)
    
    # Encode categorical variables
    label_encoders = {}
    for column in ['ip', 'method', 'path', 'protocol', 'user_agent']:
        label_encoders[column] = LabelEncoder()
        df[column + '_encoded'] = label_encoders[column].fit_transform(df[column])
    
    # Create numerical features
    df['path_length'] = df['path'].str.len()
    df['has_php'] = df['path'].str.contains('.php').astype(int)
    df['has_wp'] = df['path'].str.contains('wp-').astype(int)
    df['is_scan'] = df['user_agent'].str.contains('scan|Nmap|WPScan', case=False).astype(int)
    
    # Select features for sequence
    feature_columns = [
        'method_encoded', 'path_encoded', 'protocol_encoded',
        'statuscode',  # changed from 'status'
        'responsesize',  # changed from 'bytes_sent'
        'path_length', 'has_php',
        'has_wp', 'is_scan'
    ]
    
    return df[feature_columns], label_encoders

# 3. Model Creation
def create_lstm_model(input_shape, num_classes):
    model = Sequential([
        LSTM(64, input_shape=input_shape, return_sequences=True),
        Dropout(0.3),
        LSTM(32),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dense(num_classes, activation='sigmoid')  # sigmoid for multi-label
    ])
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    return model

# 4. Training Pipeline
def train_log_classifier(log_data, labels, window_size=5):
    """Main training pipeline"""
    # Convert logs to dataframe
    logs_df = pd.DataFrame([parse_log_line(line) for line in log_data])
    
    # Extract features
    features_df, encoders = extract_features(logs_df)
    
    # Create sequences
    X = create_sequence_features(features_df, window_size)
    
    # Prepare labels
    y = np.array(labels)
    
    # Create and train model
    input_shape = (window_size, X.shape[2])
    num_classes = y.shape[1]  # number of label classes
    
    model = create_lstm_model(input_shape, num_classes)
    
    # Split data #TODO: Use data_helper instead
    train_split = int(len(X) * 0.8)
    X_train, X_test = X[:train_split], X[train_split:]
    y_train, y_test = y[:train_split], y[train_split:]
    
    # Train
    history = model.fit(
        X_train, y_train,
        validation_data=(X_test, y_test),
        epochs=10,
        batch_size=32
    )
    
    return model, history, encoders

# 5. Usage Example
def predict_sequences(model, new_logs, encoders, window_size=5):
    """Predict on new log sequences"""
    # Process new logs same way as training
    new_df = pd.DataFrame([parse_log_line(line) for line in new_logs])
    features_df, _ = extract_features(new_df)
    sequences = create_sequence_features(features_df, window_size)
    
    # Make predictions
    predictions = model.predict(sequences)
    return predictions