import pandas as pd
import json

# Helper functions related to data loading and preprocessing

# Load dataset from a file and return it as a pandas dataframe
def load_data(data_path):
    return pd.read_csv(data_path, header=None)

# Load dataset from a file and return it as a pandas dataframe taking into account , separated and space separated files
def load_data_robust(file_path):
    import re
    """
    Loads and processes log files in both comma-separated and space-separated formats.
    
    Args:
        file_path (str): Path to the log file
        
    Returns:
        pandas.DataFrame: Processed DataFrame with 'timestamp' and 'message' columns
    """
    # First, read the first line of the file to determine format
    with open(file_path, 'r') as f:
        first_line = f.readline().strip()
    
    # Check if the format uses commas
    if ',' in first_line:
        # Comma-separated format
        df = pd.read_csv(file_path, header=None)
        
        # Extract timestamp from first column
        df['timestamp'] = df[0].str.extract(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
        
        # Combine remaining columns for message, skipping timestamp and server name
        df['message'] = df[2]
        
    else:
        # Space-separated format
        # Read the entire file
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Process each line
        timestamps = []
        messages = []
        
        for line in lines:
            # Extract timestamp and message using regex
            timestamp_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
            if timestamp_match:
                timestamps.append(timestamp_match.group(1))
                # Get everything after "intranet-server"
                message = re.search(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(.*)$', line)
                messages.append(message.group(1) if message else '')
        
        # Create DataFrame from processed lines
        df = pd.DataFrame({
            'timestamp': timestamps,
            'message': messages
        })
    
    # Clean up timestamp format (ensure single space between components)
    df['timestamp'] = df['timestamp'].apply(lambda x: re.sub(r'\s+', ' ', x.strip()) if pd.notnull(x) else x)
    
    # Clean up message (remove any leading/trailing whitespace)
    df['message'] = df['message'].str.strip()
    
    # Select and return only the needed columns
    return df[['timestamp', 'message']].copy()

# Load the true labels from a json file and return it as a pandas dataframe 
def load_true_labels(true_labels_path):
    true_labels = []

    with open(true_labels_path) as file:
        for line in file:
            true_labels.append(json.loads(line))

    # Convert to DF and return
    return pd.DataFrame(true_labels)


# Add Labels and true_type to dataset
# true_type = 1 for attack, 0 for benign
# labels = list of attack categories for each attack
def add_binary_true_labels_to_dataset(df_log_data, df_true_labels):
    for index, row in df_true_labels.iterrows():
        line = row['line']
        labels = row['labels']
        df_log_data.loc[line-1, 'true_type'] = "1"
        df_log_data.loc[line-1, 'labels'] = str(labels)

    # Add true_type = 0 for benign
    df_log_data['true_type'] = df_log_data['true_type'].replace("n", "0")
    return df_log_data


# Add labels to dataset
def add_labels_to_dataset(df_log_data, df_true_labels):
    for _, row in df_true_labels.iterrows():
        line = row['line']
        labels = row['labels']
        df_log_data.loc[line-1, 'labels'] = str(labels)
        #print("Line: ", line, " Labels: ", labels)

    # Add binary true_type as well
    df_log_data['true_type'] = df_log_data['labels'].notna().astype(int)

    return df_log_data

# Splits the data into train, test and validation sets (70%, 20%, 10%)
def split_data(x, y_multilabel):
    from sklearn.model_selection import train_test_split

    # Split into train, test and validation sets
    # 70% train, 20% test, 10% validation #TODO: Calculate if this is correct
    X_temp, X_test, y_temp, y_test = train_test_split(
        x, y_multilabel, test_size=0.2, random_state=42, stratify=y_multilabel
    )

    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.125, random_state=42, stratify=y_temp
    )

    # How many per set
    print("Training set size: ", len(X_train), " Test set size: ", len(X_test), " Validation set size: ", len(X_val))

    # How many for each class:
    print("\nClass distribution in training set:")
    print(y_train.sum())

    print("\nClass distribution in validation set:")
    print(y_val.sum())

    print("\nClass distribution in test set:")
    print(y_test.sum())

    return X_train, X_test, X_val, y_train, y_test, y_val


# #################################################################################
# ------------------------------------ DNSMASQ ------------------------------------
# #################################################################################

# Parse the log lines and match them to their message type using manually defined regular expressions
def parse_log(log_lines):
    import re
    import pandas as pd

    data = []
    # Regular expressions for each type of log line
    # Query patterns
    query_a_pattern = re.compile(
        r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
        r'dnsmasq\[\d+\]: query\[A\] '
        r'(?P<domain>[^\s]+) '
        r'from (?P<src_ip>[^\s]+)'
    )
    query_aaaa_pattern = re.compile(
        r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
        r'dnsmasq\[\d+\]: query\[AAAA\] '
        r'(?P<domain>[^\s]+) '
        r'from (?P<src_ip>[^\s]+)'
    )
    query_srv_pattern = re.compile(
        r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
        r'dnsmasq\[\d+\]: query\[SRV\] '
        r'(?P<domain>[^\s]+) '
        r'from (?P<src_ip>[^\s]+)'
    )
    query_txt_pattern = re.compile(
        r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
        r'dnsmasq\[\d+\]: query\[TXT\] '
        r'(?P<domain>[^\s]+) '
        r'from (?P<src_ip>[^\s]+)'
    )
    query_ptr_pattern = re.compile(
    r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
    r'dnsmasq\[\d+\]: query\[PTR\] '
    r'(?P<domain>[^\s]+) '
    r'from (?P<src_ip>[^\s]+)$'
    )
    query_mx_pattern = re.compile(
    r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
    r'dnsmasq\[\d+\]: query\[MX\] '
    r'(?P<domain>[^\s]+) '
    r'from (?P<src_ip>[^\s]+)$'
    )
    
    # Forwarded pattern
    forwarded_pattern = re.compile(
        r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
        r'dnsmasq\[\d+\]: forwarded '
        r'(?P<domain>[^\s]+) '
        r'to (?P<dst_ip>[^\s]+)'
    )

    # Reply pattern
    reply_pattern = re.compile(
        r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
        r'dnsmasq\[\d+\]: reply '
        r'(?P<domain>[^\s]+) '
        r'is (?P<resolved_ip>[^\s]+)'
    )

    # Cached pattern
    cached_pattern = re.compile(
        r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
        r'dnsmasq\[\d+\]: cached '
        r'(?P<domain>[^\s]+) '
        r'is (?P<resolved_ip>[^\s]+)'
    )

    # Nameserver pattern
    nameserver_pattern = re.compile(
        r'^(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) '
        r'dnsmasq\[\d+\]: nameserver '
        r'(?P<nameserver_ip>[^\s]+) '
        r'refused to do a recursive query$'
    )

    # Loop over every line in the log file and match it to a pattern
    for line in log_lines:
        #Query
        if match := query_a_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'query_a'
            data.append(match_data)
        elif match := query_aaaa_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'query_aaaa'
            data.append(match_data)
        elif match := query_srv_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'query_srv'
            data.append(match_data)
        elif match := query_txt_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'query_txt'
            data.append(match_data)
        elif match := query_ptr_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'query_ptr'
            data.append(match_data)
        elif match := query_mx_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'query_mx'
            data.append(match_data)

        #Forwarded
        elif match := forwarded_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'forwarded'
            data.append(match_data)
        
        #Reply
        elif match := reply_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'reply'
            data.append(match_data)
        
        #Cached
        elif match := cached_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'cached'
            data.append(match_data)

        #Nameserver
        elif match := nameserver_pattern.match(line):
            match_data = match.groupdict()
            match_data['message_type'] = 'nameserver'
            data.append(match_data)

        #Default
        else:
            print(f"Line does not match any pattern: {line}")

    df = pd.DataFrame(data)
    
    # Convert timestamp to a datetime object
    df['timestamp'] = pd.to_datetime('2022 ' + df['timestamp'], format='%Y %b %d %H:%M:%S', errors='coerce')
    df["message_type"] = df["message_type"].astype(str)
    
    return df



# ------------------------------------ Clustering of Events (dnsmasq) ------------------------------------

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from datetime import datetime
import seaborn as sns
from sklearn.metrics.pairwise import cosine_similarity
import json

# Function to process the DataFrame
def preprocess_data(attack_events):
    # Convert list of dictionaries to DataFrame
    df = pd.DataFrame(attack_events)
    
    # Convert timestamp to datetime if not already
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Extract filename from domain (last part after the last dot)
    df['filename'] = df['domain'].apply(lambda x: x.split('.')[-2] if isinstance(x, str) else None)
    
    return df

# Approach 1: Domain-based clustering
def cluster_by_domain_similarity(df):
    # Create TF-IDF vectors from domains
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
    domain_vectors = vectorizer.fit_transform(df['domain'])
    
    # Apply DBSCAN clustering
    clustering = DBSCAN(eps=0.1, min_samples=5, metric='cosine')
    clusters = clustering.fit_predict(domain_vectors)
    
    return clusters

# Approach 2: Time-aware clustering
def cluster_with_time(df):
    # Create feature matrix combining domain similarity and time
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
    domain_vectors = vectorizer.fit_transform(df['domain'])
    
    # Convert timestamps to numeric values (seconds since first event)
    time_values = (df['timestamp'] - df['timestamp'].min()).dt.total_seconds()
    time_values = time_values.values.reshape(-1, 1)
    
    # Scale time values
    scaler = StandardScaler()
    time_scaled = scaler.fit_transform(time_values)
    
    # Combine domain similarity with time
    # Calculate pairwise similarities for domains
    domain_similarities = cosine_similarity(domain_vectors)
    
    # Create combined distance matrix
    n_samples = len(df)
    combined_distances = np.zeros((n_samples, n_samples))
    
    # Weight for time component (adjust as needed)
    time_weight = 0.3
    
    for i in range(n_samples):
        for j in range(n_samples):
            # Domain similarity component
            domain_dist = 1 - domain_similarities[i, j]
            # Time difference component
            time_dist = abs(time_scaled[i] - time_scaled[j])
            # Combine distances
            combined_distances[i, j] = (1 - time_weight) * domain_dist + time_weight * time_dist
    
    # Apply DBSCAN on combined distances
    clustering = DBSCAN(eps=0.15, min_samples=5, metric='precomputed')
    clusters = clustering.fit_predict(combined_distances)
    
    return clusters

# Function to analyze and visualize clusters
def analyze_clusters(df, clusters, title):
    df_with_clusters = df.copy()
    df_with_clusters['cluster'] = clusters
    
    # Plot timeline of clusters
    plt.figure(figsize=(15, 8))
    plt.scatter(df_with_clusters['timestamp'], 
               df_with_clusters['cluster'],
               c=df_with_clusters['cluster'], 
               cmap='viridis',
               alpha=0.6)
    plt.title(f'Cluster Timeline - {title}')
    plt.xlabel('Time')
    plt.ylabel('Cluster')
    plt.colorbar(label='Cluster')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    
    # Print cluster statistics
    print(f"\nCluster Statistics - {title}")
    print("-" * 50)
    cluster_stats = df_with_clusters.groupby('cluster').agg({
        'timestamp': ['count', 'min', 'max'],
        'filename': lambda x: len(set(x))
    }).round(2)
    print(cluster_stats)
    
    return df_with_clusters