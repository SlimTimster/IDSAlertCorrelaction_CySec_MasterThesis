import pandas as pd
import json

# Helper functions related to data loading and preprocessing

# Load dataset from a file and return it as a pandas dataframe
def load_data(data_path):
    return pd.read_csv(data_path, header=None)

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
def add_true_labels_to_dataset(df_log_data, df_true_labels):
    for index, row in df_true_labels.iterrows():
        line = row['line']
        labels = row['labels']
        df_log_data.loc[line-1, 'true_type'] = "1"
        df_log_data.loc[line-1, 'labels'] = str(labels)

    # Add true_type = 0 for benign
    df_log_data['true_type'] = df_log_data['true_type'].replace("n", "0")
    return df_log_data