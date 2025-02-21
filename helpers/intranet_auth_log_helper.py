import pandas as pd
import os
from joblib import load, dump

"""
Extracts the following features from teh auth.log file:
- Process based features
- Suspicious directory / file paths
- Session opened / closed
- User switch
"""
def extract_features(df_raw):
    df_features = []

    for index, row in df_raw.iterrows():
        features = {}
        
        # Process based features
        features["prcs_sudo"] = "sudo" in row["message"].lower()
        features["prcs_su"] = "su" in row["message"].lower()
        features["prcs_sshd"] = "sshd" in row["message"].lower()
        features["prcs_cron"] = "cron" in row["message"].lower()
        
        # Suspicious directory / file paths
        features["dir_root"] = "/root" in row["message"].lower()
        features["dir_shadow"] = "/shadow" in row["message"].lower()
        features["dir_passwd"] = "/passwd" in row["message"].lower()
        
        # Session opened / closed
        features["sess_open"] = "session opened" in row["message"].lower()
        features["sess_close"] = "session closed" in row["message"].lower()
        features["sess_new"] = "new session" in row["message"].lower()
        
        # User switch
        features["user_switch"] = "user switch" in row["message"].lower()   

        # Alternative approach grouping the Sensitive operations into one feature:
        #sensitive_patterns = r"/root|/etc/shadow|/etc/passwd|chmod|chown"
        #df_features["sensitive_op"] = df_raw["message"].str.contains(sensitive_patterns, case=False, regex=True)

        # TODO: Feature selection shows that the following features are not useful at all:
        # dir_root  0.000000
        # sess_open  0.000000 

        df_features.append(features)
        
    return pd.DataFrame(df_features)