import pandas as pd
import os
from joblib import load, dump

import re
import pandas as pd
import numpy as np
from datetime import datetime

def extract_dns_features(df_raw):
    """
    Extract features from DNS logs focusing on domains and message types
    Input: DataFrame with columns 'timestamp' and 'message'
    """
    data = []
    unmatched_count = 0
    unmatched_entries = []

   
    # Regular expressions for each type of log line
    patterns = {
        'query_a': re.compile(r'query\[A\] (?P<domain>[^\s]+)'),
        'query_aaaa': re.compile(r'query\[AAAA\] (?P<domain>[^\s]+)'),
        'query_srv': re.compile(r'query\[SRV\] (?P<domain>[^\s]+)'),
        'query_txt': re.compile(r'query\[TXT\] (?P<domain>[^\s]+)'),
        'query_ptr': re.compile(r'query\[PTR\] (?P<domain>[^\s]+)'),
        'query_mx': re.compile(r'query\[MX\] (?P<domain>[^\s]+)'),
        'forwarded': re.compile(r'forwarded (?P<domain>[^\s]+)'),
        'reply': re.compile(r'reply (?P<domain>[^\s]+)'),
        'cached': re.compile(r'cached (?P<domain>[^\s]+)'),
        'nameserver': re.compile(r'nameserver'),  # No domain in nameserver messages
    }
   
    # Process each row in the DataFrame
    for i, row in df_raw.iterrows():
        timestamp = row['timestamp']
        message = row['message']
        
        matched = False
        for msg_type, pattern in patterns.items():
            if match := pattern.match(message):
                entry = {
                    'message_type': msg_type,
                    'timestamp': timestamp
                }
               
                # Add domain and its features if present in the pattern
                if 'domain' in pattern.groupindex:
                    domain = match.group('domain')
                    entry['domain'] = domain
                    entry.update(extract_domain_features(domain))
                else:
                    entry['domain'] = None
                    entry.update(extract_domain_features(None))
                   
                data.append(entry)
                matched = True
                break

        if not matched:
            unmatched_count += 1
            unmatched_entries.append(f"Row {i}: {row['message']}")

    if unmatched_count > 0:
        print(f"WARNING: {unmatched_count} rows ({unmatched_count/len(df_raw)*100:.2f}%) didn't match any pattern")
        if unmatched_entries:
            print("Unmatched rows:")
            for example in unmatched_entries:
                print(f"  {example}")

    # Convert to DataFrame
    df = pd.DataFrame(data)
    return df

def extract_domain_features(domain):
    """Extract features from a domain name"""
    if pd.isna(domain):
        return {
            'domain_length': 0,
            'domain_parts': 0,
            'avg_part_length': 0,
            'max_part_length': 0,
            'special_char_count': 0,
            'numeric_char_count': 0,
            'alpha_char_count': 0,
            'entropy': 0
        }
        
    # Basic length features
    features = {
        'domain_length': len(domain),
        'domain_parts': len(domain.split('.')),
        'avg_part_length': np.mean([len(part) for part in domain.split('.')]),
        'max_part_length': max([len(part) for part in domain.split('.')]),
        'special_char_count': len(re.findall(r'[^a-zA-Z0-9\.]', domain)),
        'numeric_char_count': len(re.findall(r'[0-9]', domain)),
        'alpha_char_count': len(re.findall(r'[a-zA-Z]', domain))
    }
    
    # Calculate Shannon entropy
    char_freq = {}
    for char in domain:
        char_freq[char] = char_freq.get(char, 0) + 1
    entropy = 0
    for freq in char_freq.values():
        prob = freq / len(domain)
        entropy -= prob * np.log2(prob)
    features['entropy'] = entropy
    
    return features