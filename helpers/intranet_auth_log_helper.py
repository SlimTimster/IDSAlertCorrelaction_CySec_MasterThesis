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


"""
Save trained models using joblib.

Args:
    models: Dictionary of trained models with their names
    output_dir: Directory where models will be saved
"""
def save_models_to_disk(models: dict, output_dir: str = 'trained-models', overwrite: bool = False) -> None:
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Save each model
        for name, model in models.items():
            # Create a safe filename from the model name
            filename = f"{name.replace(' ', '_').lower()}.joblib"
            filepath = os.path.join(output_dir, filename)
            
            # If overwrite is False and the file already exists, skip saving
            if not overwrite and os.path.exists(filepath):
                print(f"Model {name} already exists at {filepath}. Skipping...")
                continue

            # Save the model
            dump(model, filepath)
            print(f"Saved {name} to {filepath}")
            
    except Exception as e:
        print(f"Error saving models: {e}")

"""
Load saved models from the specified directory.

Args:
    input_dir: Directory containing saved models
    
Returns:
    Dictionary of loaded models with their names
"""
def load_models_from_disk(input_dir: str = 'trained-models') -> dict:
    loaded_models = {}
    try:
        # Load each model from the directory
        for filename in os.listdir(input_dir):
            if filename.endswith('.joblib'):
                filepath = os.path.join(input_dir, filename)
                # Get model name from filename (remove .joblib and convert to original format)
                model_name = filename.replace('.joblib', '')
                
                # Load the model
                loaded_models[model_name] = load(filepath)
                print(f"Loaded {model_name} from {filepath}")
                
        return loaded_models
        
    except Exception as e:
        print(f"Error loading models: {e}")
        return {}
    

"""
Classify the unseen data using all models.

Returns:
    Dictionary of model names and their predictions
"""
def classify_unseen_data(models: dict, unseen_features: pd.DataFrame) -> dict:
    unseen_predictions = {}

    for name, model in models.items():
        unseen_predictions[name] = model.predict(unseen_features)

    return unseen_predictions