import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

def export_network_model():
    cache_path = os.path.join("notebooks", "features_cache.csv")
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)
    out_model_path = os.path.join(models_dir, "network_rf_model.joblib")

    if not os.path.exists(cache_path):
        print(f"Error: {cache_path} not found.")
        return

    print("Loading features_cache.csv to train network model...")
    df = pd.read_csv(cache_path)
    
    feature_cols = [
        'age_days', 'whois_has_error',
        'has_spf', 'has_dmarc', 'has_mx', 'dns_has_error',
        'tls_valid', 'tls_has_error',
        'has_hsts', 'has_csp', 'has_x_frame_options', 'has_x_content_type_options'
    ]
    
    # Handle possible column name variations
    if 'whois_has error' in df.columns and 'whois_has_error' not in df.columns:
        df['whois_has_error'] = df['whois_has error']
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    X = df[feature_cols].copy()
    X['age_days'] = X['age_days'].fillna(-1)
    X = X.fillna(0)
    y = (df['label'] == 'malicious').astype(int)

    rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    rf.fit(X, y)
    
    joblib.dump(rf, out_model_path)
    print(f"[SUCCESS] Exported {out_model_path} successfully!")

if __name__ == "__main__":
    export_network_model()
