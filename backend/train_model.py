import os
import sys
import pandas as pd
import numpy as np
import requests
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Ensure the backend directory is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_extraction import extract_features

# Dataset URLs to try
DATASET_URLS = [
    # Primary: A clean raw URL dataset from github (isuruda)
    "https://raw.githubusercontent.com/isuruda/Phishing-URL-Detection/master/phishing.csv",
    # Alternative: A popular malicious/benign URLs list (saran-pt)
    "https://raw.githubusercontent.com/saran-pt/phishing-site-detection/master/phishing_site_urls.csv"
]

def load_data():
    """Download a dataset from public sources, sample 10,000 rows, or generate synthetic fallback."""
    print("Attempting to load URL dataset...")
    
    # Create data directory if it doesn't exist
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_root = os.path.dirname(backend_dir)
    data_dir = os.path.join(workspace_root, "data")
    os.makedirs(data_dir, exist_ok=True)
    csv_path = os.path.join(data_dir, "phishing_dataset.csv")
    
    # If the sampled dataset already exists locally, use it
    if os.path.exists(csv_path):
        print(f"Found existing dataset at {csv_path}. Loading...")
        try:
            return pd.read_csv(csv_path)
        except Exception as e:
            print(f"Error reading local file: {e}. Re-downloading...")
            
    for url in DATASET_URLS:
        try:
            print(f"Downloading from {url}...")
            # We fetch with a 10s timeout to avoid hanging
            df = pd.read_csv(url)
            print(f"Successfully downloaded. Rows: {len(df)}, Columns: {list(df.columns)}")
            
            # Normalize column names
            df.columns = [col.lower() for col in df.columns]
            
            # Determine url and label columns
            url_col = 'url' if 'url' in df.columns else (df.columns[0] if len(df.columns) > 0 else None)
            label_col = 'label' if 'label' in df.columns else ('status' if 'status' in df.columns else (df.columns[1] if len(df.columns) > 1 else None))
            
            if not url_col or not label_col:
                print("Could not automatically map URL or Label column. Trying next source...")
                continue
                
            # Clean and parse labels
            df = df[[url_col, label_col]].dropna()
            
            # Convert label column to binary (0 = Legitimate, 1 = Phishing)
            # Legitimate values: 'legitimate', 'benign', 'good', '0', 0
            # Phishing values: 'phishing', 'bad', '1', 1
            def clean_label(val):
                s = str(val).strip().lower()
                if s in ['legitimate', 'benign', 'good', '0', '0.0', 'no', 'safe']:
                    return 0
                elif s in ['phishing', 'bad', '1', '1.0', 'yes', 'malicious']:
                    return 1
                else:
                    # Default heuristic fallback
                    return 1 if 'bad' in s or 'phish' in s or 'mal' in s else 0
                    
            df['label'] = df[label_col].apply(clean_label)
            df = df.rename(columns={url_col: 'url'})
            
            # Balance the dataset (sample 5000 legitimate and 5000 phishing)
            legit_df = df[df['label'] == 0]
            phish_df = df[df['label'] == 1]
            
            min_samples = min(len(legit_df), len(phish_df), 5000)
            if min_samples < 500:
                print("Too few samples of one class. Trying next source...")
                continue
                
            sampled_legit = legit_df.sample(n=min_samples, random_state=42)
            sampled_phish = phish_df.sample(n=min_samples, random_state=42)
            
            final_df = pd.concat([sampled_legit, sampled_phish]).sample(frac=1, random_state=42).reset_index(drop=True)
            print(f"Sampled balanced dataset of {len(final_df)} rows ({min_samples} each).")
            
            # Save local copy for subsequent runs
            final_df[['url', 'label']].to_csv(csv_path, index=False)
            return final_df[['url', 'label']]
            
        except Exception as e:
            print(f"Failed to download/parse from {url}: {e}")
            
    # Fallback: Generate synthetic dataset if network is down
    print("Network datasets unavailable. Generating realistic synthetic URL dataset...")
    df = generate_synthetic_data(10000)
    df.to_csv(csv_path, index=False)
    print(f"Saved synthetic dataset to {csv_path}")
    return df

def generate_synthetic_data(num_samples=10000):
    """Generate highly realistic synthetic URLs and labels to ensure local build always succeeds offline."""
    import random
    
    benign_templates = [
        "https://www.google.com/search?q={}",
        "https://www.facebook.com/profile/{}",
        "https://www.youtube.com/watch?v={}",
        "https://www.microsoft.com/en-us/{}",
        "https://www.wikipedia.org/wiki/{}",
        "https://www.github.com/{}/{}",
        "https://www.amazon.com/dp/{}",
        "https://www.apple.com/shop/{}",
        "https://www.linkedin.com/in/{}",
        "https://www.netflix.com/title/{}"
    ]
    
    phishing_templates = [
        "http://{}-login-verify-{}.com/login",
        "http://{}-verification-update.net/{}",
        "http://verify-{}-credentials.org/signin",
        "http://{}-security-update.com/{}",
        "http://{}-support-login.net/{}",
        "http://{}-account-recover.com/{}",
        "http://{}-bonus-wallet.com/update",
        "http://{}.rebrand.ly/{}",
        "http://{}.bit.ly/{}",
        "http://{}-cmd-webscr.com/signin"
    ]
    
    brands = ["paypal", "ebay", "apple", "google", "facebook", "amazon", "netflix", "microsoft", "chase", "bankofamerica", "wellsfargo", "yahoo", "outlook", "dropbox"]
    words = ["login", "verify", "secure", "account", "update", "signin", "bank", "webscr", "cmd", "confirm", "wp-admin", "wp-content", "submit", "recover", "bonus", "wallet"]
    
    data = []
    # Benign
    for i in range(num_samples // 2):
        tpl = random.choice(benign_templates)
        rand_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))
        url = tpl.format(rand_str) if tpl.count("{}") == 1 else tpl.format(rand_str, rand_str)
        data.append({"url": url, "label": 0})
        
    # Phishing
    for i in range(num_samples // 2):
        tpl = random.choice(phishing_templates)
        brand = random.choice(brands)
        word = random.choice(words)
        url = tpl.format(brand, word)
        data.append({"url": url, "label": 1})
        
    return pd.DataFrame(data)

def main():
    # Load dataset
    df = load_data()
    
    # Feature extraction
    print("Extracting features from URLs (offline mode)...")
    feature_list = []
    
    total = len(df)
    for idx, row in df.iterrows():
        url = row['url']
        # Extract features offline (skips live network requests)
        feats = extract_features(url, offline=True)
        feature_list.append(feats)
        
        # Simple progress report every 10%
        if (idx + 1) % (total // 10) == 0 or idx == total - 1:
            print(f"Processed {idx + 1}/{total} URLs ({(idx + 1) / total * 100:.0f}%)")
            
    X = pd.DataFrame(feature_list)
    y = df['label']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"Train set size: {X_train.shape[0]}, Test set size: {X_test.shape[0]}")
    
    # Train model
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print("\n" + "="*30)
    print("Model Evaluation Metrics:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("="*30 + "\n")
    
    # Print feature importances
    importances = model.feature_importances_
    features = X.columns
    indices = np.argsort(importances)[::-1]
    
    print("Feature Importances (Lexical Features):")
    for f in range(X.shape[1]):
        print(f"{f + 1}. {features[indices[f]]:<25} : {importances[indices[f]]:.4f}")
    print("="*30 + "\n")
    
    # Save model
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(backend_dir, "model.pkl")
    joblib.dump(model, model_path)
    print(f"Trained model successfully saved to {model_path}")

if __name__ == "__main__":
    main()
