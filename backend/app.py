import os
import sys
import sqlite3
import json
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
import joblib

# Ensure the backend directory is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_extraction import extract_features, normalize_url

app = Flask(__name__)
backend_dir = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(backend_dir, 'model.pkl')

# On serverless hosting like Vercel, filesystem is read-only except for /tmp
if os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV'):
    DB_PATH = '/tmp/history.db'
else:
    DB_PATH = os.path.join(backend_dir, 'history.db')

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            risk_score REAL NOT NULL,
            risk_factors TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Helper to connect to DB
def get_db_connection():
    init_db()  # Ensure database tables exist
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Add CORS headers manually to prevent cross-origin issues
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS, DELETE'
    return response

# Handle preflight OPTIONS requests
@app.route('/api/analyze', methods=['OPTIONS'])
@app.route('/api/history', methods=['OPTIONS'])
def handle_options():
    return '', 204

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL parameter is required.'}), 400
        
    raw_url = data['url'].strip()
    if not raw_url:
        return jsonify({'error': 'URL cannot be empty.'}), 400
        
    try:
        normalized = normalize_url(raw_url)
    except Exception as e:
        return jsonify({'error': f'Malformed URL: {str(e)}'}), 400
        
    # Load model
    if not os.path.exists(MODEL_PATH):
        return jsonify({
            'error': 'Model has not been trained yet. Please run backend/train_model.py first.'
        }), 500
        
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        return jsonify({'error': f'Failed to load model: {str(e)}'}), 500
        
    # Extract features (online mode: live network check)
    print(f"Analyzing URL: {normalized}")
    try:
        feats = extract_features(normalized, offline=False)
    except Exception as e:
        print(f"Error during feature extraction: {e}")
        # Fallback offline extraction if online fails
        feats = extract_features(normalized, offline=True)
        
    # Convert features to DataFrame for prediction
    # Ensure columns match training features
    feature_order = [
        'url_length', 'num_dots', 'has_at', 'has_dash', 'has_double_slash_path',
        'use_ip', 'num_subdomains', 'num_suspicious_keywords', 'is_shortened',
        'is_https', 'ssl_valid', 'domain_age_days', 'num_redirects'
    ]
    feats_df = pd.DataFrame([feats])[feature_order]
    
    # Run ML prediction
    try:
        prediction_prob = model.predict_proba(feats_df)[0][1] # Probability of class 1 (phishing)
    except Exception as e:
        print(f"Model prediction failed: {e}")
        # Fallback heuristic prediction if model fails
        prediction_prob = 0.5
        
    # Calculate a hybrid risk score and compile list of threat factors
    risk_factors = []
    base_score = prediction_prob * 100
    
    # Adjust score and collect factors based on network & lexical signals
    # 1. SSL & Protocol
    if feats['is_https'] == 0:
        risk_factors.append("Insecure Protocol: URL uses unencrypted HTTP instead of HTTPS.")
        base_score = max(base_score, 40) # HTTP is a baseline suspicion
    elif feats['ssl_valid'] == 0:
        risk_factors.append("Invalid SSL Certificate: HTTPS connection succeeded but certificate is self-signed, expired, or invalid.")
        base_score = max(base_score, 65) # Invalid SSL on HTTPS is highly suspicious
        
    # 2. Domain Age
    if feats['domain_age_days'] != -1:
        if feats['domain_age_days'] < 30:
            risk_factors.append(f"Newly Registered Domain: Domain is only {feats['domain_age_days']} days old.")
            base_score += 25
        elif feats['domain_age_days'] < 90:
            risk_factors.append(f"Recent Domain Registration: Domain is only {feats['domain_age_days']} days old.")
            base_score += 15
    else:
        # If domain is not IP and WHOIS failed, it could be newly registered or using privacy proxy
        if feats['use_ip'] == 0 and feats['url_length'] > 12:
            risk_factors.append("Unknown Domain Age: WHOIS domain lookup failed or was rate-limited (common for new/suspicious domains).")
            base_score += 5

    # 3. Redirects
    if feats['num_redirects'] > 2:
        risk_factors.append(f"Multiple Redirections: Request was redirected {feats['num_redirects']} times (hides landing page).")
        base_score += 15
    elif feats['num_redirects'] == 1 or feats['num_redirects'] == 2:
        # Normal redirects happen, but we can list them as warnings if base score is already high
        pass

    # 4. Lexical red flags
    if feats['use_ip'] == 1:
        risk_factors.append("IP Address Hostname: Uses numerical IP instead of a domain name (classic phishing bypass).")
        base_score = max(base_score, 80)
        
    if feats['is_shortened'] == 1:
        risk_factors.append("URL Shortening Service: Domain uses a shortening service (masks real destination).")
        base_score = max(base_score, 50)
        
    if feats['has_at'] == 1:
        risk_factors.append("Spoofed Authority: URL contains '@' character which can obscure the actual destination.")
        base_score += 15
        
    if feats['has_double_slash_path'] == 1:
        risk_factors.append("Redirection Parameter: URL contains '//' inside path, indicating nested redirection.")
        base_score += 10
        
    if feats['num_suspicious_keywords'] > 0:
        risk_factors.append(f"Suspicious Keywords: URL contains {feats['num_suspicious_keywords']} keyword(s) common in scams (e.g. login, verify, secure).")
        base_score += (feats['num_suspicious_keywords'] * 10)
        
    if feats['num_subdomains'] >= 4:
        risk_factors.append(f"Excessive Subdomains: Hostname contains {feats['num_subdomains']} subdomains (often used in brand spoofing).")
        base_score += 10
        
    if feats['url_length'] > 75:
        risk_factors.append(f"Abnormal Length: URL is very long ({feats['url_length']} characters) which can hide parts of the address.")
        base_score += 5

    # 5. Hybrid Safe Discounter for Trusted Authorities & Mature Domains
    TRUSTED_DOMAINS = {
        'google.com', 'microsoft.com', 'wikipedia.org', 'github.com', 'apple.com', 
        'amazon.com', 'facebook.com', 'linkedin.com', 'netflix.com', 'yahoo.com', 
        'outlook.com', 'youtube.com', 'twitter.com', 'instagram.com'
    }
    
    import urllib.parse
    parsed_host = urllib.parse.urlparse(normalized).hostname or ''
    parsed_host_lower = parsed_host.lower()
    
    # Extract registerable root domain
    parts = parsed_host_lower.split('.')
    root_domain = parsed_host_lower
    if len(parts) > 2:
        # Handle co.uk etc.
        suffix = '.'.join(parts[-2:])
        from feature_extraction import DOUBLE_TLDS
        if suffix in DOUBLE_TLDS and len(parts) >= 3:
            root_domain = '.'.join(parts[-3:])
        else:
            root_domain = '.'.join(parts[-2:])
            
    is_trusted = root_domain in TRUSTED_DOMAINS or any(parsed_host_lower.endswith('.' + td) for td in TRUSTED_DOMAINS)
    
    # Apply discounter rules
    if is_trusted:
        # If HTTPS is valid or not IP/at/shortener spoofed, discount risk heavily
        if feats['use_ip'] == 0 and feats['has_at'] == 0 and feats['is_shortened'] == 0:
            if feats['is_https'] == 1 and feats['ssl_valid'] == 1:
                base_score = min(base_score * 0.1, 5.0) # Down to <5%
                risk_factors = [] # Clear warning indicators for clean trusted hosts
            else:
                base_score = min(base_score * 0.4, 30.0) # Moderate trust discount
    elif feats['domain_age_days'] > 365 and feats['is_https'] == 1 and feats['ssl_valid'] == 1:
        # Mature registered domain with valid SSL gets a 60% discount on lexical quirks
        base_score = base_score * 0.4

    # Cap risk score at 100% and round
    final_risk_score = round(min(max(base_score, 0), 100), 1)
    
    # Classify verdict
    if final_risk_score >= 70:
        verdict = "phishing"
    elif final_risk_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "legitimate"
        
    # Safe/Legitimate domains should have an empty factor list if score is low
    if verdict == "legitimate" and len(risk_factors) == 0:
        risk_factors.append("No obvious threat indicators detected.")
        
    # Log results to SQLite DB
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scans (url, prediction, risk_score, risk_factors) VALUES (?, ?, ?, ?)',
            (raw_url, verdict, final_risk_score, json.dumps(risk_factors))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log scan to database: {e}")
        
    return jsonify({
        'url': raw_url,
        'normalized_url': normalized,
        'prediction': verdict,
        'risk_score': final_risk_score,
        'confidence': round(prediction_prob, 2),
        'features': feats,
        'risk_factors': risk_factors
    })

@app.route('/api/history', methods=['GET'])
def get_history():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, url, prediction, risk_score, risk_factors, timestamp FROM scans ORDER BY timestamp DESC LIMIT 50')
        rows = cursor.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'id': row['id'],
                'url': row['url'],
                'prediction': row['prediction'],
                'risk_score': row['risk_score'],
                'risk_factors': json.loads(row['risk_factors']),
                'timestamp': row['timestamp']
            })
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': f'Database query failed: {str(e)}'}), 500

@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Scan history item deleted successfully.'})
    except Exception as e:
        return jsonify({'error': f'Database operation failed: {str(e)}'}), 500

if __name__ == '__main__':
    init_db()
    # Run on default Flask port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
