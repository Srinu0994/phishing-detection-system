import requests
import json

def test_api():
    print("="*50)
    print("Testing Phishing Detector API Endpoints...")
    print("="*50)
    
    # 1. Test GET /api/history when empty (or with existing scans)
    print("\n1. Testing GET /api/history (Initial Fetch)")
    try:
        r = requests.get("http://127.0.0.1:5000/api/history")
        print(f"Status Code: {r.status_code}")
        print(f"Response length: {len(r.json())} items")
    except Exception as e:
        print(f"API Request Failed: {e}")
        return
    
    # 2. Test POST /api/analyze for a benign URL
    print("\n2. Testing POST /api/analyze (Benign URL: https://www.google.com)")
    payload = {"url": "https://www.google.com"}
    r = requests.post("http://127.0.0.1:5000/api/analyze", json=payload)
    print(f"Status Code: {r.status_code}")
    res_data = r.json()
    print(f"Verdict: {res_data.get('prediction')}")
    print(f"Risk Score: {res_data.get('risk_score')}%")
    print(f"Risk Factors: {res_data.get('risk_factors')}")
    
    # 3. Test POST /api/analyze for a phishing URL
    print("\n3. Testing POST /api/analyze (Phishing URL: http://login-verify-secure-update.bit.ly/login)")
    payload = {"url": "http://login-verify-secure-update.bit.ly/login"}
    r = requests.post("http://127.0.0.1:5000/api/analyze", json=payload)
    print(f"Status Code: {r.status_code}")
    res_data = r.json()
    print(f"Verdict: {res_data.get('prediction')}")
    print(f"Risk Score: {res_data.get('risk_score')}%")
    print(f"Risk Factors: {res_data.get('risk_factors')}")
    
    # 4. Test GET /api/history again (should contain the new scans)
    print("\n4. Testing GET /api/history (After Scans)")
    r = requests.get("http://127.0.0.1:5000/api/history")
    print(f"Status Code: {r.status_code}")
    print(f"Number of scans in history: {len(r.json())} items")
    print(f"Latest item in history: URL='{r.json()[0]['url']}' Verdict='{r.json()[0]['prediction']}'")
    print("="*50)

if __name__ == "__main__":
    test_api()
