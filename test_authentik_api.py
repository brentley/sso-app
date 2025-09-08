#!/usr/bin/env python3
"""
Quick test of Authentik API connection
"""

import requests
import time

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def test_api():
    print("Testing Authentik API...")
    
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Test simple API call
    start = time.time()
    response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/core/users/?limit=1", headers=headers, timeout=10)
    duration = time.time() - start
    
    print(f"Response: {response.status_code} ({duration:.2f}s)")
    print(f"Content: {response.text[:200]}")
    
    if response.status_code == 200:
        print("✅ API is working")
    else:
        print("❌ API failed")

if __name__ == "__main__":
    test_api()