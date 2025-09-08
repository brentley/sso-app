#!/usr/bin/env python3
"""
Test creating a single application with detailed error reporting
"""

import requests
import re

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def test_create_app():
    """Test creating a simple application"""
    
    # Create the simplest possible application data
    app_data = {
        'name': 'Test Migration App',
        'slug': 'test-migration-app',
        'launch_url': 'https://example.com',
        'open_in_new_tab': True,
        'meta_launch_url': 'https://example.com',
        'meta_description': '',
        'meta_publisher': '',
        'policy_engine_mode': 'any'
    }
    
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    print("Testing application creation with data:")
    print(app_data)
    
    try:
        response = requests.post(
            f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/", 
            headers=headers, 
            json=app_data, 
            timeout=30
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response text: {response.text}")
        
        if response.status_code in [200, 201]:
            print("✅ Success!")
            return response.json()
        else:
            print("❌ Failed")
            
    except Exception as e:
        print(f"Error: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"Response: {e.response.text}")

if __name__ == "__main__":
    test_create_app()