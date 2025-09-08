#!/usr/bin/env python3
"""
Debug single application creation with actual data
"""

import requests
import re
from pathlib import Path

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def test_create_jamf_app():
    """Test creating Jamf app with actual data from migration"""
    
    app_name = "Jamf"
    sso_url = "https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIK7DS1O1O4NMHRYXVV2/sso"
    logo_path = "/Users/brent/Documents/Logos/jamf.png"
    
    # Create the application data exactly as in migration
    app_data = {
        'name': app_name,
        'slug': re.sub(r'[^a-z0-9-]', '-', app_name.lower().replace(' ', '-')),
        'launch_url': sso_url,
        'open_in_new_tab': True,
        'meta_launch_url': sso_url,
        'meta_description': f'Migrated from Duo SSO. Square logo available at: {Path(logo_path).parent}/{Path(logo_path).stem}_square.png',
        'meta_publisher': 'Duo Migration',
        'policy_engine_mode': 'any',
        'group': ''
    }
    
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    print("Testing Jamf application creation with data:")
    print(app_data)
    print()
    
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
    test_create_jamf_app()