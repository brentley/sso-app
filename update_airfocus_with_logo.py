#!/usr/bin/env python3
"""
Update existing Airfocus application with logo
"""

import requests
import os
import base64

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def update_airfocus_logo():
    """Try to update the existing Airfocus application with logo"""
    
    # First, get the existing Airfocus application
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Get Airfocus app
    response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/?slug=airfocus", headers=headers)
    if response.status_code != 200:
        print(f"Failed to get Airfocus app: {response.status_code}")
        return
    
    apps = response.json().get('results', [])
    if not apps:
        print("Airfocus app not found")
        return
    
    airfocus_app = apps[0]
    app_pk = airfocus_app['pk']
    print(f"Found Airfocus app: {app_pk}")
    
    # Try different logo approaches
    logo_path = "/Users/brent/Documents/Logos/airfocus_square.png"
    
    if not os.path.exists(logo_path):
        print(f"Logo file not found: {logo_path}")
        return
    
    # Approach 1: Try PATCH with base64 data URL (smaller image)
    print("Trying PATCH with base64 data URL...")
    with open(logo_path, 'rb') as f:
        logo_data = f.read()
    
    # Create a smaller version if too big
    if len(logo_data) > 50000:  # 50KB limit
        print(f"Logo is large ({len(logo_data)} bytes), trying to use file path reference...")
        # Try just referencing the file path
        update_data = {
            'meta_icon': f"/media/public/application-icons/airfocus_square.png",
            'meta_description': f'Migrated from Duo SSO. Logo: {logo_path}'
        }
    else:
        b64_data = base64.b64encode(logo_data).decode()
        data_url = f"data:image/png;base64,{b64_data}"
        update_data = {
            'meta_icon': data_url,
            'meta_description': 'Migrated from Duo SSO with embedded logo'
        }
    
    try:
        response = requests.patch(
            f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/{app_pk}/",
            headers=headers,
            json=update_data
        )
        
        print(f"PATCH response: {response.status_code}")
        if response.status_code == 200:
            print("✅ Successfully updated Airfocus with logo!")
            result = response.json()
            print(f"Meta icon: {result.get('meta_icon', 'None')[:100]}...")
        else:
            print(f"❌ Failed to update: {response.text}")
            
    except Exception as e:
        print(f"Error updating application: {e}")

    # Approach 2: Try multipart file upload to specific application
    print("\nTrying multipart upload to application endpoint...")
    try:
        files = {'file': ('airfocus_square.png', logo_data, 'image/png')}
        response = requests.post(
            f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/{app_pk}/set_icon/",
            headers={"Authorization": f"Bearer {AUTHENTIK_TOKEN}"},
            files=files
        )
        print(f"File upload response: {response.status_code}")
        if response.status_code < 400:
            print(f"Response: {response.text}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"File upload error: {e}")

if __name__ == "__main__":
    update_airfocus_logo()