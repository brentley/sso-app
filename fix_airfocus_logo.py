#!/usr/bin/env python3
"""
Fix Airfocus logo - create smaller version and upload
"""

import requests
import os
import base64
from PIL import Image
import io

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def create_small_logo():
    """Create a very small version of the Airfocus logo"""
    logo_path = "/Users/brent/Documents/Logos/airfocus_square.png"
    
    if not os.path.exists(logo_path):
        print(f"Logo file not found: {logo_path}")
        return None
    
    try:
        with Image.open(logo_path) as img:
            # Create a very small version - 64x64 pixels
            small_img = img.resize((64, 64), Image.Resampling.LANCZOS)
            
            # Convert to bytes
            img_buffer = io.BytesIO()
            small_img.save(img_buffer, format='PNG', optimize=True)
            img_buffer.seek(0)
            
            small_logo_data = img_buffer.getvalue()
            print(f"Created small logo: {len(small_logo_data)} bytes (was {os.path.getsize(logo_path)})")
            return small_logo_data
            
    except Exception as e:
        print(f"Error creating small logo: {e}")
        return None

def update_airfocus_with_small_logo():
    """Update Airfocus with a very small logo that should work"""
    
    # Get current Airfocus application
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
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
    print(f"Found Airfocus app: {airfocus_app['name']} ({app_pk})")
    
    # Create small logo
    small_logo_data = create_small_logo()
    if not small_logo_data:
        return
    
    # Create base64 data URL with small logo
    b64_data = base64.b64encode(small_logo_data).decode()
    data_url = f"data:image/png;base64,{b64_data}"
    
    print(f"Data URL length: {len(data_url)} characters")
    
    # Update the application
    update_data = {
        'meta_icon': data_url,
        'meta_description': 'Migrated from Duo SSO with small embedded logo'
    }
    
    try:
        response = requests.patch(
            f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/{app_pk}/",
            headers=headers,
            json=update_data
        )
        
        print(f"Update response: {response.status_code}")
        if response.status_code == 200:
            print("✅ Successfully updated Airfocus with small logo!")
            result = response.json()
            if result.get('meta_icon'):
                print(f"Logo updated - length: {len(result['meta_icon'])} chars")
            else:
                print("No logo in response")
        else:
            print(f"❌ Failed to update: {response.text}")
            
    except Exception as e:
        print(f"Error updating application: {e}")

def list_all_current_apps():
    """List all current applications to see what exists"""
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/", headers=headers)
    if response.status_code == 200:
        apps = response.json().get('results', [])
        print(f"\nFound {len(apps)} applications:")
        for app in apps:
            icon_status = "📷" if app.get('meta_icon') else "❌"
            print(f"  {icon_status} {app['name']} ({app['slug']}) - PK: {app['pk']}")
    else:
        print(f"Failed to list applications: {response.status_code}")

if __name__ == "__main__":
    list_all_current_apps()
    update_airfocus_with_small_logo()