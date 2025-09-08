#!/usr/bin/env python3
"""
Simple approach - recreate Airfocus with logo
"""

import requests
import base64
from PIL import Image
import io

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def create_tiny_logo():
    """Create a tiny 32x32 logo"""
    logo_path = "/Users/brent/Documents/Logos/airfocus_square.png"
    
    try:
        with Image.open(logo_path) as img:
            # Create tiny version - 32x32 pixels
            tiny_img = img.resize((32, 32), Image.Resampling.LANCZOS)
            
            img_buffer = io.BytesIO()
            tiny_img.save(img_buffer, format='PNG', optimize=True, quality=85)
            img_buffer.seek(0)
            
            return img_buffer.getvalue()
    except Exception as e:
        print(f"Error: {e}")
        return None

def delete_and_recreate_airfocus():
    """Delete existing Airfocus and recreate with logo"""
    
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Get existing app
    response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/?slug=airfocus", headers=headers)
    if response.status_code == 200:
        apps = response.json().get('results', [])
        if apps:
            app_pk = apps[0]['pk']
            print(f"Deleting existing Airfocus app: {app_pk}")
            
            # Delete existing app
            delete_response = requests.delete(f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/{app_pk}/", headers=headers)
            print(f"Delete response: {delete_response.status_code}")
    
    # Create tiny logo
    logo_data = create_tiny_logo()
    if logo_data:
        b64_data = base64.b64encode(logo_data).decode()
        data_url = f"data:image/png;base64,{b64_data}"
        print(f"Tiny logo: {len(logo_data)} bytes, data URL: {len(data_url)} chars")
    else:
        data_url = None
    
    # Recreate application with logo
    app_data = {
        'name': 'AirFocus',
        'slug': 'airfocus',
        'launch_url': 'https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIAQOWT6AJ9SA500JM4X/sso',
        'open_in_new_tab': True,
        'meta_launch_url': 'https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIAQOWT6AJ9SA500JM4X/sso',
        'meta_description': 'Migrated from Duo SSO with logo',
        'meta_publisher': 'Duo Migration',
        'policy_engine_mode': 'any',
        'group': ''
    }
    
    if data_url:
        app_data['meta_icon'] = data_url
    
    try:
        response = requests.post(
            f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/",
            headers=headers,
            json=app_data
        )
        
        print(f"Create response: {response.status_code}")
        if response.status_code == 201:
            print("✅ Successfully recreated Airfocus with logo!")
            result = response.json()
            print(f"New PK: {result['pk']}")
            if result.get('meta_icon'):
                print(f"✅ Logo successfully embedded!")
            else:
                print("❌ No logo in result")
        else:
            print(f"❌ Failed: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    delete_and_recreate_airfocus()