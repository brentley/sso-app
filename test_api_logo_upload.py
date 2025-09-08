#!/usr/bin/env python3
"""
Test API logo upload methods that should work since manual upload works
"""

import requests
import base64
from PIL import Image
import io
import os

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def create_optimized_logo(logo_path, max_size=32):
    """Create optimized small logo"""
    try:
        with Image.open(logo_path) as img:
            # Create small optimized version
            small_img = img.resize((max_size, max_size), Image.Resampling.LANCZOS)
            
            img_buffer = io.BytesIO()
            small_img.save(img_buffer, format='PNG', optimize=True)
            img_buffer.seek(0)
            
            return img_buffer.getvalue()
    except Exception as e:
        print(f"Error creating optimized logo: {e}")
        return None

def test_create_zoom_with_logo():
    """Test creating Zoom app with logo since matching now works"""
    
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"  
    }
    
    # Create optimized logo
    logo_path = "/Users/brent/Documents/Logos/zoom.png"
    if not os.path.exists(logo_path):
        print("Zoom logo not found")
        return
        
    logo_data = create_optimized_logo(logo_path, 48)  # 48x48 pixels
    if not logo_data:
        return
        
    print(f"Created optimized logo: {len(logo_data)} bytes")
    
    # Create base64 data URL
    b64_data = base64.b64encode(logo_data).decode()
    data_url = f"data:image/png;base64,{b64_data}"
    
    print(f"Data URL length: {len(data_url)} characters")
    
    # Check if Zoom app already exists
    existing_response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/?slug=zoom-video-conferencing", headers=headers)
    if existing_response.status_code == 200 and existing_response.json().get('results'):
        print("Zoom app already exists, skipping...")
        return
    
    # Create app data
    app_data = {
        'name': 'Zoom - Video Conferencing',
        'slug': 'zoom-video-conferencing',
        'launch_url': 'https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIXOG62NLHB6A8QJBSVB/sso',
        'open_in_new_tab': True,
        'meta_launch_url': 'https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIXOG62NLHB6A8QJBSVB/sso',
        'meta_description': 'Migrated from Duo SSO with optimized logo',
        'meta_publisher': 'Duo Migration',
        'policy_engine_mode': 'any',
        'group': '',
        'meta_icon': data_url
    }
    
    try:
        response = requests.post(
            f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/",
            headers=headers,
            json=app_data
        )
        
        print(f"Create Zoom response: {response.status_code}")
        if response.status_code == 201:
            print("✅ Successfully created Zoom with logo!")
            result = response.json()
            print(f"PK: {result['pk']}")
            if result.get('meta_icon'):
                print("✅ Logo successfully embedded!")
            else:
                print("❌ No logo in result")
        else:
            print(f"❌ Failed: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_create_zoom_with_logo()