#!/usr/bin/env python3
"""
Test different approaches to upload logo to Authentik
"""

import requests
import os

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def test_media_endpoints():
    """Test various media upload endpoints"""
    
    logo_path = "/Users/brent/Documents/Logos/airfocus_square.png"
    
    if not os.path.exists(logo_path):
        print(f"Logo file not found: {logo_path}")
        return
    
    # Try different upload approaches
    endpoints_to_try = [
        "/api/v3/core/applications/set_icon/",
        "/api/v3/media/",
        "/media/",
        "/static/dist/assets/icons/",
        "/if/admin/core/application/set_icon/",
        "/api/v3/core/applications/upload_icon/",
    ]
    
    headers = {"Authorization": f"Bearer {AUTHENTIK_TOKEN}"}
    
    with open(logo_path, 'rb') as f:
        logo_data = f.read()
    
    print(f"Testing upload of {logo_path} ({len(logo_data)} bytes)")
    
    for endpoint in endpoints_to_try:
        print(f"\n🔍 Testing endpoint: {endpoint}")
        
        # Try multipart upload
        try:
            files = {'file': ('airfocus_square.png', logo_data, 'image/png')}
            response = requests.post(
                f"{AUTHENTIK_BASE_URL}{endpoint}",
                headers=headers,
                files=files,
                timeout=10
            )
            print(f"   Status: {response.status_code}")
            if response.status_code < 400:
                print(f"   Response: {response.text[:200]}")
            else:
                print(f"   Error: {response.text[:100]}")
        except Exception as e:
            print(f"   Exception: {e}")

def explore_api_structure():
    """Explore Authentik API structure for media/file operations"""
    
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    endpoints_to_check = [
        "/api/v3/",
        "/api/v3/core/",
        "/api/v3/core/applications/",
    ]
    
    print("\n📋 Exploring API structure:")
    for endpoint in endpoints_to_check:
        try:
            response = requests.options(f"{AUTHENTIK_BASE_URL}{endpoint}", headers=headers)
            print(f"\n{endpoint}:")
            print(f"  Allowed methods: {response.headers.get('Allow', 'Not specified')}")
            
            # Try GET to see available operations
            get_response = requests.get(f"{AUTHENTIK_BASE_URL}{endpoint}", headers=headers)
            if get_response.status_code == 200:
                content = get_response.text
                # Look for file/upload/media related fields
                if 'file' in content.lower() or 'upload' in content.lower() or 'icon' in content.lower():
                    print(f"  Contains file/upload/icon references")
                    
        except Exception as e:
            print(f"  Error exploring {endpoint}: {e}")

def check_existing_apps_with_icons():
    """Check how existing apps store their icons"""
    
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Get apps with icons
    response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/", headers=headers)
    if response.status_code == 200:
        apps = response.json().get('results', [])
        apps_with_icons = [app for app in apps if app.get('meta_icon')]
        
        print(f"\n🖼️ Found {len(apps_with_icons)} applications with icons:")
        for app in apps_with_icons[:3]:  # Show first 3
            print(f"  - {app['name']}: {app['meta_icon']}")
            
        if apps_with_icons:
            print(f"\nIcon URL pattern: {apps_with_icons[0]['meta_icon']}")

if __name__ == "__main__":
    check_existing_apps_with_icons()
    explore_api_structure() 
    test_media_endpoints()