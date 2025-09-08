#!/usr/bin/env python3
"""
Check how Authentik stores media/icons for applications
"""

import requests
import json

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def check_applications_with_icons():
    """Check existing applications that have icons"""
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # Get all applications
    response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/", headers=headers)
    
    if response.status_code != 200:
        print(f"Failed to get applications: {response.status_code}")
        return
    
    applications = response.json().get('results', [])
    print(f"Found {len(applications)} applications")
    
    # Find applications with icons
    apps_with_icons = []
    for app in applications:
        if app.get('meta_icon'):
            apps_with_icons.append({
                'name': app.get('name'),
                'slug': app.get('slug'),
                'meta_icon': app.get('meta_icon')
            })
    
    print(f"\nApplications with icons ({len(apps_with_icons)}):")
    for app in apps_with_icons:
        print(f"  - {app['name']}: {app['meta_icon']}")
    
    return apps_with_icons

def check_media_endpoints():
    """Try different media-related API endpoints"""
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    endpoints = [
        "/api/v3/",
        "/api/v3/core/",
        "/api/v3/core/media/",
        "/api/v3/media/",
        "/media/",
        "/static/",
    ]
    
    print("\nChecking media endpoints:")
    for endpoint in endpoints:
        try:
            response = requests.get(f"{AUTHENTIK_BASE_URL}{endpoint}", headers=headers, timeout=5)
            print(f"  {endpoint}: {response.status_code}")
            if response.status_code == 200:
                content = response.text[:200]
                print(f"    Content preview: {content}")
        except Exception as e:
            print(f"  {endpoint}: Error - {e}")

if __name__ == "__main__":
    apps_with_icons = check_applications_with_icons()
    check_media_endpoints()