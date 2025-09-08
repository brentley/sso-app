#!/usr/bin/env python3
"""
List all roles to verify the Helpdesk role UUID
"""

import requests
import json

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def authentik_request(method, endpoint, data=None):
    """Make authenticated request to Authentik API"""
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{AUTHENTIK_BASE_URL}{endpoint}"
    
    if method.upper() == 'GET':
        response = requests.get(url, headers=headers, timeout=15)
    
    return response

def list_all_roles():
    """List all roles"""
    print("🔍 Listing all roles...")
    
    response = authentik_request('GET', '/api/v3/rbac/roles/')
    
    if response.status_code == 200:
        roles = response.json().get('results', [])
        print(f"✅ Found {len(roles)} roles")
        
        helpdesk_found = False
        
        for role in roles:
            name = role.get('name', 'Unknown')
            uuid = role.get('uuid', role.get('pk', 'Unknown'))
            global_perms = role.get('global_permissions', [])
            
            print(f"   📋 {name}")
            print(f"      UUID: {uuid}")
            print(f"      Global permissions: {len(global_perms)}")
            
            if name == 'Helpdesk':
                helpdesk_found = True
                print(f"      ⭐ THIS IS THE HELPDESK ROLE")
                if global_perms:
                    print(f"      Permission IDs: {global_perms}")
                else:
                    print(f"      ❌ No permissions assigned")
            print()
        
        if not helpdesk_found:
            print("❌ Helpdesk role not found!")
            
    else:
        print(f"❌ Failed to list roles: {response.status_code}")
        print(f"   Response: {response.text}")

def main():
    print("🚀 Listing All Roles")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        list_all_roles()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()