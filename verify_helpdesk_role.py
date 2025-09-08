#!/usr/bin/env python3
"""
Simple verification script to check the Helpdesk role permissions
"""

import requests
import json

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"
HELPDESK_ROLE_ID = "b0303790-5a7f-42f1-ac13-cdd30146b816"

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

def verify_role_permissions():
    """Check the Helpdesk role and its permissions"""
    print("🔍 Verifying Helpdesk role permissions...")
    
    # Get the role details
    response = authentik_request('GET', f'/api/v3/rbac/roles/{HELPDESK_ROLE_ID}/')
    
    if response.status_code == 200:
        role_data = response.json()
        
        print(f"✅ Role found: {role_data.get('name', 'Unknown')}")
        print(f"   📋 Role ID: {role_data.get('uuid', 'Unknown')}")
        
        global_permissions = role_data.get('global_permissions', [])
        print(f"   🔧 Global permissions count: {len(global_permissions)}")
        
        if global_permissions:
            print(f"\n📊 Permission IDs assigned to role:")
            for i, perm_id in enumerate(global_permissions[:20]):  # Show first 20
                print(f"   {i+1:2d}. Permission ID: {perm_id}")
            
            if len(global_permissions) > 20:
                print(f"   ... and {len(global_permissions) - 20} more permissions")
        else:
            print("   ❌ No global permissions found")
        
        return len(global_permissions) > 0
    else:
        print(f"❌ Failed to get role: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def main():
    print("🚀 Verifying Helpdesk Role Permissions")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Verify role permissions
        has_permissions = verify_role_permissions()
        
        if has_permissions:
            print(f"\n🎉 SUCCESS!")
            print(f"   ✅ Helpdesk role has permissions assigned")
            print(f"   📍 View in UI: https://id.visiquate.com/if/admin/#/identity/roles")
        else:
            print(f"\n❌ Helpdesk role has no permissions assigned")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()