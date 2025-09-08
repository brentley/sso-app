#!/usr/bin/env python3
"""
Test permission assignment on the test role to see if it's a role-specific issue
"""

import requests
import json

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"
TEST_ROLE_ID = "56c8e63d-5790-4e72-a102-09c92e8001ac"  # The test role

def authentik_request(method, endpoint, data=None):
    """Make authenticated request to Authentik API"""
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{AUTHENTIK_BASE_URL}{endpoint}"
    
    if method.upper() == 'PATCH':
        response = requests.patch(url, headers=headers, json=data, timeout=15)
    elif method.upper() == 'GET':
        response = requests.get(url, headers=headers, timeout=15)
    
    return response

def test_permission_assignment():
    """Test assigning a single permission to the test role"""
    print("🧪 Testing permission assignment on test role...")
    
    # Try to assign just one simple permission (view_user = ID 12)
    update_data = {
        "global_permissions": [12]
    }
    
    print(f"📋 Attempting to assign permission ID 12 (view_user)")
    
    response = authentik_request('PATCH', f'/api/v3/rbac/roles/{TEST_ROLE_ID}/', update_data)
    
    print(f"   Status Code: {response.status_code}")
    print(f"   Response Text: {response.text}")
    
    if response.status_code == 200:
        print(f"✅ API accepted the request")
        
        # Now check if it actually worked
        verify_response = authentik_request('GET', f'/api/v3/rbac/roles/{TEST_ROLE_ID}/')
        
        if verify_response.status_code == 200:
            role_data = verify_response.json()
            global_perms = role_data.get('global_permissions', [])
            
            print(f"🔍 Verification: Role has {len(global_perms)} permissions")
            if global_perms:
                print(f"   ✅ SUCCESS! Permissions: {global_perms}")
                return True
            else:
                print(f"   ❌ FAILED! Still 0 permissions after assignment")
                return False
        else:
            print(f"   ❌ Failed to verify: {verify_response.status_code}")
            return False
    else:
        print(f"❌ API rejected the request")
        return False

def examine_role_structure():
    """Examine the exact structure of a role to understand fields"""
    print(f"\n🔍 Examining role structure...")
    
    response = authentik_request('GET', f'/api/v3/rbac/roles/{TEST_ROLE_ID}/')
    
    if response.status_code == 200:
        role_data = response.json()
        print(f"📋 Role structure:")
        for key, value in role_data.items():
            print(f"   {key}: {value}")
    else:
        print(f"❌ Failed to get role structure: {response.status_code}")

def main():
    print("🚀 Testing Permission Assignment")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Examine role structure first
        examine_role_structure()
        
        # Test permission assignment
        test_permission_assignment()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()