#!/usr/bin/env python3
"""
Try using the /rbac/permissions/assigned_by_roles/{uuid}/assign/ endpoint
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
    
    if method.upper() == 'POST':
        response = requests.post(url, headers=headers, json=data, timeout=15)
    elif method.upper() == 'GET':
        response = requests.get(url, headers=headers, timeout=15)
    
    return response

def try_assign_endpoint():
    """Try the assign endpoint with permission IDs"""
    print("🔧 Testing /rbac/permissions/assigned_by_roles/{uuid}/assign/ endpoint...")
    
    # Try to assign permission IDs directly
    endpoint = f"/api/v3/rbac/permissions/assigned_by_roles/{HELPDESK_ROLE_ID}/assign/"
    
    # Test with just one permission first
    assign_data = {
        "permissions": [12]  # view_user permission ID
    }
    
    print(f"📋 Endpoint: {endpoint}")
    print(f"   Data: {assign_data}")
    
    response = authentik_request('POST', endpoint, assign_data)
    
    print(f"   Status Code: {response.status_code}")
    print(f"   Response Text: {response.text}")
    
    if response.status_code == 200:
        print(f"✅ Assignment request accepted")
        return True
    else:
        print(f"❌ Assignment request failed")
        
        # Try with codenames instead of IDs
        print(f"\n🔄 Trying with codenames instead of IDs...")
        
        assign_data_codenames = {
            "permissions": ["authentik_core.view_user"]  # Permission codename
        }
        
        print(f"   Data: {assign_data_codenames}")
        
        response2 = authentik_request('POST', endpoint, assign_data_codenames)
        
        print(f"   Status Code: {response2.status_code}")
        print(f"   Response Text: {response2.text}")
        
        if response2.status_code == 200:
            print(f"✅ Assignment with codenames accepted")
            return True
        else:
            print(f"❌ Assignment with codenames also failed")
            return False

def check_assigned_permissions():
    """Check what permissions are assigned to roles"""
    print(f"\n🔍 Checking assigned permissions endpoint...")
    
    response = authentik_request('GET', '/api/v3/rbac/permissions/assigned_by_roles/')
    
    if response.status_code == 200:
        data = response.json()
        results = data.get('results', [])
        
        print(f"✅ Found {len(results)} permission assignments")
        
        # Look for assignments to our role
        helpdesk_assignments = [r for r in results if r.get('role_uuid') == HELPDESK_ROLE_ID]
        
        if helpdesk_assignments:
            print(f"🎯 Found {len(helpdesk_assignments)} assignments for Helpdesk role:")
            for assignment in helpdesk_assignments:
                perm = assignment.get('permission_codename', 'unknown')
                obj_pk = assignment.get('object_pk', 'global')
                print(f"   - {perm} (object: {obj_pk})")
        else:
            print(f"❌ No assignments found for Helpdesk role")
    else:
        print(f"❌ Failed to check assignments: {response.status_code}")
        print(f"   Response: {response.text}")

def main():
    print("🚀 Testing Permission Assignment Endpoint")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Check current assignments first
        check_assigned_permissions()
        
        # Try assignment endpoint
        success = try_assign_endpoint()
        
        if success:
            print(f"\n🔄 Rechecking assignments after assignment attempt...")
            check_assigned_permissions()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()