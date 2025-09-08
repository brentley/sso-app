#!/usr/bin/env python3
"""
Final script to assign all Helpdesk permissions using the correct codename format
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

def assign_all_helpdesk_permissions():
    """Assign all required permissions using correct codename format"""
    print("🔧 Assigning all Helpdesk permissions using correct format...")
    
    # All the permissions we need in app_label.codename format
    helpdesk_permissions = [
        # Core user management
        "authentik_core.view_user",
        "authentik_core.change_user", 
        "authentik_core.add_user",
        "authentik_core.reset_user_password",
        "authentik_core.impersonate",  # User impersonation
        
        # Group management
        "authentik_core.view_group",
        "authentik_core.change_group",
        "authentik_core.add_user_to_group",
        "authentik_core.remove_user_from_group",
        
        # User connections and troubleshooting
        "authentik_core.view_usersourceconnection",
        "authentik_core.preview_user",
        "authentik_core.view_user_applications"
    ]
    
    endpoint = f"/api/v3/rbac/permissions/assigned_by_roles/{HELPDESK_ROLE_ID}/assign/"
    
    print(f"📋 Assigning {len(helpdesk_permissions)} permissions:")
    for perm in helpdesk_permissions:
        print(f"   - {perm}")
    
    assign_data = {
        "permissions": helpdesk_permissions
    }
    
    response = authentik_request('POST', endpoint, assign_data)
    
    print(f"\n📡 Assignment request:")
    print(f"   Status Code: {response.status_code}")
    print(f"   Response: {response.text}")
    
    if response.status_code == 200:
        print(f"✅ All permissions assigned successfully!")
        try:
            response_data = response.json()
            assigned_count = len(response_data) if isinstance(response_data, list) else 1
            print(f"   📊 Assigned {assigned_count} permissions")
        except:
            print(f"   📊 Assignment completed")
        return True
    else:
        print(f"❌ Assignment failed")
        return False

def verify_permissions_via_assigned_endpoint():
    """Check assignments via the assigned_by_roles endpoint with proper parameters"""
    print(f"\n🔍 Verifying permissions via assignments endpoint...")
    
    # Try checking with role_uuid parameter
    response = authentik_request('GET', f'/api/v3/rbac/permissions/assigned_by_roles/?role_uuid={HELPDESK_ROLE_ID}')
    
    if response.status_code == 200:
        data = response.json()
        results = data.get('results', [])
        
        print(f"✅ Found {len(results)} permission assignments for Helpdesk role")
        
        if results:
            print(f"📋 Assigned permissions:")
            for assignment in results:
                perm = assignment.get('permission_codename', 'unknown')
                obj_pk = assignment.get('object_pk', 'global')
                scope = 'global' if obj_pk is None else f'object {obj_pk}'
                print(f"   ✅ {perm} ({scope})")
            return True
        else:
            print(f"❌ No permissions found")
            return False
    else:
        print(f"❌ Failed to check assignments: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def main():
    print("🚀 Final Helpdesk Permission Assignment")
    print("Using the correct /rbac/permissions/assigned_by_roles/{uuid}/assign/ endpoint")
    print("with app_label.codename format")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Assign all permissions
        success = assign_all_helpdesk_permissions()
        
        if success:
            # Verify assignments
            verified = verify_permissions_via_assigned_endpoint()
            
            if verified:
                print(f"\n🎉 SUCCESS!")
                print(f"   ✅ Helpdesk role permissions successfully assigned and verified")
                print(f"   📍 View role at: https://id.visiquate.com/if/admin/#/identity/roles")
                print(f"   🔗 Role ID: {HELPDESK_ROLE_ID}")
                print(f"\n🔧 HELPDESK STAFF CAN NOW:")
                print(f"   ✅ View, edit, create users and reset passwords")  
                print(f"   ✅ Impersonate users for troubleshooting")
                print(f"   ✅ Manage user group memberships")
                print(f"   ✅ View user connections and application access")
                print(f"   ✅ Preview user data for support purposes")
            else:
                print(f"\n⚠️ Permissions assigned but verification had issues")
                print(f"   Check the Authentik admin UI to confirm")
        else:
            print(f"\n❌ Permission assignment failed")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()