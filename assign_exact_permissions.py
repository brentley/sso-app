#!/usr/bin/env python3
"""
Assign the exact permission IDs we found to the Helpdesk role
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
    
    if method.upper() == 'PATCH':
        response = requests.patch(url, headers=headers, json=data, timeout=15)
    elif method.upper() == 'GET':
        response = requests.get(url, headers=headers, timeout=15)
    
    return response

def assign_permissions():
    """Assign the exact permissions we need"""
    print("🔧 Assigning specific permissions to Helpdesk role...")
    
    # These are the exact permission IDs we found:
    # 9: add_user, 10: change_user, 12: view_user, 13: reset_user_password, 14: impersonate
    # 5: add_user_to_group, 6: remove_user_from_group, 2: change_group, 4: view_group
    # Plus some additional useful ones: 38: view_usersourceconnection, 17: preview_user, 18: view_user_applications
    permission_ids = [9, 10, 12, 13, 14, 5, 6, 2, 4, 38, 17, 18]
    
    permission_names = {
        9: "add_user",
        10: "change_user",
        12: "view_user", 
        13: "reset_user_password",
        14: "impersonate",
        5: "add_user_to_group",
        6: "remove_user_from_group",
        2: "change_group",
        4: "view_group",
        38: "view_usersourceconnection",
        17: "preview_user",
        18: "view_user_applications"
    }
    
    print(f"📋 Assigning {len(permission_ids)} permissions:")
    for perm_id in permission_ids:
        name = permission_names.get(perm_id, "unknown")
        print(f"   {perm_id:2d}: {name}")
    
    update_data = {
        "global_permissions": permission_ids
    }
    
    response = authentik_request('PATCH', f'/api/v3/rbac/roles/{HELPDESK_ROLE_ID}/', update_data)
    
    if response.status_code == 200:
        print(f"✅ Successfully assigned permissions to Helpdesk role!")
        return True
    else:
        print(f"❌ Failed to assign permissions: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def verify_assignment():
    """Verify the permission assignment worked"""
    print(f"\n🔍 Verifying assignment...")
    
    response = authentik_request('GET', f'/api/v3/rbac/roles/{HELPDESK_ROLE_ID}/')
    
    if response.status_code == 200:
        role_data = response.json()
        global_perms = role_data.get('global_permissions', [])
        
        print(f"✅ Role has {len(global_perms)} global permissions")
        if global_perms:
            print(f"   Permission IDs: {global_perms}")
            return True
        else:
            print(f"   ❌ No permissions found")
            return False
    else:
        print(f"❌ Failed to verify: {response.status_code}")
        return False

def main():
    print("🚀 Assigning Exact Permissions to Helpdesk Role")
    
    try:
        # Test API connection  
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Assign permissions
        success = assign_permissions()
        
        if success:
            # Verify
            verified = verify_assignment()
            
            if verified:
                print(f"\n🎉 SUCCESS!")
                print(f"   ✅ Helpdesk role permissions successfully assigned and verified")
                print(f"   📍 Check at: https://id.visiquate.com/if/admin/#/identity/roles")
                print(f"   🔧 Role ID: {HELPDESK_ROLE_ID}")
                print(f"\n📖 HELPDESK STAFF CAN NOW:")
                print(f"   ✅ View, edit, create, and reset user accounts")  
                print(f"   ✅ Impersonate users for troubleshooting")
                print(f"   ✅ Add/remove users from groups")
                print(f"   ✅ View groups and user connections")
                print(f"   ✅ Preview user data and application access")
            else:
                print(f"\n⚠️  Assignment may have failed - verification inconclusive")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()