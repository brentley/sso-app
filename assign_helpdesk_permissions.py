#!/usr/bin/env python3
"""
Assign permissions to the Helpdesk role using the correct API endpoints
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
        return requests.get(url, headers=headers, timeout=15)
    elif method.upper() == 'POST':
        return requests.post(url, headers=headers, json=data, timeout=15)

def get_permission_codenames():
    """Get the specific permission codenames (strings) for helpdesk role"""
    
    # Define exactly what helpdesk should be able to do using codenames
    helpdesk_permissions = [
        # Core user management
        "authentik_core.view_user",
        "authentik_core.change_user", 
        "authentik_core.add_user",
        "authentik_core.reset_user_password",
        
        # User impersonation for troubleshooting
        "authentik_core.can_impersonate",
        
        # Group management (but not create/delete groups)  
        "authentik_core.view_group",
        "authentik_core.change_group",
        "authentik_core.add_user_to_group",
        "authentik_core.remove_user_from_group",
        
        # User-group relationships
        "authentik_core.view_usersourceconnection",
        "authentik_core.change_usersourceconnection",
        
        # User preview for troubleshooting
        "authentik_core.preview_user",
        "authentik_core.view_user_applications",
    ]
    
    return helpdesk_permissions

def assign_permissions_to_role(role_id, permission_codenames):
    """Assign permissions to a role using the correct API endpoint"""
    print(f"🔧 Assigning {len(permission_codenames)} permissions to Helpdesk role...")
    
    # Use the correct endpoint from the schema
    endpoint = f"/api/v3/rbac/permissions/assigned_by_roles/{role_id}/assign/"
    
    # Create the request payload according to PermissionAssignRequest schema
    assign_data = {
        "permissions": permission_codenames
        # object_pk is optional - omitting it means global assignment
        # model is optional as well
    }
    
    response = authentik_request('POST', endpoint, assign_data)
    
    if response.status_code in [200, 201]:
        print("✅ Successfully assigned permissions to Helpdesk role!")
        return True
    else:
        print(f"❌ Failed to assign permissions: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def verify_permissions(role_id):
    """Verify that permissions were assigned by checking the role"""
    print(f"\n🔍 Verifying permission assignment...")
    
    response = authentik_request('GET', f'/api/v3/rbac/roles/{role_id}/')
    if response.status_code == 200:
        role_data = response.json()
        global_perms = role_data.get('global_permissions', [])
        print(f"✅ Role now has {len(global_perms)} global permissions")
        
        # Also check assigned permissions endpoint
        response2 = authentik_request('GET', f'/api/v3/rbac/permissions/assigned_by_roles/')
        if response2.status_code == 200:
            assigned = response2.json().get('results', [])
            role_assignments = [a for a in assigned if a.get('role_uuid') == role_id]
            print(f"✅ Found {len(role_assignments)} permission assignments for this role")
            
            if role_assignments:
                print("📋 Assigned permissions:")
                for assignment in role_assignments[:10]:  # Show first 10
                    perm = assignment.get('permission_codename', 'unknown')
                    print(f"   - {perm}")
                if len(role_assignments) > 10:
                    print(f"   ... and {len(role_assignments) - 10} more")
        
        return len(global_perms) > 0 or len(role_assignments) > 0
    else:
        print(f"❌ Failed to verify: {response.status_code}")
        return False

def main():
    print("🚀 Assigning Permissions to Helpdesk Role")
    print("Purpose: Use the correct /rbac/permissions/assigned_by_roles/{uuid}/assign/ API")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Get permission codenames
        permissions = get_permission_codenames()
        print(f"📋 Permissions to assign:")
        for perm in permissions:
            print(f"   - {perm}")
        
        # Assign permissions
        success = assign_permissions_to_role(HELPDESK_ROLE_ID, permissions)
        
        if success:
            # Verify the assignment
            verified = verify_permissions(HELPDESK_ROLE_ID)
            
            if verified:
                print(f"\n🎉 SUCCESS!")
                print(f"   ✅ Helpdesk role permissions assigned and verified")
                print(f"   🔗 Role ID: {HELPDESK_ROLE_ID}")
                print(f"   📍 Check at: https://id.visiquate.com/if/admin/#/identity/roles")
                print(f"\n📖 HELPDESK STAFF CAN NOW:")
                print(f"   - View and edit user accounts")  
                print(f"   - Reset passwords")
                print(f"   - Create new users")
                print(f"   - Impersonate users for troubleshooting")
                print(f"   - Add/remove users from groups")
                print(f"   - View user application access")
                print(f"   - Preview user data for troubleshooting")
            else:
                print(f"\n⚠️ Permissions assigned but verification inconclusive")
        else:
            print(f"\n❌ Permission assignment failed")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()