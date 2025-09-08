#!/usr/bin/env python3
"""
Fix the Helpdesk Role by properly fetching ALL permissions (585) and assigning appropriate ones
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
    elif method.upper() == 'PATCH':
        response = requests.patch(url, headers=headers, json=data, timeout=15)
    
    return response

def get_all_permissions():
    """Get ALL global permissions with proper pagination"""
    print("🔍 Fetching all global permissions...")
    
    all_permissions = []
    offset = 0
    limit = 100
    max_iterations = 10  # Safety limit
    iteration = 0
    
    while iteration < max_iterations:
        response = authentik_request('GET', f'/api/v3/rbac/permissions/?limit={limit}&offset={offset}')
        
        if response.status_code != 200:
            print(f"❌ Failed to fetch permissions: {response.status_code}")
            break
        
        data = response.json()
        batch = data.get('results', [])
        
        print(f"   Batch {iteration + 1}: {len(batch)} permissions")
        
        if not batch:
            break
            
        all_permissions.extend(batch)
        
        if len(batch) < limit:
            break
            
        offset += limit
        iteration += 1
    
    print(f"✅ Found {len(all_permissions)} total global permissions")
    return all_permissions

def select_helpdesk_permissions(all_permissions):
    """Select appropriate permissions for helpdesk role"""
    print("\n📊 Analyzing permissions for helpdesk role...")
    
    # Define exactly what helpdesk should be able to do
    helpdesk_permission_codenames = [
        # Core user management
        'view_user',
        'change_user', 
        'add_user',
        'reset_user_password',
        'can_impersonate',  # User impersonation for troubleshooting
        
        # Group management (but not create/delete groups)
        'view_group',
        'change_group',
        'add_user_to_group',
        'remove_user_from_group',
        
        # User-group relationships
        'view_usersourceconnection',
        'change_usersourceconnection',
        
        # User preview for troubleshooting
        'preview_user',
        'view_user_applications',
        
        # User session management
        'view_usersession',
        'change_usersession',
        
        # Token management for user support
        'view_token',
        
        # Group source connections
        'view_groupsourceconnection',
        'change_groupsourceconnection'
    ]
    
    # Permissions to absolutely exclude (dangerous for helpdesk)
    forbidden_patterns = [
        'delete_',
        'add_group',
        'superuser',
        'application',
        'flow',
        'provider',
        'stage',
        'source',
        'brand',
        'tenant',
        'certificate',
        'policy',
        'property',
        'blueprint',
        'reputation'
    ]
    
    permission_ids = []
    allowed_permissions = []
    
    print("✅ HELPDESK PERMISSIONS (user support functions):")
    for perm in all_permissions:
        codename = perm.get('codename', '')
        name = perm.get('name', '')
        app_label = perm.get('app_label', '')
        perm_id = perm.get('id')
        
        # Check if it's a desired helpdesk permission
        if codename in helpdesk_permission_codenames:
            # Make sure it's not forbidden
            is_forbidden = any(pattern in codename.lower() for pattern in forbidden_patterns)
            
            if not is_forbidden:
                permission_ids.append(perm_id)
                allowed_permissions.append(f"{app_label}.{codename}")
                print(f"   ✅ {app_label}.{codename}: {name}")
    
    # Also include any user/group related permissions that aren't dangerous
    for perm in all_permissions:
        codename = perm.get('codename', '')
        name = perm.get('name', '')
        app_label = perm.get('app_label', '')
        perm_id = perm.get('id')
        
        # Skip if already included
        if perm_id in permission_ids:
            continue
            
        # Include safe user/group permissions
        if ('user' in codename.lower() or 'group' in codename.lower()) and app_label == 'authentik_core':
            is_forbidden = any(pattern in codename.lower() for pattern in forbidden_patterns)
            
            if not is_forbidden:
                permission_ids.append(perm_id)
                allowed_permissions.append(f"{app_label}.{codename}")
                print(f"   ✅ {app_label}.{codename}: {name}")
    
    print(f"\n❌ FORBIDDEN PERMISSION PATTERNS (excluded from helpdesk):")
    for pattern in forbidden_patterns[:10]:  # Show first 10
        print(f"   ❌ *{pattern}* - anything containing '{pattern}'")
                
    print(f"\n📊 SUMMARY: {len(permission_ids)} permissions selected for helpdesk role")
    return permission_ids, allowed_permissions

def update_helpdesk_role(permission_ids):
    """Update the helpdesk role with proper permissions"""
    print(f"\n🔧 Updating Helpdesk role with {len(permission_ids)} permissions...")
    
    # The role ID we created earlier
    role_id = "b0303790-5a7f-42f1-ac13-cdd30146b816"
    
    update_data = {
        "global_permissions": permission_ids
    }
    
    response = authentik_request('PATCH', f'/api/v3/rbac/roles/{role_id}/', update_data)
    
    if response.status_code == 200:
        print(f"✅ Successfully updated Helpdesk role")
        print(f"   📋 Global permissions assigned: {len(permission_ids)}")
        return True
    else:
        print(f"❌ Failed to update role: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def main():
    print("🚀 Fixing Helpdesk Role Permissions")
    print("Purpose: Assign proper global permissions to the existing helpdesk role")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/?limit=1')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Get all permissions
        all_permissions = get_all_permissions()
        
        if len(all_permissions) < 100:
            print("❌ Expected ~585 permissions but got less than 100. Check API pagination.")
            return
        
        # Select appropriate permissions
        permission_ids, allowed_permissions = select_helpdesk_permissions(all_permissions)
        
        if not permission_ids:
            print("❌ No suitable permissions found")
            return
        
        # Update the role
        success = update_helpdesk_role(permission_ids)
        
        if success:
            print(f"\n🎉 SUCCESS!")
            print(f"   ✅ Helpdesk role permissions updated")
            print(f"   📋 Total global permissions: {len(permission_ids)}")
            print(f"\n📖 HELPDESK PERMISSIONS SUMMARY:")
            for perm in allowed_permissions[:15]:  # Show first 15
                print(f"   - {perm}")
            if len(allowed_permissions) > 15:
                print(f"   ... and {len(allowed_permissions) - 15} more permissions")
            
            print(f"\n📍 VERIFY AT:")
            print(f"   https://id.visiquate.com/if/admin/#/identity/roles")
            print(f"   Role ID: b0303790-5a7f-42f1-ac13-cdd30146b816")
            print(f"\n🔧 HELPDESK CAPABILITIES:")
            print(f"   ✅ User account management (view, edit, create, reset passwords)")
            print(f"   ✅ User impersonation for troubleshooting")
            print(f"   ✅ Group membership management") 
            print(f"   ✅ User session and application access viewing")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()