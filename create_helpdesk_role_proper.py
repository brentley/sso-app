#!/usr/bin/env python3
"""
Create a proper Helpdesk Role (not Group) with global permissions in Authentik
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
    elif method.upper() == 'POST':
        response = requests.post(url, headers=headers, json=data, timeout=15)
    elif method.upper() == 'PUT':
        response = requests.put(url, headers=headers, json=data, timeout=15)
    elif method.upper() == 'PATCH':
        response = requests.patch(url, headers=headers, json=data, timeout=15)
    
    return response

def get_helpdesk_permissions():
    """Get the specific global permissions a helpdesk role should have"""
    print("🔍 Finding appropriate helpdesk global permissions...")
    
    # Get all global permissions
    response = authentik_request('GET', '/api/v3/rbac/permissions/?limit=1000')
    
    if response.status_code != 200:
        print(f"❌ Failed to fetch permissions: {response.status_code}")
        return []
    
    all_permissions = response.json().get('results', [])
    print(f"✅ Found {len(all_permissions)} total global permissions")
    
    # Define exactly what helpdesk should be able to do
    helpdesk_permission_codenames = [
        # Core user management
        'view_user',
        'change_user', 
        'add_user',
        'reset_user_password',
        
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
        'view_user_applications'
    ]
    
    # Permissions to absolutely exclude (dangerous for helpdesk)
    forbidden_codenames = [
        'delete_user',
        'delete_group', 
        'add_group',
        'enable_group_superuser',
        'disable_group_superuser',
        'assign_user_permissions',
        'unassign_user_permissions',
        'add_application',
        'change_application',
        'delete_application',
        'add_flow',
        'change_flow',
        'delete_flow'
    ]
    
    permission_ids = []
    
    print("✅ HELPDESK PERMISSIONS (user support functions):")
    for perm in all_permissions:
        codename = perm.get('codename', '')
        name = perm.get('name', '')
        app_label = perm.get('app_label', '')
        perm_id = perm.get('id')
        
        # Include if it's in our helpdesk list and not forbidden
        if codename in helpdesk_permission_codenames and codename not in forbidden_codenames:
            permission_ids.append(perm_id)
            print(f"   ✅ {app_label}.{codename}: {name}")
    
    print(f"\n❌ FORBIDDEN PERMISSIONS (excluded from helpdesk):")
    excluded_count = 0
    for perm in all_permissions:
        codename = perm.get('codename', '')
        name = perm.get('name', '')
        app_label = perm.get('app_label', '')
        
        if codename in forbidden_codenames:
            if excluded_count < 10:  # Show first 10
                print(f"   ❌ {app_label}.{codename}: {name}")
            excluded_count += 1
    
    if excluded_count > 10:
        print(f"   ... and {excluded_count - 10} more forbidden permissions")
                
    print(f"\n📊 SUMMARY: {len(permission_ids)} permissions selected for helpdesk role")
    return permission_ids

def create_helpdesk_role(permission_ids):
    """Create the helpdesk role with appropriate global permissions"""
    print("\n🏗️ Creating Helpdesk role...")
    
    # Check if helpdesk role already exists
    response = authentik_request('GET', '/api/v3/rbac/roles/?search=Helpdesk')
    if response.status_code == 200:
        existing_roles = response.json().get('results', [])
        for role in existing_roles:
            if role['name'].lower() == 'helpdesk':
                print(f"⚠️ Helpdesk role already exists (ID: {role['pk']})")
                return update_helpdesk_role(role['pk'], permission_ids)
    
    # Create new helpdesk role
    role_data = {
        "name": "Helpdesk",
        "global_permissions": permission_ids
    }
    
    response = authentik_request('POST', '/api/v3/rbac/roles/', role_data)
    
    if response.status_code == 201:
        role = response.json()
        print(f"✅ Created Helpdesk role: ID {role['pk']}")
        print(f"   📋 Global permissions assigned: {len(permission_ids)}")
        return role['pk']
    else:
        print(f"❌ Failed to create role: {response.status_code}")
        print(f"   Response: {response.text}")
        return None

def update_helpdesk_role(role_id, permission_ids):
    """Update existing helpdesk role with improved permissions"""
    print(f"\n🔧 Updating existing Helpdesk role...")
    
    update_data = {
        "global_permissions": permission_ids
    }
    
    response = authentik_request('PATCH', f'/api/v3/rbac/roles/{role_id}/', update_data)
    
    if response.status_code == 200:
        print(f"✅ Successfully updated Helpdesk role permissions")
        print(f"   📋 New global permissions count: {len(permission_ids)}")
        return role_id
    else:
        print(f"❌ Failed to update role: {response.status_code}")
        print(f"   Response: {response.text}")
        return None

def main():
    print("🚀 Creating Proper Helpdesk Role in Authentik")
    print("Purpose: Create Role (not Group) with global permissions for helpdesk functions")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/?limit=1')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Get improved permissions
        permission_ids = get_helpdesk_permissions()
        
        if not permission_ids:
            print("❌ No suitable permissions found")
            return
        
        # Create the role
        role_id = create_helpdesk_role(permission_ids)
        
        if role_id:
            print(f"\n🎉 SUCCESS!")
            print(f"   ✅ Helpdesk role created successfully")
            print(f"   🔗 Role ID: {role_id}")
            print(f"   📋 Total global permissions: {len(permission_ids)}")
            print(f"\n📖 HELPDESK STAFF CAN NOW:")
            print(f"   - View and edit user accounts")  
            print(f"   - Reset passwords")
            print(f"   - Create new users")
            print(f"   - Add/remove users from groups")
            print(f"   - View user application access")
            print(f"   - Preview user data for troubleshooting")
            print(f"\n⚠️  HELPDESK STAFF CANNOT:")
            print(f"   - Delete users or groups") 
            print(f"   - Create/delete groups")
            print(f"   - Assign permissions directly")
            print(f"   - Modify applications, flows, or providers")
            print(f"\n📍 VISIBLE AT:")
            print(f"   https://id.visiquate.com/if/admin/#/identity/roles")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()