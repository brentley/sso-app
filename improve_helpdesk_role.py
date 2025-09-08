#!/usr/bin/env python3
"""
Improve the existing Helpdesk role with comprehensive user management permissions
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
    """Get the specific permissions a helpdesk role should have"""
    print("🔍 Finding appropriate helpdesk permissions...")
    
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
        'unassign_user_permissions'
    ]
    
    permission_ids = []
    
    # Get core authentik permissions
    response = authentik_request('GET', '/api/v3/rbac/permissions/?search=authentik_core&limit=100')
    
    if response.status_code == 200:
        data = response.json()
        permissions = data.get('results', [])
        
        print("✅ HELPDESK PERMISSIONS (user support functions):")
        for perm in permissions:
            codename = perm.get('codename', '')
            name = perm.get('name', '')
            app_label = perm.get('app_label', '')
            perm_id = perm.get('id')
            
            # Include if it's in our helpdesk list and not forbidden
            if codename in helpdesk_permission_codenames and codename not in forbidden_codenames:
                permission_ids.append(perm_id)
                print(f"   ✅ {app_label}.{codename}: {name}")
        
        print(f"\n❌ FORBIDDEN PERMISSIONS (excluded from helpdesk):")
        for perm in permissions:
            codename = perm.get('codename', '')
            name = perm.get('name', '')
            app_label = perm.get('app_label', '')
            
            if codename in forbidden_codenames:
                print(f"   ❌ {app_label}.{codename}: {name}")
                
    else:
        print(f"❌ Failed to fetch permissions: {response.status_code}")
        return []
    
    print(f"\n📊 SUMMARY: {len(permission_ids)} permissions selected for helpdesk role")
    return permission_ids

def find_helpdesk_group():
    """Find the existing Helpdesk group"""
    response = authentik_request('GET', '/api/v3/core/groups/?search=Helpdesk')
    if response.status_code == 200:
        groups = response.json().get('results', [])
        for group in groups:
            if group['name'].lower() == 'helpdesk':
                return group
    return None

def update_helpdesk_group(group_id, new_permissions):
    """Update the helpdesk group with improved permissions"""
    print(f"\n🔧 Updating Helpdesk group permissions...")
    
    # Get current group data
    response = authentik_request('GET', f'/api/v3/core/groups/{group_id}/')
    if response.status_code != 200:
        print(f"❌ Failed to get current group data: {response.status_code}")
        return False
    
    current_group = response.json()
    
    # Update with new permissions
    update_data = {
        "name": current_group['name'],
        "is_superuser": False,
        "attributes": {
            "description": "Semi-privileged role for helpdesk staff to support users with account problems",
            "created_by": "automation",
            "updated_by": "automation_improvement", 
            "use_cases": [
                "Reset user passwords",
                "Reactivate deactivated accounts", 
                "Add/remove users from groups",
                "Create new user accounts",
                "View user details for troubleshooting",
                "Preview user data for debugging"
            ]
        },
        "user_permissions": new_permissions
    }
    
    response = authentik_request('PATCH', f'/api/v3/core/groups/{group_id}/', update_data)
    
    if response.status_code == 200:
        print(f"✅ Successfully updated Helpdesk group permissions")
        print(f"   📋 New permissions count: {len(new_permissions)}")
        return True
    else:
        print(f"❌ Failed to update group: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def main():
    print("🚀 Improving Helpdesk Role Permissions")
    print("Purpose: Add comprehensive user management permissions for helpdesk functions")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/?limit=1')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Find existing helpdesk group
        helpdesk_group = find_helpdesk_group()
        if not helpdesk_group:
            print("❌ Helpdesk group not found. Please run create_helpdesk_role.py first.")
            return
            
        print(f"✅ Found existing Helpdesk group: {helpdesk_group['name']} (ID: {helpdesk_group['pk']})")
        print(f"   Current permissions: {len(helpdesk_group.get('user_permissions', []))}")
        
        # Get improved permissions
        new_permissions = get_helpdesk_permissions()
        
        if not new_permissions:
            print("❌ No suitable permissions found")
            return
        
        # Update the group
        success = update_helpdesk_group(helpdesk_group['pk'], new_permissions)
        
        if success:
            print(f"\n🎉 SUCCESS!")
            print(f"   ✅ Helpdesk role permissions improved")
            print(f"   🔗 Group ID: {helpdesk_group['pk']}")
            print(f"   📋 Total permissions: {len(new_permissions)}")
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
            print(f"   - Access admin interface")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()