#!/usr/bin/env python3
"""
Create helpdesk role in Authentik using RBAC API
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
    
    return response

def get_available_permissions():
    """Get all available permissions via RBAC API"""
    print("🔍 Fetching permissions via RBAC API...")
    
    permissions = []
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
            
        permissions.extend(batch)
        
        if len(batch) < limit:
            break
            
        offset += limit
        iteration += 1
    
    print(f"✅ Found {len(permissions)} permissions")
    return permissions

def analyze_permissions_for_helpdesk(permissions):
    """Analyze permissions to identify what helpdesk should have"""
    print("\n📊 Analyzing permissions for helpdesk role...")
    
    helpdesk_permissions = []
    excluded_permissions = []
    
    # Define helpdesk needs for supporting users
    helpdesk_needs = {
        'user_support': ['view_user', 'change_user', 'add_user'],  # View, edit, create users
        'password_management': ['reset_user_password', 'change_password'],  # Password help
        'group_management': ['view_group', 'change_group'],  # See and modify group membership
        'account_management': ['activate_user', 'deactivate_user'],  # Account status
    }
    
    # Dangerous permissions to exclude
    forbidden = [
        'delete_user', 'delete_group', 'add_group',  # No deleting or creating groups
        'application', 'flow', 'source', 'provider', 'stage',  # No system admin
        'tenant', 'brand', 'certificate', 'token',  # No infrastructure
        'superuser', 'admin'  # No elevated privileges
    ]
    
    print("🎧 HELPDESK PERMISSIONS (what helpdesk staff should have):")
    for perm in permissions:
        codename = perm.get('codename', '').lower()
        name = perm.get('name', '')
        app_label = perm.get('app_label', '')
        model = perm.get('model', '')
        
        # Check if this permission is needed for helpdesk
        is_helpful = False
        for category, needs in helpdesk_needs.items():
            if any(need in codename for need in needs):
                is_helpful = True
                break
        
        # Check if it's related to user/group management
        if not is_helpful and (model in ['user', 'group'] or 'user' in codename or 'group' in codename):
            if not any(forbidden_word in codename for forbidden_word in forbidden):
                is_helpful = True
        
        # Check if it's explicitly forbidden
        is_forbidden = any(forbidden_word in codename for forbidden_word in forbidden)
        
        if is_helpful and not is_forbidden:
            helpdesk_permissions.append(perm['id'])
            print(f"   ✅ {app_label}.{codename}: {name}")
        elif is_forbidden or any(admin_word in codename for admin_word in ['application', 'flow', 'source', 'provider']):
            excluded_permissions.append(perm['id'])
    
    print(f"\n❌ EXCLUDED PERMISSIONS (too dangerous for helpdesk):")
    excluded_count = 0
    for perm in permissions:
        if perm['id'] in excluded_permissions:
            app_label = perm.get('app_label', '')
            codename = perm.get('codename', '').lower()
            name = perm.get('name', '')
            if excluded_count < 10:  # Show first 10
                print(f"   ❌ {app_label}.{codename}: {name}")
            excluded_count += 1
    
    if excluded_count > 10:
        print(f"   ... and {excluded_count - 10} more excluded permissions")
    
    print(f"\n📊 SUMMARY:")
    print(f"   ✅ Helpdesk permissions: {len(helpdesk_permissions)}")
    print(f"   ❌ Excluded permissions: {len(excluded_permissions)}")
    
    return helpdesk_permissions

def create_helpdesk_group(helpdesk_permissions):
    """Create the helpdesk group with appropriate permissions"""
    print("\n🏗️ Creating Helpdesk group...")
    
    # Check if helpdesk group already exists
    response = authentik_request('GET', '/api/v3/core/groups/?search=Helpdesk')
    if response.status_code == 200:
        existing_groups = response.json().get('results', [])
        for group in existing_groups:
            if group['name'].lower() == 'helpdesk':
                print(f"⚠️ Helpdesk group already exists (ID: {group['pk']})")
                return group['pk']
    
    # Create new helpdesk group
    group_data = {
        "name": "Helpdesk",
        "is_superuser": False,
        "attributes": {
            "description": "Semi-privileged role for helpdesk staff to support users with account problems",
            "created_by": "automation",
            "use_cases": [
                "Reset user passwords",
                "Reactivate deactivated accounts", 
                "Add/remove users from groups",
                "Create new user accounts",
                "View user details for troubleshooting"
            ]
        },
        "user_permissions": helpdesk_permissions
    }
    
    response = authentik_request('POST', '/api/v3/core/groups/', group_data)
    
    if response.status_code == 201:
        group = response.json()
        print(f"✅ Created Helpdesk group: ID {group['pk']}")
        print(f"   📋 Permissions assigned: {len(helpdesk_permissions)}")
        return group['pk']
    else:
        print(f"❌ Failed to create group: {response.status_code}")
        print(f"   Response: {response.text}")
        return None

def main():
    print("🚀 Creating Helpdesk Role in Authentik")
    print("Purpose: Enable helpdesk staff to support users without admin privileges")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/?limit=1')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Get all available permissions
        permissions = get_available_permissions()
        if not permissions:
            print("❌ No permissions found")
            return
        
        # Analyze and select helpdesk permissions
        helpdesk_perms = analyze_permissions_for_helpdesk(permissions)
        
        if not helpdesk_perms:
            print("❌ No suitable permissions found for helpdesk role")
            return
        
        # Create the helpdesk group
        group_id = create_helpdesk_group(helpdesk_perms)
        
        if group_id:
            print(f"\n🎉 SUCCESS!")
            print(f"   ✅ Helpdesk role created successfully")
            print(f"   🔗 Group ID: {group_id}")
            print(f"   📋 Total permissions: {len(helpdesk_perms)}")
            print(f"\n📖 USAGE:")
            print(f"   1. Add helpdesk staff users to the 'Helpdesk' group")
            print(f"   2. They will inherit all helpdesk permissions")
            print(f"   3. They can now support users without admin access")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()