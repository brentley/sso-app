#!/usr/bin/env python3
"""
Investigate Authentik's role and permission system to create semi-privileged user management role
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
    
    return response

def investigate_permissions():
    """Investigate available permissions in Authentik"""
    print("🔍 Investigating Authentik permissions system...")
    
    # Initialize return values
    user_permissions = []
    group_permissions = []
    admin_permissions = []
    
    # Check what permissions are available
    print("\n1. Available Permissions:")
    response = authentik_request('GET', '/api/v3/core/permissions/')
    if response.status_code == 200:
        permissions = response.json().get('results', [])
        print(f"   Found {len(permissions)} permissions")
        
        # Look for user and group related permissions
        for perm in permissions:
            codename = perm.get('codename', '')
            name = perm.get('name', '')
            content_type = perm.get('content_type', {})
            app_label = content_type.get('app_label', '') if content_type else ''
            model = content_type.get('model', '') if content_type else ''
            
            full_name = f"{app_label}.{codename}" if app_label else codename
            
            if 'user' in codename.lower() or model == 'user':
                user_permissions.append({
                    'codename': codename,
                    'name': name,
                    'full': full_name,
                    'app': app_label,
                    'model': model
                })
            elif 'group' in codename.lower() or model == 'group':
                group_permissions.append({
                    'codename': codename,
                    'name': name,
                    'full': full_name,
                    'app': app_label,
                    'model': model
                })
            elif any(word in codename.lower() for word in ['application', 'flow', 'source', 'provider', 'stage']):
                admin_permissions.append({
                    'codename': codename,
                    'name': name,
                    'full': full_name,
                    'app': app_label,
                    'model': model
                })
        
        print(f"\n📋 USER-related permissions ({len(user_permissions)}):")
        for perm in user_permissions[:10]:  # Show first 10
            print(f"   ✅ {perm['full']}: {perm['name']}")
        if len(user_permissions) > 10:
            print(f"   ... and {len(user_permissions) - 10} more")
            
        print(f"\n👥 GROUP-related permissions ({len(group_permissions)}):")
        for perm in group_permissions:
            print(f"   ✅ {perm['full']}: {perm['name']}")
            
        print(f"\n⚙️  ADMIN-related permissions ({len(admin_permissions)}):")
        for perm in admin_permissions[:5]:  # Show first 5
            print(f"   ❌ {perm['full']}: {perm['name']}")
        if len(admin_permissions) > 5:
            print(f"   ... and {len(admin_permissions) - 5} more (should be EXCLUDED)")
    
    else:
        print(f"   ❌ Failed to fetch permissions: {response.status_code}")
        print(f"   Response: {response.text[:200]}")
    
    return user_permissions, group_permissions, admin_permissions

def investigate_roles():
    """Investigate existing roles in Authentik"""
    print("\n2. Existing Roles:")
    response = authentik_request('GET', '/api/v3/core/groups/')
    if response.status_code == 200:
        groups = response.json().get('results', [])
        
        # Look for groups that act as roles (have permissions)
        role_groups = []
        for group in groups:
            if group.get('is_superuser') or len(group.get('user_permissions', [])) > 0:
                role_groups.append({
                    'name': group['name'],
                    'is_superuser': group.get('is_superuser', False),
                    'permissions': group.get('user_permissions', []),
                    'pk': group['pk']
                })
        
        print(f"   Found {len(role_groups)} groups with permissions:")
        for role in role_groups:
            print(f"   🔑 '{role['name']}' (ID: {role['pk']})")
            print(f"      - Superuser: {role['is_superuser']}")
            print(f"      - Permissions: {len(role['permissions'])}")

def check_rbac_api():
    """Check if Authentik has dedicated RBAC API endpoints"""
    print("\n3. RBAC API Endpoints:")
    
    rbac_endpoints = [
        '/api/v3/rbac/roles/',
        '/api/v3/rbac/permissions/', 
        '/api/v3/core/groups/',  # Groups can act as roles
        '/api/v3/core/users/',   # Users for role assignment
    ]
    
    for endpoint in rbac_endpoints:
        response = authentik_request('GET', endpoint)
        print(f"   {endpoint}: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            count = len(data.get('results', [])) if 'results' in data else 'N/A'
            print(f"      ✅ Available - {count} items")
        elif response.status_code == 404:
            print(f"      ❌ Not available")
        else:
            print(f"      ⚠️ Error: {response.status_code}")

def design_helpdesk_role(user_perms, group_perms, admin_perms):
    """Design the helpdesk role based on discovered permissions - focused on user support"""
    print("\n4. Designing Helpdesk Role (for user support):")
    
    # Define what helpdesk should be able to do to support users with problems
    helpdesk_capabilities = {
        'user_support': [
            'view_user',         # View user details to diagnose problems
            'change_user',       # Update user info (email, name) when needed  
            'reset_password',    # Help users who forgot passwords
            'activate_user',     # Reactivate deactivated accounts
            'deactivate_user'    # Temporarily disable problematic accounts
        ],
        'group_support': [
            'view_group',        # See what groups exist and who's in them
            'change_group'       # Add/remove users from groups for access issues
        ],
        'account_creation': [
            'add_user',          # Create new user accounts when needed
            'send_invitation',   # Send activation/invitation links
            'generate_link'      # Generate password reset links
        ],
        'forbidden_admin': [
            'application', 'flow', 'source', 'provider', 'stage', 
            'tenant', 'brand', 'certificate', 'token', 'delete_user',
            'delete_group', 'add_group'  # Don't let helpdesk create/delete groups
        ]
    }
    
    # Find matching permissions
    role_permissions = []
    
    print("   🎧 HELPDESK USER SUPPORT permissions:")
    for perm in user_perms:
        if any(cap in perm['codename'].lower() for cap in helpdesk_capabilities['user_support'] + helpdesk_capabilities['account_creation']):
            role_permissions.append(perm['full'])
            print(f"      ✅ {perm['full']}: {perm['name']}")
    
    print("   👥 HELPDESK GROUP SUPPORT permissions:")
    for perm in group_perms:
        codename_lower = perm['codename'].lower()
        # Include view and change, but exclude add/delete group
        if any(cap in codename_lower for cap in helpdesk_capabilities['group_support']):
            if not any(forbidden in codename_lower for forbidden in ['delete_group', 'add_group']):
                role_permissions.append(perm['full'])
                print(f"      ✅ {perm['full']}: {perm['name']}")
    
    print("   ❌ FORBIDDEN admin permissions (helpdesk should NOT have):")
    excluded_count = 0
    for perm in admin_perms[:10]:  # Show some examples
        print(f"      ❌ {perm['full']}: {perm['name']}")
        excluded_count += 1
    if len(admin_perms) > excluded_count:
        print(f"      ... and {len(admin_perms) - excluded_count} more FORBIDDEN permissions")
    
    # Also show forbidden user permissions
    print("   ❌ FORBIDDEN user permissions (too dangerous for helpdesk):")
    for perm in user_perms:
        if 'delete' in perm['codename'].lower():
            print(f"      ❌ {perm['full']}: {perm['name']} (too dangerous)")
    
    return role_permissions

def main():
    print("🚀 Investigating Authentik Role and Permission System")
    print("Goal: Create semi-privileged user management role")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/?limit=1')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Investigate permissions
        user_perms, group_perms, admin_perms = investigate_permissions()
        
        # Investigate existing roles
        investigate_roles()
        
        # Check RBAC endpoints
        check_rbac_api()
        
        # Design the role
        role_permissions = design_helpdesk_role(user_perms, group_perms, admin_perms)
        
        print(f"\n💡 RECOMMENDED HELPDESK ROLE DESIGN:")
        print(f"   Name: 'Helpdesk'")
        print(f"   Description: 'Role for helpdesk staff to support users with account problems'")
        print(f"   Total permissions: {len(role_permissions)}")
        print(f"   Implementation: Create as Authentik group with specific permissions")
        print(f"   Use cases: Password resets, account reactivation, group membership fixes")
        
        # Save detailed analysis
        analysis = {
            'user_permissions': user_perms,
            'group_permissions': group_perms, 
            'admin_permissions': admin_perms,
            'recommended_role_permissions': role_permissions
        }
        
        with open('authentik_role_analysis.json', 'w') as f:
            json.dump(analysis, f, indent=2)
        print(f"   📁 Detailed analysis saved to authentik_role_analysis.json")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()