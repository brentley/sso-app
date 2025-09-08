#!/usr/bin/env python3
"""
Debug script to examine available permissions and find the exact ones we need
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
    
    return response

def search_for_user_permissions():
    """Find all user-related permissions"""
    print("🔍 Searching for user-related permissions...")
    
    # Search for permissions containing 'user' in codename or name
    response = authentik_request('GET', '/api/v3/rbac/permissions/?search=user&limit=50')
    
    if response.status_code == 200:
        permissions = response.json().get('results', [])
        print(f"✅ Found {len(permissions)} user-related permissions")
        
        target_codenames = [
            'view_user', 'change_user', 'add_user', 'reset_user_password', 'can_impersonate'
        ]
        
        found_permissions = {}
        
        print(f"\n📋 User-related permissions:")
        for perm in permissions:
            codename = perm.get('codename', '')
            name = perm.get('name', '')
            app_label = perm.get('app_label', '')
            perm_id = perm.get('id')
            
            print(f"   {perm_id:4d}: {app_label}.{codename} - {name}")
            
            # Check if this is one we want
            if codename in target_codenames:
                found_permissions[codename] = {
                    'id': perm_id,
                    'full_name': f"{app_label}.{codename}",
                    'name': name
                }
        
        print(f"\n🎯 Target permissions found:")
        for codename in target_codenames:
            if codename in found_permissions:
                perm = found_permissions[codename]
                print(f"   ✅ {perm['full_name']} (ID: {perm['id']})")
            else:
                print(f"   ❌ {codename} - NOT FOUND")
                
        return found_permissions
    else:
        print(f"❌ Failed to search permissions: {response.status_code}")
        return {}

def search_for_group_permissions():
    """Find group-related permissions"""
    print(f"\n🔍 Searching for group-related permissions...")
    
    response = authentik_request('GET', '/api/v3/rbac/permissions/?search=group&limit=50')
    
    if response.status_code == 200:
        permissions = response.json().get('results', [])
        print(f"✅ Found {len(permissions)} group-related permissions")
        
        target_codenames = [
            'view_group', 'change_group', 'add_user_to_group', 'remove_user_from_group'
        ]
        
        found_permissions = {}
        
        print(f"\n📋 Group-related permissions:")
        for perm in permissions:
            codename = perm.get('codename', '')
            name = perm.get('name', '')
            app_label = perm.get('app_label', '')
            perm_id = perm.get('id')
            
            if any(target in codename for target in ['group', 'user_to_group']):
                print(f"   {perm_id:4d}: {app_label}.{codename} - {name}")
                
                if codename in target_codenames:
                    found_permissions[codename] = {
                        'id': perm_id,
                        'full_name': f"{app_label}.{codename}",
                        'name': name
                    }
        
        print(f"\n🎯 Target group permissions found:")
        for codename in target_codenames:
            if codename in found_permissions:
                perm = found_permissions[codename]
                print(f"   ✅ {perm['full_name']} (ID: {perm['id']})")
            else:
                print(f"   ❌ {codename} - NOT FOUND")
                
        return found_permissions
    else:
        print(f"❌ Failed to search group permissions: {response.status_code}")
        return {}

def main():
    print("🚀 Debug: Finding Helpdesk Permissions")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Search for relevant permissions
        user_permissions = search_for_user_permissions()
        group_permissions = search_for_group_permissions()
        
        all_found = {**user_permissions, **group_permissions}
        
        if all_found:
            print(f"\n📊 SUMMARY: Found {len(all_found)} target permissions")
            permission_ids = [perm['id'] for perm in all_found.values()]
            print(f"   Permission IDs to assign: {permission_ids}")
        else:
            print(f"\n❌ No target permissions found")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()