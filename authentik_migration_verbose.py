#!/usr/bin/env python3
"""
Authentik Group Migration - Verbose Version
Creates groups in Authentik with detailed progress output
"""

import json
import time
import requests
import os
import sys
from datetime import datetime

# Force immediate output flushing for all print statements
import builtins
original_print = builtins.print

def print_flush(*args, **kwargs):
    original_print(*args, **kwargs)
    sys.stdout.flush()

# Override print function
builtins.print = print_flush

# Authentik API credentials
AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def timestamp():
    """Get current timestamp for logging"""
    return datetime.now().strftime("%H:%M:%S")

def authentik_request(method, endpoint, data=None):
    """Make authenticated request to Authentik API with detailed logging"""
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{AUTHENTIK_BASE_URL}{endpoint}"
    
    print(f"[{timestamp()}] 🔄 API {method} {endpoint}")
    if data:
        print(f"[{timestamp()}] 📤 Request data: {json.dumps(data, indent=2)}")
    
    start_time = time.time()
    
    if method.upper() == 'GET':
        response = requests.get(url, headers=headers)
    elif method.upper() == 'POST':
        response = requests.post(url, headers=headers, json=data)
    elif method.upper() == 'PUT':
        response = requests.put(url, headers=headers, json=data)
    elif method.upper() == 'DELETE':
        response = requests.delete(url, headers=headers)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")
    
    duration = time.time() - start_time
    
    if response.status_code >= 200 and response.status_code < 300:
        print(f"[{timestamp()}] ✅ {response.status_code} ({duration:.2f}s)")
    else:
        print(f"[{timestamp()}] ❌ {response.status_code} ({duration:.2f}s) - {response.text}")
    
    return response

def get_authentik_users():
    """Get all users from Authentik using SEARCH API (works better than bulk fetch)"""
    print(f"\n[{timestamp()}] 🔍 Fetching Authentik users using search API...")
    users = []
    offset = 0
    limit = 100
    fetched_pages = 0
    max_pages = 50  # Safety limit to prevent infinite loops
    
    # Use search API with empty search parameter to get ALL users
    # This works better than bulk fetch which excludes some users
    while fetched_pages < max_pages:
        print(f"[{timestamp()}] 🔄 Fetching page {fetched_pages + 1} (offset {offset})...")
        # CRITICAL FIX: Use search API instead of bulk fetch
        response = authentik_request('GET', f'/api/v3/core/users/?search=&limit={limit}&offset={offset}')
        
        if response.status_code != 200:
            print(f"[{timestamp()}] ❌ Failed to fetch users at offset {offset}: {response.status_code}")
            break
        
        data = response.json()
        batch = data.get('results', [])
        pagination = data.get('pagination', {})
        total_count = pagination.get('count', 0)
        
        print(f"[{timestamp()}] 📊 Search API returned {len(batch)} users (pagination says total: {total_count})")
        
        # If no results in this batch, we're done
        if not batch:
            print(f"[{timestamp()}] ✅ No more results - stopping")
            break
            
        users.extend(batch)
        fetched_pages += 1
        
        print(f"[{timestamp()}] 📈 Total collected so far: {len(users)} users")
        
        # If we got fewer results than requested, we've reached the end
        if len(batch) < limit:
            print(f"[{timestamp()}] ✅ Got {len(batch)} results (less than limit {limit}) - reached end")
            break
            
        # If we have a reliable total count and reached it, stop
        if total_count > 0 and len(users) >= total_count:
            print(f"[{timestamp()}] ✅ Reached expected total count {total_count} - stopping")
            break
            
        offset += limit
        
        # Small delay to be nice to the API
        time.sleep(0.2)
    
    if fetched_pages >= max_pages:
        print(f"[{timestamp()}] ⚠️ Hit safety limit of {max_pages} pages - stopping")
    
    print(f"[{timestamp()}] ✅ Total users found: {len(users)} (fetched {fetched_pages} pages)")
    print(f"[{timestamp()}] 🎯 Using search API instead of bulk fetch to find ALL users")
    return users

def get_authentik_groups():
    """Get all groups from Authentik with progress"""
    print(f"\n[{timestamp()}] 🔍 Fetching Authentik groups...")
    groups = []
    offset = 0
    limit = 100
    
    while True:
        response = authentik_request('GET', f'/api/v3/core/groups/?limit={limit}&offset={offset}')
        if response.status_code != 200:
            print(f"[{timestamp()}] ❌ Failed to fetch groups at offset {offset}")
            break
        
        data = response.json()
        batch = data.get('results', [])
        if not batch:
            break
            
        groups.extend(batch)
        print(f"[{timestamp()}] 📊 Fetched {len(batch)} groups (total: {len(groups)})")
        offset += limit
        
        if len(batch) < limit:
            break
            
        # Small delay to be nice to the API
        time.sleep(0.1)
    
    print(f"[{timestamp()}] ✅ Total groups found: {len(groups)}")
    return groups

def create_authentik_group(group_name):
    """Create a group in Authentik with detailed logging"""
    print(f"\n[{timestamp()}] 🏗️  Creating group: '{group_name}'")
    
    group_data = {
        "name": group_name,
        "is_superuser": False,
        "attributes": {
            "migrated_from": "duo",
            "migration_timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        }
    }
    
    response = authentik_request('POST', '/api/v3/core/groups/', group_data)
    
    if response.status_code == 201:
        group = response.json()
        print(f"[{timestamp()}] ✅ Created group '{group_name}' with ID: {group['pk']}")
        return group
    elif response.status_code == 400 and 'unique' in response.text.lower():
        print(f"[{timestamp()}] ⚠️  Group '{group_name}' already exists, looking it up...")
        return None  # Will be handled by caller
    else:
        print(f"[{timestamp()}] ❌ Failed to create group '{group_name}': {response.status_code}")
        return None

def find_user_by_email(email):
    """Find a user by email using individual search (works better than bulk fetch)"""
    if not email:
        return None
        
    response = authentik_request('GET', f'/api/v3/core/users/?search={email}')
    
    if response.status_code == 200:
        data = response.json()
        results = data.get('results', [])
        
        # Look for exact email match
        for user in results:
            if user.get('email', '').lower() == email.lower():
                return user
    
    return None

def sync_group_membership(group_name, group_pk, expected_members, authentik_user_lookup):
    """Sync group membership using individual user searches (FIXED APPROACH)"""
    print(f"[{timestamp()}] 🔄 Syncing membership for group '{group_name}' with individual user lookup")
    
    # Get current group members
    response = authentik_request('GET', f'/api/v3/core/groups/{group_pk}/')
    if response.status_code != 200:
        print(f"[{timestamp()}] ❌ Failed to get group data for {group_name}")
        return {'added': 0, 'removed': 0, 'errors': 0, 'already_synced': 0}
    
    group_data = response.json()
    current_member_pks = set(str(pk) for pk in group_data.get('users', []))
    
    # Build expected members set using INDIVIDUAL SEARCHES (bypasses bulk API filtering)
    expected_member_pks = set()
    found_users = []
    missing_users = []
    
    print(f"[{timestamp()}] 🔍 Looking up {len(expected_members)} expected members individually...")
    
    for i, member in enumerate(expected_members, 1):
        email = member.get('email', '').strip()
        if not email:
            continue
            
        if i <= 3 or i % 10 == 0 or i == len(expected_members):  # Log progress for larger groups
            print(f"[{timestamp()}] 📍 Checking user {i}/{len(expected_members)}: {email}")
        
        # Try individual search first (this finds ALL users including recently created ones)
        user = find_user_by_email(email)
        if user:
            expected_member_pks.add(str(user['pk']))
            found_users.append({'email': email, 'pk': user['pk']})
        else:
            # Fallback to bulk lookup cache (for users found by bulk operations)
            if email in authentik_user_lookup:
                user_pk = str(authentik_user_lookup[email]['pk'])
                expected_member_pks.add(user_pk)
                found_users.append({'email': email, 'pk': user_pk})
            else:
                missing_users.append(email)
    
    print(f"[{timestamp()}] 📊 Current members: {len(current_member_pks)}")
    print(f"[{timestamp()}] 📊 Expected members: {len(expected_member_pks)} found, {len(missing_users)} missing (from {len(expected_members)} total)")
    
    if missing_users and len(missing_users) <= 10:  # Log specific missing users for small numbers
        print(f"[{timestamp()}] ⚠️  Missing users: {', '.join(missing_users)}")
    elif missing_users:
        print(f"[{timestamp()}] ⚠️  Missing users: {missing_users[0]}, {missing_users[1]}, ... and {len(missing_users)-2} others")
    
    # Find users to add and remove
    to_add = expected_member_pks - current_member_pks
    to_remove = current_member_pks - expected_member_pks
    already_synced = current_member_pks & expected_member_pks
    
    results = {'added': 0, 'removed': 0, 'errors': 0, 'already_synced': len(already_synced)}
    
    if not to_add and not to_remove:
        print(f"[{timestamp()}] ✅ Group '{group_name}' already in sync!")
        return results
    
    print(f"[{timestamp()}] 📝 Changes needed: +{len(to_add)} users, -{len(to_remove)} users")
    
    # Update group with the correct member list
    new_member_list = list(expected_member_pks)
    
    update_data = {
        "name": group_name,
        "users": new_member_list
    }
    
    response = authentik_request('PUT', f'/api/v3/core/groups/{group_pk}/', update_data)
    
    if response.status_code in [200, 201, 204]:
        print(f"[{timestamp()}] ✅ Updated group '{group_name}' membership")
        results['added'] = len(to_add)
        results['removed'] = len(to_remove)
        
        # Log specific changes for transparency
        if to_add:
            added_emails = [user['email'] for user in found_users if str(user['pk']) in to_add]
            print(f"[{timestamp()}] ➕ Added: {', '.join(added_emails[:5])}{'...' if len(added_emails) > 5 else ''}")
        
        if to_remove:
            print(f"[{timestamp()}] ➖ Removed {len(to_remove)} existing members")
    else:
        print(f"[{timestamp()}] ❌ Failed to update group '{group_name}' membership: {response.status_code}")
        print(f"[{timestamp()}] 📝 Response: {response.text[:200]}")
        results['errors'] = len(to_add) + len(to_remove)
    
    return results

def main():
    start_time = time.time()
    print(f"[{timestamp()}] 🚀 Starting Authentik group migration with verbose output")
    print(f"[{timestamp()}] 🔑 Using token: {AUTHENTIK_TOKEN[:20]}...")
    
    try:
        # Test API connection
        print(f"\n[{timestamp()}] 🧪 Testing Authentik API connection...")
        response = authentik_request('GET', '/api/v3/core/users/?limit=1')
        if response.status_code != 200:
            print(f"[{timestamp()}] ❌ API test failed, exiting")
            return
        print(f"[{timestamp()}] ✅ API connection confirmed")
        
        # Get existing Authentik users and groups
        authentik_users = get_authentik_users()
        authentik_groups = get_authentik_groups()
        
        # Create lookup maps
        print(f"\n[{timestamp()}] 🗂️  Building lookup maps...")
        print(f"[{timestamp()}] 📊 Processing {len(authentik_users)} users from API...")
        
        authentik_user_lookup = {}
        users_with_email = 0
        users_without_email = 0
        
        for user in authentik_users:
            email = user.get('email')
            if email:
                authentik_user_lookup[email] = user
                users_with_email += 1
            else:
                users_without_email += 1
        
        authentik_group_lookup = {group['name']: group for group in authentik_groups}
        
        print(f"[{timestamp()}] ✅ User lookup: {len(authentik_user_lookup)} entries (from {users_with_email} users with email, {users_without_email} without)")
        print(f"[{timestamp()}] ✅ Group lookup: {len(authentik_group_lookup)} entries")
        
        # Debug: Check if our known n8n users are in the lookup
        n8n_test_emails = ["brent.langston@visiquate.com", "megan.langston@visiquate.com", "vitaliy.gavrylenko@visiquate.com"]
        print(f"[{timestamp()}] 🔍 Debug: Checking if n8n test users are in lookup...")
        for email in n8n_test_emails:
            if email in authentik_user_lookup:
                user = authentik_user_lookup[email]
                print(f"[{timestamp()}] ✅ Found {email} -> ID {user['pk']}")
            else:
                print(f"[{timestamp()}] ❌ Missing {email} from lookup")
        
        # Find all group files
        group_files = [f for f in os.listdir('group_migration') if f.startswith('group_') and f.endswith('.json')]
        group_files.sort()  # Process in consistent order
        
        print(f"\n[{timestamp()}] 📁 Found {len(group_files)} group files to process")
        
        # Track migration results
        migration_results = {
            'groups_created': 0,
            'groups_already_existed': 0,
            'groups_updated': 0,
            'groups_unchanged': 0,
            'users_added_to_groups': 0,
            'users_removed_from_groups': 0,
            'users_already_synced': 0,
            'users_not_found': 0,
            'membership_failures': 0,
            'errors': []
        }
        
        created_groups = {}
        
        # Process each group file
        for i, group_file in enumerate(group_files, 1):
            print(f"\n[{timestamp()}] 📋 Processing group {i}/{len(group_files)}: {group_file}")
            
            group_path = f"group_migration/{group_file}"
            
            with open(group_path, 'r') as f:
                group_data = json.load(f)
            
            group_name = group_data['clean_name']
            original_name = group_data['original_name']
            members = group_data['members']
            
            print(f"[{timestamp()}] 🏷️  Group: '{group_name}'")
            print(f"[{timestamp()}] 📝 Original: '{original_name}'")
            print(f"[{timestamp()}] 👥 Members: {len(members)}")
            
            # Check if group already exists
            authentik_group = authentik_group_lookup.get(group_name)
            
            if not authentik_group:
                # Create group
                authentik_group = create_authentik_group(group_name)
                if authentik_group:
                    authentik_group_lookup[group_name] = authentik_group
                    migration_results['groups_created'] += 1
                    created_groups[group_name] = authentik_group['pk']
                else:
                    print(f"[{timestamp()}] ❌ Skipping group {group_name} - creation failed")
                    migration_results['errors'].append(f"Failed to create group: {group_name}")
                    continue
            else:
                print(f"[{timestamp()}] ⚠️  Group '{group_name}' already exists (ID: {authentik_group['pk']})")
                migration_results['groups_already_existed'] += 1
                created_groups[group_name] = authentik_group['pk']
            
            # Sync group membership to match Duo data exactly
            sync_results = sync_group_membership(group_name, authentik_group['pk'], members, authentik_user_lookup)
            
            # Update migration statistics
            migration_results['users_added_to_groups'] += sync_results['added']
            migration_results['users_removed_from_groups'] += sync_results['removed']
            migration_results['users_already_synced'] += sync_results['already_synced']
            migration_results['membership_failures'] += sync_results['errors']
            
            # Count users not found in Authentik
            users_not_found = 0
            for member in members:
                email = member.get('email', '').strip()
                if email and email not in authentik_user_lookup:
                    users_not_found += 1
            migration_results['users_not_found'] += users_not_found
            
            if users_not_found > 0:
                print(f"[{timestamp()}] ⚠️  {users_not_found} users from Duo not found in Authentik")
            
            # Track if group was updated or unchanged
            if sync_results['added'] > 0 or sync_results['removed'] > 0:
                migration_results['groups_updated'] += 1
            else:
                migration_results['groups_unchanged'] += 1
            
            print(f"[{timestamp()}] ✅ Completed group '{group_name}'")
            
            # Delay between groups to be nice to the API
            if i < len(group_files):
                print(f"[{timestamp()}] ⏸️  Pausing before next group...")
                time.sleep(0.2)
        
        # Save final results
        total_time = time.time() - start_time
        
        final_summary = {
            'authentik_migration_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'migration_duration_seconds': round(total_time, 2),
            'authentik_stats': {
                'total_users_found': len(authentik_users),
                'total_groups_found': len(authentik_groups)
            },
            'migration_results': migration_results,
            'created_groups': created_groups,
            'total_groups_processed': len(group_files)
        }
        
        with open('group_migration/authentik_migration_summary.json', 'w') as f:
            json.dump(final_summary, f, indent=2)
        
        print(f"\n[{timestamp()}] 🎉 Authentik migration completed!")
        print(f"[{timestamp()}] ⏱️  Total time: {total_time:.1f} seconds")
        print(f"[{timestamp()}] 🏗️  Groups created: {migration_results['groups_created']}")
        print(f"[{timestamp()}] ♻️  Groups already existed: {migration_results['groups_already_existed']}")
        print(f"[{timestamp()}] 🔄 Groups updated: {migration_results['groups_updated']}")
        print(f"[{timestamp()}] ✅ Groups unchanged: {migration_results['groups_unchanged']}")
        print(f"[{timestamp()}] ➕ Users added to groups: {migration_results['users_added_to_groups']}")
        print(f"[{timestamp()}] ➖ Users removed from groups: {migration_results['users_removed_from_groups']}")
        print(f"[{timestamp()}] 👥 Users already in sync: {migration_results['users_already_synced']}")
        print(f"[{timestamp()}] ⚠️  Users not found in Authentik: {migration_results['users_not_found']}")
        print(f"[{timestamp()}] ❌ Membership failures: {migration_results['membership_failures']}")
        print(f"[{timestamp()}] 📁 Summary saved to authentik_migration_summary.json")
        print(f"[{timestamp()}] 🔁 This script can be run repeatedly to sync changes from Duo")
        
        if migration_results['errors']:
            print(f"[{timestamp()}] ⚠️  {len(migration_results['errors'])} errors occurred (see summary file)")
        
    except Exception as e:
        print(f"[{timestamp()}] ❌ Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()