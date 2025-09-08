#!/usr/bin/env python3
"""
Check which n8n group members exist in Authentik
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
        response = requests.get(url, headers=headers)
    elif method.upper() == 'POST':
        response = requests.post(url, headers=headers, json=data)
    
    return response

def get_authentik_users():
    """Get all users from Authentik - with FIXED pagination"""
    print("🔍 Fetching Authentik users...")
    users = []
    offset = 0
    limit = 100
    
    while True:
        response = authentik_request('GET', f'/api/v3/core/users/?limit={limit}&offset={offset}')
        if response.status_code != 200:
            print(f"❌ Failed to fetch users at offset {offset}")
            break
        
        data = response.json()
        batch = data.get('results', [])
        pagination = data.get('pagination', {})
        total_count = pagination.get('count', 0)
        
        print(f"📊 Fetched {len(batch)} users (total so far: {len(users)}, expected: {total_count})")
        
        # If no results, we're done
        if not batch:
            print("✅ No more results - stopping")
            break
            
        users.extend(batch)
        
        # If we got fewer results than the limit, we've reached the end
        if len(batch) < limit:
            print(f"✅ Got {len(batch)} results (less than limit {limit}) - stopping")
            break
            
        # If we've reached the expected total count, we're done
        if total_count > 0 and len(users) >= total_count:
            print(f"✅ Reached expected total count {total_count} - stopping")
            break
            
        offset += limit
    
    print(f"✅ Total users found: {len(users)}")
    return users

def main():
    # n8n group members from Duo
    n8n_members = [
        "megan.langston@visiquate.com",
        "vitaliy.gavrylenko@visiquate.com", 
        "natalya.goryayinova@visiquate.com",
        "denys.malyshev@visiquate.com",
        "oleg.avdyeyev@visiquate.com",
        "serhii.tkachuk@visiquate.com",
        "oleksii.voitenko@visiquate.com",
        "brent.langston@visiquate.com",
        "ben.adeemi@visiquate.com",
        "yuliia.lutai@visiquate.com",
        "sergiy.vats@visiquate.com",
        "maksym.dilanian@visiquate.com",
        "serhii.chaika@visiquate.com"
    ]
    
    print(f"🔍 Checking {len(n8n_members)} n8n group members in Authentik...")
    
    # Get all Authentik users
    authentik_users = get_authentik_users()
    authentik_emails = {user['email'].lower() for user in authentik_users if user.get('email')}
    
    print(f"\n📊 Found {len(authentik_emails)} users with email addresses in Authentik")
    
    # Check each n8n member
    found = []
    missing = []
    
    for email in n8n_members:
        if email.lower() in authentik_emails:
            found.append(email)
            print(f"✅ FOUND: {email}")
        else:
            missing.append(email)
            print(f"❌ MISSING: {email}")
    
    print(f"\n📈 SUMMARY:")
    print(f"✅ Found in Authentik: {len(found)}")
    print(f"❌ Missing from Authentik: {len(missing)}")
    print(f"📊 This explains why only {len(found)} users are in the n8n group in Authentik")
    
    if missing:
        print(f"\n👥 Missing users that need to be created in Authentik:")
        for email in missing:
            print(f"   - {email}")

if __name__ == "__main__":
    main()