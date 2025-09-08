#!/usr/bin/env python3
"""
Check each n8n user individually in Authentik API
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
        response = requests.get(url, headers=headers, timeout=10)
    elif method.upper() == 'POST':
        response = requests.post(url, headers=headers, json=data, timeout=10)
    
    return response

def search_user_by_email(email):
    """Search for a specific user by email"""
    # Try direct search by email
    response = authentik_request('GET', f'/api/v3/core/users/?search={email}')
    
    if response.status_code == 200:
        data = response.json()
        results = data.get('results', [])
        
        # Look for exact email match
        for user in results:
            if user.get('email', '').lower() == email.lower():
                return user
    
    return None

def search_user_by_username(username):
    """Search for a specific user by username"""
    # Try search by username
    response = authentik_request('GET', f'/api/v3/core/users/?search={username}')
    
    if response.status_code == 200:
        data = response.json()
        results = data.get('results', [])
        
        # Look for exact username match
        for user in results:
            if user.get('username', '').lower() == username.lower():
                return user
    
    return None

def main():
    # n8n group members from Duo
    n8n_members = [
        {
            "username": "megan.langston",
            "email": "megan.langston@visiquate.com",
            "realname": "Megan Langston"
        },
        {
            "username": "vitaliy.gavrylenko",
            "email": "vitaliy.gavrylenko@visiquate.com", 
            "realname": "Vitaliy Gavrylenko"
        },
        {
            "username": "natalya.goryayinova",
            "email": "natalya.goryayinova@visiquate.com",
            "realname": "Natalya Goryayinova"
        },
        {
            "username": "denys.malyshev",
            "email": "denys.malyshev@visiquate.com",
            "realname": "Denys Malyshev"
        },
        {
            "username": "oleg.avdyeyev",
            "email": "oleg.avdyeyev@visiquate.com",
            "realname": "Oleg Avdyeyev"
        },
        {
            "username": "serhii.tkachuk",
            "email": "serhii.tkachuk@visiquate.com",
            "realname": "Serhii Tkachuk"
        },
        {
            "username": "oleksii.voitenko",
            "email": "oleksii.voitenko@visiquate.com",
            "realname": "Oleksii Voitenko"
        },
        {
            "username": "brent.langston",
            "email": "brent.langston@visiquate.com",
            "realname": "Brent Langston"
        },
        {
            "username": "ben.adeemi",
            "email": "ben.adeemi@visiquate.com",
            "realname": "Ben Adeemi"
        },
        {
            "username": "yuliia.lutai",
            "email": "yuliia.lutai@visiquate.com",
            "realname": "Yuliia Lutai"
        },
        {
            "username": "sergiy.vats",
            "email": "sergiy.vats@visiquate.com",
            "realname": "Sergiy Vats"
        },
        {
            "username": "maksym.dilanian",
            "email": "maksym.dilanian@visiquate.com",
            "realname": "Maksym Dilanian"
        },
        {
            "username": "serhii.chaika",
            "email": "serhii.chaika@visiquate.com",
            "realname": "Serhii Chaika"
        }
    ]
    
    print(f"🔍 Checking each n8n group member individually in Authentik...")
    print(f"📧 Testing API with single user search first...")
    
    # Test API connectivity with known user (brent.langston)
    test_user = search_user_by_email("brent.langston@visiquate.com")
    if test_user:
        print(f"✅ API working - found test user: {test_user.get('username')} ({test_user.get('email')})")
    else:
        print(f"❌ API test failed - could not find brent.langston@visiquate.com")
        return
    
    print(f"\n🔍 Now checking all {len(n8n_members)} n8n members...")
    
    found_users = []
    missing_users = []
    
    for member in n8n_members:
        username = member['username']
        email = member['email']
        realname = member['realname']
        
        print(f"\n👤 Checking: {realname} ({email})")
        
        # Try searching by email first
        user = search_user_by_email(email)
        if user:
            found_users.append({
                'expected': member,
                'found': user,
                'match_type': 'email'
            })
            print(f"   ✅ FOUND by email: ID={user['pk']}, username='{user.get('username')}', email='{user.get('email')}'")
            continue
        
        # Try searching by username
        user = search_user_by_username(username)
        if user:
            found_users.append({
                'expected': member,
                'found': user,
                'match_type': 'username'
            })
            print(f"   ✅ FOUND by username: ID={user['pk']}, username='{user.get('username')}', email='{user.get('email')}'")
            continue
        
        # Try variations (without domain, etc.)
        username_only = username.split('@')[0] if '@' in username else username
        user = search_user_by_username(username_only)
        if user:
            found_users.append({
                'expected': member,
                'found': user,
                'match_type': 'username_variation'
            })
            print(f"   ✅ FOUND by username variation '{username_only}': ID={user['pk']}, username='{user.get('username')}', email='{user.get('email')}'")
            continue
        
        # Not found
        missing_users.append(member)
        print(f"   ❌ NOT FOUND: {email}")
    
    print(f"\n📊 SUMMARY:")
    print(f"✅ Found in Authentik: {len(found_users)}")
    print(f"❌ Missing from Authentik: {len(missing_users)}")
    
    if found_users:
        print(f"\n✅ FOUND USERS:")
        for item in found_users:
            expected = item['expected']
            found = item['found']
            match_type = item['match_type']
            print(f"   {expected['email']} -> ID {found['pk']} (matched by {match_type})")
    
    if missing_users:
        print(f"\n❌ MISSING USERS:")
        for user in missing_users:
            print(f"   {user['email']} ({user['realname']})")

if __name__ == "__main__":
    main()