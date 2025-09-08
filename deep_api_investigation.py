#!/usr/bin/env python3
"""
Deep investigation: Why do bulk and individual searches return different users?
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

def get_user_individual_search(email):
    """Get user via individual search"""
    response = authentik_request('GET', f'/api/v3/core/users/?search={email}')
    
    if response.status_code == 200:
        data = response.json()
        results = data.get('results', [])
        for user in results:
            if user.get('email', '').lower() == email.lower():
                return user
    return None

def get_user_by_id(user_id):
    """Get user by specific ID"""
    response = authentik_request('GET', f'/api/v3/core/users/{user_id}/')
    
    if response.status_code == 200:
        return response.json()
    return None

def deep_bulk_search():
    """Do exhaustive bulk search to see what's actually returned"""
    print("🔬 Deep investigation: Exhaustive bulk search...")
    
    all_emails = set()
    all_users = []
    
    # Try different API endpoints
    endpoints_to_try = [
        '/api/v3/core/users/',  # Original bulk fetch
        '/api/v3/core/users/?search=',  # Search with empty parameter
        '/api/v3/core/users/?ordering=email',  # Different ordering
        '/api/v3/core/users/?is_active=true',  # Only active users
        '/api/v3/core/users/?type=internal',  # Only internal users
    ]
    
    for endpoint in endpoints_to_try:
        print(f"\n🔍 Testing endpoint: {endpoint}")
        
        page_emails = set()
        offset = 0
        max_pages = 10
        
        for page in range(max_pages):
            url_with_pagination = f"{endpoint}{'&' if '?' in endpoint else '?'}limit=100&offset={offset}"
            response = authentik_request('GET', url_with_pagination)
            
            if response.status_code != 200:
                print(f"❌ Failed: {response.status_code}")
                break
                
            data = response.json()
            users = data.get('results', [])
            total_count = data.get('pagination', {}).get('count', 0)
            
            if not users:
                break
                
            page_user_emails = [u.get('email', '') for u in users if u.get('email')]
            page_emails.update(page_user_emails)
            
            # Look specifically for our test users
            found_test_users = []
            for user in users:
                email = user.get('email', '')
                if email in ['megan.langston@visiquate.com', 'vitaliy.gavrylenko@visiquate.com', 'brent.langston@visiquate.com']:
                    found_test_users.append(f"{email} (ID: {user['pk']})")
            
            print(f"   Page {page + 1}: {len(users)} users, {len(page_user_emails)} with email, total count: {total_count}")
            if found_test_users:
                print(f"   🎯 Found test users: {', '.join(found_test_users)}")
            
            if len(users) < 100:  # Last page
                break
                
            offset += 100
        
        all_emails.update(page_emails)
        print(f"✅ {endpoint}: Found {len(page_emails)} unique emails")
    
    print(f"\n📊 COMBINED RESULTS:")
    print(f"   Total unique emails across all endpoints: {len(all_emails)}")
    
    # Check specific users in the combined results
    test_emails = ['megan.langston@visiquate.com', 'vitaliy.gavrylenko@visiquate.com', 'brent.langston@visiquate.com']
    
    for email in test_emails:
        if email in all_emails:
            print(f"   ✅ {email} found in bulk results")
        else:
            print(f"   ❌ {email} NOT found in bulk results")
    
    return all_emails

def investigate_missing_users():
    """Investigate specific missing users"""
    print("\n🔍 Investigating specific missing users...")
    
    missing_emails = [
        'megan.langston@visiquate.com',
        'vitaliy.gavrylenko@visiquate.com', 
        'natalya.goryayinova@visiquate.com',
        'oleg.avdyeyev@visiquate.com'
    ]
    
    for email in missing_emails:
        print(f"\n👤 Investigating: {email}")
        
        # Try individual search
        user = get_user_individual_search(email)
        if user:
            print(f"   ✅ Individual search: Found ID {user['pk']}")
            print(f"      - Username: {user.get('username')}")
            print(f"      - Active: {user.get('is_active')}")
            print(f"      - Type: {user.get('type')}")
            print(f"      - Groups: {len(user.get('groups', []))}")
            print(f"      - Last login: {user.get('last_login')}")
            print(f"      - Date joined: {user.get('date_joined')}")
            
            # Try to get same user by ID
            user_by_id = get_user_by_id(user['pk'])
            if user_by_id:
                print(f"   ✅ Direct ID lookup: Confirmed")
            else:
                print(f"   ❌ Direct ID lookup: Failed")
        else:
            print(f"   ❌ Individual search: NOT FOUND")

def main():
    print("🚀 Deep API Investigation: Why are users missing from bulk operations?")
    
    # First, verify our test case
    print("\n🧪 Verify test case:")
    megan_individual = get_user_individual_search('megan.langston@visiquate.com')
    if megan_individual:
        print(f"✅ Control test: Individual search finds megan (ID: {megan_individual['pk']})")
    else:
        print(f"❌ Control test FAILED: Individual search should find megan!")
        return
    
    # Deep bulk search investigation
    bulk_emails = deep_bulk_search()
    
    # Investigate specific missing users
    investigate_missing_users()
    
    print("\n💡 CONCLUSIONS:")
    print("   1. If individual search finds users but bulk doesn't:")
    print("      -> There's API filtering in bulk operations")
    print("   2. If different bulk endpoints return different results:")
    print("      -> User status/type filtering affects bulk results")
    print("   3. Possible solutions:")
    print("      -> Use individual search for each expected user")
    print("      -> Find the right bulk API parameters to include all users")

if __name__ == "__main__":
    main()