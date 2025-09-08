#!/usr/bin/env python3
"""
Investigate why bulk fetch and individual search return different results
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
    
    return response

def bulk_fetch_sample():
    """Get a sample from bulk fetch API"""
    print("🔍 Testing bulk fetch API...")
    response = authentik_request('GET', '/api/v3/core/users/?limit=10&offset=0')
    
    if response.status_code == 200:
        data = response.json()
        users = data.get('results', [])
        print(f"✅ Bulk fetch returned {len(users)} users")
        print(f"📊 Sample user structure:")
        if users:
            user = users[0]
            print(f"   ID: {user.get('pk')}")
            print(f"   Username: {user.get('username')}")
            print(f"   Email: {user.get('email')}")
            print(f"   Active: {user.get('is_active')}")
            print(f"   Type: {user.get('type')}")
            print(f"   All fields: {list(user.keys())}")
        
        # Check if megan.langston is in this sample
        for user in users:
            if user.get('email') == 'megan.langston@visiquate.com':
                print(f"✅ Found megan.langston in bulk fetch sample: {user}")
                return user
        
        print(f"❌ megan.langston not in first 10 users from bulk fetch")
    
    return None

def search_fetch_megan():
    """Search for megan specifically"""
    print("\n🔍 Testing search API for megan.langston...")
    response = authentik_request('GET', '/api/v3/core/users/?search=megan.langston@visiquate.com')
    
    if response.status_code == 200:
        data = response.json()
        users = data.get('results', [])
        print(f"✅ Search returned {len(users)} users")
        
        for user in users:
            if user.get('email') == 'megan.langston@visiquate.com':
                print(f"✅ Found megan via search:")
                print(f"   ID: {user.get('pk')}")
                print(f"   Username: {user.get('username')}")
                print(f"   Email: {user.get('email')}")
                print(f"   Active: {user.get('is_active')}")
                print(f"   Type: {user.get('type')}")
                print(f"   All fields: {list(user.keys())}")
                return user
    
    return None

def bulk_fetch_specific_page():
    """Try to find megan in bulk fetch by looking at more pages"""
    print("\n🔍 Looking for megan in bulk fetch across multiple pages...")
    
    for page in range(10):  # Check first 10 pages
        offset = page * 100
        response = authentik_request('GET', f'/api/v3/core/users/?limit=100&offset={offset}')
        
        if response.status_code == 200:
            data = response.json()
            users = data.get('results', [])
            print(f"📄 Page {page + 1}: {len(users)} users")
            
            if not users:  # No more results
                break
            
            for user in users:
                if user.get('email') == 'megan.langston@visiquate.com':
                    print(f"✅ Found megan in bulk fetch on page {page + 1}:")
                    print(f"   ID: {user.get('pk')}")
                    print(f"   Username: {user.get('username')}")
                    print(f"   Email: {user.get('email')}")
                    print(f"   Active: {user.get('is_active')}")
                    print(f"   Type: {user.get('type')}")
                    return user
        else:
            print(f"❌ Failed to fetch page {page + 1}: {response.status_code}")
            break
    
    print(f"❌ megan.langston not found in bulk fetch across first 10 pages (1000+ users)")
    return None

def compare_apis():
    """Compare the two API approaches"""
    print("🔬 Comparing API approaches for user discovery...")
    
    # Test both approaches
    bulk_user = bulk_fetch_sample()
    search_user = search_fetch_megan()
    bulk_extended = bulk_fetch_specific_page()
    
    print(f"\n📊 Results:")
    print(f"   Bulk fetch (first 10): {'✅ Found' if bulk_user else '❌ Not found'}")
    print(f"   Search API: {'✅ Found' if search_user else '❌ Not found'}")  
    print(f"   Bulk fetch (extended): {'✅ Found' if bulk_extended else '❌ Not found'}")
    
    if search_user and not bulk_extended:
        print(f"\n💡 CONCLUSION:")
        print(f"   - Individual search FINDS the user")
        print(f"   - Bulk fetch does NOT return this user (even across 1000+ users)")
        print(f"   - This suggests different filtering/inclusion logic between APIs")
        print(f"   - Possible causes: user status, permissions, or API endpoint differences")
        
        print(f"\n🔧 RECOMMENDED SOLUTION:")
        print(f"   Use search API instead of bulk fetch for building user lookup")
    
    # Compare pagination info
    print(f"\n🔍 Checking pagination metadata...")
    bulk_response = authentik_request('GET', '/api/v3/core/users/?limit=1')
    search_response = authentik_request('GET', '/api/v3/core/users/?search=&limit=1') 
    
    if bulk_response.status_code == 200 and search_response.status_code == 200:
        bulk_data = bulk_response.json()
        search_data = search_response.json()
        
        bulk_total = bulk_data.get('pagination', {}).get('count', 0)
        search_total = search_data.get('pagination', {}).get('count', 0)
        
        print(f"   Bulk API total count: {bulk_total}")
        print(f"   Search API total count: {search_total}")
        
        if bulk_total != search_total:
            print(f"   ⚠️  Different total counts - confirms different filtering!")

if __name__ == "__main__":
    compare_apis()