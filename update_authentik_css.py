#!/usr/bin/env python3
"""
Update Authentik brand CSS to reduce application name boldness in user portal
"""

import requests
import json
import datetime

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
    elif method.upper() == 'PATCH':
        response = requests.patch(url, headers=headers, json=data, timeout=15)
    elif method.upper() == 'PUT':
        response = requests.put(url, headers=headers, json=data, timeout=15)
    
    return response

def find_visiquate_brand():
    """Find the id.visiquate.com brand"""
    print("🔍 Looking for id.visiquate.com brand...")
    
    response = authentik_request('GET', '/api/v3/core/brands/')
    if response.status_code == 200:
        brands = response.json().get('results', [])
        for brand in brands:
            if 'id.visiquate.com' in brand.get('domain', ''):
                print(f"✅ Found brand: {brand['domain']} (ID: {brand['brand_uuid']})")
                return brand
        
        print("❌ Brand id.visiquate.com not found")
        return None
    else:
        print(f"❌ Failed to fetch brands: {response.status_code}")
        return None

def backup_current_css(brand):
    """Create a backup of the current custom CSS"""
    current_css = brand.get('attributes', {}).get('custom_css', '')
    
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f'authentik_css_backup_{timestamp}.css'
    
    with open(backup_filename, 'w') as f:
        f.write(current_css)
    
    print(f"✅ Current CSS backed up to: {backup_filename}")
    print(f"   CSS length: {len(current_css)} characters")
    
    return backup_filename, current_css

def create_improved_css(original_css):
    """Add CSS rules to reduce application name boldness"""
    
    # CSS to reduce boldness of application names in the user portal
    debold_css = """

/* ===== VisiQuate User Portal - Reduced Application Name Boldness ===== */

/* Reduce boldness of application names in the user portal library view */
.pf-c-card__title,
.pf-c-card__title a,
.pf-c-card__title-text {
    font-weight: 500 !important; /* Medium instead of bold */
}

/* Target the application tiles/cards in the user portal */
.ak-library-app .pf-c-card__title {
    font-weight: 500 !important;
}

/* Also target any app name links */
.ak-library-app a {
    font-weight: 500 !important;
}

/* Application list items */
.pf-c-data-list__item-main .pf-c-data-list__cell h3,
.pf-c-data-list__item-main .pf-c-data-list__cell a {
    font-weight: 500 !important;
}

/* Any bold application names in general */
.ak-application-name,
.application-name {
    font-weight: 500 !important;
}

/* Reduce PatternFly card title boldness globally for app tiles */
.pf-c-page__main .pf-c-card__title {
    font-weight: 500 !important;
}

/* Also force light mode for better visibility */
:root {
    --pf-global--Color--light-100: #ffffff !important;
    --pf-global--BackgroundColor--light-100: #ffffff !important;
}
"""
    
    return original_css + debold_css

def update_brand_css(brand_uuid, new_css):
    """Update the brand's custom CSS"""
    print(f"\n🔧 Updating brand CSS...")
    
    update_data = {
        "attributes": {
            "custom_css": new_css
        }
    }
    
    response = authentik_request('PATCH', f'/api/v3/core/brands/{brand_uuid}/', update_data)
    
    if response.status_code == 200:
        print("✅ Successfully updated brand CSS")
        print(f"   New CSS length: {len(new_css)} characters")
        return True
    else:
        print(f"❌ Failed to update CSS: {response.status_code}")
        print(f"   Response: {response.text}")
        return False

def main():
    print("🚀 Updating Authentik Brand CSS")
    print("Purpose: Reduce application name boldness in user portal and force light mode")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/?limit=1')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Find the brand
        brand = find_visiquate_brand()
        if not brand:
            return
        
        # Backup current CSS
        backup_file, original_css = backup_current_css(brand)
        
        # Create improved CSS
        new_css = create_improved_css(original_css)
        
        # Update the brand
        success = update_brand_css(brand['brand_uuid'], new_css)
        
        if success:
            print(f"\n🎉 SUCCESS!")
            print(f"   ✅ Authentik brand CSS updated")
            print(f"   📁 Original CSS backed up to: {backup_file}")
            print(f"   🎯 Application names will now be less bold")
            print(f"   🌞 Light mode will be enforced")
            print(f"\n📖 CHANGES MADE:")
            print(f"   - Reduced font-weight from bold (700) to medium (500)")
            print(f"   - Applied to: card titles, app names, data list items")
            print(f"   - Added light mode enforcement")
            print(f"\n💡 The changes should be visible immediately in the user portal")
            print(f"   Visit: https://id.visiquate.com/if/user/#/library")
        else:
            print(f"\n❌ Update failed. CSS backup is available at: {backup_file}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()