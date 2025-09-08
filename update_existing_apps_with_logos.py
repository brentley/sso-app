#!/usr/bin/env python3
"""
Update existing Authentik applications with their corresponding logos
"""

import requests
import json
import base64
from PIL import Image
import io
import os
import re
from pathlib import Path

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"
LOGO_DIR = "/Users/brent/Documents/Logos"

def print_progress(msg):
    print(f"[{msg}]")

def authentik_request(method, endpoint, data=None):
    """Make request to Authentik API"""
    url = f"{AUTHENTIK_BASE_URL}{endpoint}"
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=30)
        elif method == 'PATCH':
            response = requests.patch(url, headers=headers, json=data, timeout=30)
        
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print_progress(f"❌ API error for {method} {endpoint}: {e}")
        if hasattr(e, 'response') and e.response:
            print_progress(f"   Response: {e.response.text}")
        return None

def create_small_logo_for_embedding(square_logo_path, max_size=64):
    """Create a small version of square logo for embedding in Authentik"""
    try:
        if not os.path.exists(square_logo_path):
            print_progress(f"❌ Square logo not found: {square_logo_path}")
            return None
            
        with Image.open(square_logo_path) as img:
            small_img = img.resize((max_size, max_size), Image.Resampling.LANCZOS)
            
            output_buffer = io.BytesIO()
            small_img.save(output_buffer, format='PNG', optimize=True)
            output_buffer.seek(0)
            
            small_data = output_buffer.getvalue()
            print_progress(f"   Created small logo: {len(small_data)} bytes")
            
            b64_data = base64.b64encode(small_data).decode()
            data_url = f"data:image/png;base64,{b64_data}"
            print_progress(f"   Data URL: {len(data_url)} chars")
            return data_url
            
    except Exception as e:
        print_progress(f"❌ Error creating small embedded logo: {e}")
        return None

def normalize_name(name):
    """Normalize name for fuzzy matching"""
    normalized = re.sub(r'[^a-zA-Z0-9]', '', name.lower())
    normalized = re.sub(r'(sso|app|application|test|stage|staging|stg|prod|production|videoconferencing|singlesignon)', '', normalized)
    return normalized

def find_square_logo_file(app_name):
    """Find square logo file for an application"""
    if not os.path.exists(LOGO_DIR):
        return None
    
    normalized_app = normalize_name(app_name)
    
    # Look for existing square logos first
    square_files = list(Path(LOGO_DIR).glob("*_square.png"))
    
    best_match = None
    best_score = 0
    
    for square_file in square_files:
        # Remove _square suffix for matching
        base_name = square_file.stem.replace('_square', '')
        normalized_file = normalize_name(base_name)
        
        if normalized_app in normalized_file or normalized_file in normalized_app:
            score = len(set(normalized_app) & set(normalized_file)) / len(set(normalized_app) | set(normalized_file))
            if score > best_score:
                best_score = score
                best_match = square_file
    
    if best_match and best_score > 0.3:
        print_progress(f"✅ Found square logo: {best_match.name} (score: {best_score:.2f})")
        return str(best_match)
    else:
        print_progress(f"❌ No square logo found for '{app_name}'")
        return None

def update_app_with_logo(app):
    """Update a single application with its logo"""
    app_name = app['name']
    app_pk = app['pk']
    app_slug = app['slug']
    
    print_progress(f"\n🔄 Processing: {app_name}")
    print_progress(f"   PK: {app_pk}")
    print_progress(f"   Slug: {app_slug}")
    
    # Check if already has logo
    if app.get('meta_icon'):
        print_progress(f"✅ Already has logo ({len(app['meta_icon'])} chars), skipping")
        return True
    
    # Find square logo
    square_logo_path = find_square_logo_file(app_name)
    if not square_logo_path:
        print_progress(f"⚠️ No square logo found, skipping")
        return False
    
    # Create small embedded logo
    small_logo_url = create_small_logo_for_embedding(square_logo_path, 64)
    if not small_logo_url:
        print_progress(f"❌ Failed to create embedded logo")
        return False
    
    # Update application
    update_data = {
        'meta_icon': small_logo_url
    }
    
    result = authentik_request('PATCH', f'/api/v3/core/applications/{app_pk}/', update_data)
    
    if result:
        print_progress(f"✅ Updated application with logo!")
        if result.get('meta_icon'):
            print_progress(f"✅ Logo confirmed in response!")
        else:
            print_progress(f"❌ No logo in response")
        return True
    else:
        print_progress(f"❌ Failed to update application")
        return False

def main():
    print_progress("🚀 Starting logo update for existing applications")
    
    # Get all applications
    all_apps = []
    page = 1
    
    while True:
        apps_data = authentik_request('GET', f'/api/v3/core/applications/?page={page}&page_size=50')
        if not apps_data or not apps_data.get('results'):
            break
            
        all_apps.extend(apps_data['results'])
        
        if not apps_data.get('next'):
            break
        page += 1
    
    print_progress(f"✅ Found {len(all_apps)} total applications")
    
    # Filter for apps that might be from our migration (have launch URLs with Duo)
    duo_apps = []
    for app in all_apps:
        launch_url = app.get('launch_url', '')
        if 'sso-8090a1e6.sso.duosecurity.com' in launch_url:
            duo_apps.append(app)
    
    print_progress(f"✅ Found {len(duo_apps)} applications with Duo SSO URLs")
    
    # Update each app
    updated_count = 0
    skipped_count = 0
    failed_count = 0
    
    for app in duo_apps:
        try:
            result = update_app_with_logo(app)
            if result is True:
                updated_count += 1
            elif result is False:
                skipped_count += 1
            else:
                failed_count += 1
        except Exception as e:
            print_progress(f"❌ Error processing {app['name']}: {e}")
            failed_count += 1
    
    print_progress(f"\n🎉 Update completed!")
    print_progress(f"   Updated: {updated_count}")
    print_progress(f"   Skipped: {skipped_count}")
    print_progress(f"   Failed: {failed_count}")

if __name__ == "__main__":
    main()