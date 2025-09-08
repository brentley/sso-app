#!/usr/bin/env python3
"""
Test the updated migration script on a few applications
"""

import json
import time
import requests
import os
import sys
from datetime import datetime
import re
from PIL import Image
import io
import base64
from pathlib import Path
import duo_client.admin

# Just copy the key functions from the main migration script to test a few apps
AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"
DUO_INTEGRATION_KEY = "DIB1WWR50U35U32DK6UL"
DUO_SECRET_KEY = "X5vVhpqAFm2aKdC6VJUC5opFIImHVdwtsrjjxQ5a"
DUO_API_HOSTNAME = "api-8090a1e6.duosecurity.com"
LOGO_DIR = "/Users/brent/Documents/Logos"

def print_progress(msg):
    """Print with timestamp and flush"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {msg}")
    sys.stdout.flush()

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
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data, timeout=30)
        elif method == 'PATCH':
            response = requests.patch(url, headers=headers, json=data, timeout=30)
        
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print_progress(f"❌ Authentik API error for {method} {endpoint}: {e}")
        if hasattr(e, 'response') and e.response:
            print_progress(f"   Response: {e.response.text}")
        return None

def normalize_name(name):
    """Normalize name for fuzzy matching"""
    normalized = re.sub(r'[^a-zA-Z0-9]', '', name.lower())
    normalized = re.sub(r'(sso|app|application|test|stage|staging|stg|prod|production|videoconferencing|singlesignon)', '', normalized)
    return normalized

def find_logo_file(app_name):
    """Find logo file using fuzzy matching"""
    if not os.path.exists(LOGO_DIR):
        print_progress(f"⚠️ Logo directory not found: {LOGO_DIR}")
        return None
    
    normalized_app = normalize_name(app_name)
    print_progress(f"🔍 Looking for logo for '{app_name}' (normalized: '{normalized_app}')")
    
    logo_files = []
    for ext in ['png', 'jpg', 'jpeg', 'svg', 'gif']:
        logo_files.extend(Path(LOGO_DIR).glob(f"*.{ext}"))
        logo_files.extend(Path(LOGO_DIR).glob(f"*.{ext.upper()}"))
    
    best_match = None
    best_score = 0
    
    for logo_file in logo_files:
        normalized_file = normalize_name(logo_file.stem)
        
        if normalized_app in normalized_file or normalized_file in normalized_app:
            score = len(set(normalized_app) & set(normalized_file)) / len(set(normalized_app) | set(normalized_file))
            if score > best_score:
                best_score = score
                best_match = logo_file
    
    if best_match and best_score > 0.3:
        print_progress(f"✅ Found logo: {best_match.name} (score: {best_score:.2f})")
        return str(best_match)
    else:
        print_progress(f"❌ No logo found for '{app_name}'")
        return None

def make_square_logo(image_path, output_size=512):
    """Create square version of logo with padding and save as new file"""
    try:
        path_obj = Path(image_path)
        output_filename = f"{path_obj.stem}_square{path_obj.suffix}"
        output_path = path_obj.parent / output_filename
        
        if output_path.exists():
            print_progress(f"   Using existing square logo: {output_filename}")
            with open(output_path, 'rb') as f:
                return f.read()
        
        with Image.open(image_path) as img:
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            width, height = img.size
            
            if width == height:
                square_img = img.resize((output_size, output_size), Image.Resampling.LANCZOS)
                print_progress(f"   Logo already square, resized to {output_size}x{output_size}")
            else:
                max_dim = max(width, height)
                square_img = Image.new('RGBA', (max_dim, max_dim), (255, 255, 255, 0))
                
                paste_x = (max_dim - width) // 2
                paste_y = (max_dim - height) // 2
                square_img.paste(img, (paste_x, paste_y), img if img.mode == 'RGBA' else None)
                
                square_img = square_img.resize((output_size, output_size), Image.Resampling.LANCZOS)
                print_progress(f"   Logo padded from {width}x{height} to {output_size}x{output_size}")
            
            square_img.save(output_path, format='PNG')
            print_progress(f"✅ Square logo saved: {output_filename}")
            
            img_buffer = io.BytesIO()
            square_img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            return img_buffer.getvalue()
    except Exception as e:
        print_progress(f"❌ Error processing logo {image_path}: {e}")
        return None

def create_small_logo_for_embedding(logo_data, max_size=64):
    """Create a small version of logo for embedding in Authentik"""
    try:
        img_buffer = io.BytesIO(logo_data)
        with Image.open(img_buffer) as img:
            small_img = img.resize((max_size, max_size), Image.Resampling.LANCZOS)
            
            output_buffer = io.BytesIO()
            small_img.save(output_buffer, format='PNG', optimize=True)
            output_buffer.seek(0)
            
            small_data = output_buffer.getvalue()
            print_progress(f"   Created small logo: {len(small_data)} bytes (was {len(logo_data)})")
            
            b64_data = base64.b64encode(small_data).decode()
            data_url = f"data:image/png;base64,{b64_data}"
            print_progress(f"✅ Small logo embedded as data URL ({len(data_url)} chars)")
            return data_url
            
    except Exception as e:
        print_progress(f"❌ Error creating small embedded logo: {e}")
        return None

def test_app_migration(app_name, sso_url):
    """Test migrating a single app"""
    print_progress(f"\n🔄 Testing migration: {app_name}")
    print_progress(f"   SSO URL: {sso_url}")
    
    # Find and process logo
    logo_path = find_logo_file(app_name)
    if not logo_path:
        print_progress(f"⚠️ Skipping '{app_name}' - no logo found")
        return
    
    logo_data = make_square_logo(logo_path)
    if not logo_data:
        print_progress(f"⚠️ Skipping '{app_name}' - failed to process logo")
        return
    
    # Create small embedded logo
    small_logo_url = create_small_logo_for_embedding(logo_data, 64)
    if not small_logo_url:
        print_progress(f"⚠️ Skipping '{app_name}' - failed to create small logo")
        return
    
    # Create slug and check if exists
    slug = re.sub(r'[^a-z0-9-]', '-', app_name.lower().replace(' ', '-'))
    existing_apps = authentik_request('GET', f'/api/v3/core/applications/?slug={slug}')
    if existing_apps and existing_apps.get('results'):
        print_progress(f"⚠️ Application with slug '{slug}' already exists, skipping")
        return
    
    # Create application with embedded logo
    app_data = {
        'name': app_name,
        'slug': slug,
        'launch_url': sso_url,
        'open_in_new_tab': True,
        'meta_launch_url': sso_url,
        'meta_description': f'Migrated from Duo SSO. Square logo available at: {Path(logo_path).parent}/{Path(logo_path).stem}_square.png',
        'meta_publisher': 'Duo Migration',
        'policy_engine_mode': 'any',
        'group': '',
        'meta_icon': small_logo_url
    }
    
    result = authentik_request('POST', '/api/v3/core/applications/', app_data)
    
    if result:
        print_progress(f"✅ Created application: {app_name}")
        print_progress(f"   PK: {result.get('pk')}")
        if result.get('meta_icon'):
            print_progress(f"   ✅ Logo successfully embedded!")
        else:
            print_progress(f"   ❌ No logo in result")
    else:
        print_progress(f"❌ Failed to create application: {app_name}")

# Test with a few applications
test_apps = [
    ("Dropbox - File Storage", "https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIX5T7WOHRY2H8J6O38R/sso"),
    ("Salesforce - CRM", "https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIAHFA802T9FGIH3DBNK/sso"), 
    ("ChatGPT Enterprise", "https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIXQ92CE7TPPVC8GGA88/sso")
]

if __name__ == "__main__":
    print_progress("🚀 Testing updated migration script")
    for app_name, sso_url in test_apps:
        test_app_migration(app_name, sso_url)