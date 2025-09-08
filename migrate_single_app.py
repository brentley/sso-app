#!/usr/bin/env python3
"""
Single app migration test - Airfocus from Duo to Authentik
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

# Authentik API credentials
AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

# Duo API credentials
DUO_INTEGRATION_KEY = "DIB1WWR50U35U32DK6UL"
DUO_SECRET_KEY = "X5vVhpqAFm2aKdC6VJUC5opFIImHVdwtsrjjxQ5a"
DUO_API_HOSTNAME = "api-8090a1e6.duosecurity.com"

# Logo directory
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

def create_duo_client():
    """Create authenticated Duo client"""
    return duo_client.admin.Admin(
        ikey=DUO_INTEGRATION_KEY,
        skey=DUO_SECRET_KEY,
        host=DUO_API_HOSTNAME
    )

def get_duo_integrations():
    """Get all integrations from Duo"""
    try:
        client = create_duo_client()
        integrations = client.get_integrations()
        return integrations
    except Exception as e:
        print_progress(f"❌ Failed to get Duo integrations: {e}")
        return None

def normalize_name(name):
    """Normalize name for fuzzy matching"""
    # Remove common words and normalize
    normalized = re.sub(r'[^a-zA-Z0-9]', '', name.lower())
    normalized = re.sub(r'(sso|app|application|test|stage|staging|stg|prod|production)', '', normalized)
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
        
        # Calculate similarity score
        if normalized_app in normalized_file or normalized_file in normalized_app:
            score = len(set(normalized_app) & set(normalized_file)) / len(set(normalized_app) | set(normalized_file))
            if score > best_score:
                best_score = score
                best_match = logo_file
    
    if best_match and best_score > 0.3:  # Threshold for acceptable match
        print_progress(f"✅ Found logo: {best_match.name} (score: {best_score:.2f})")
        return str(best_match)
    else:
        print_progress(f"❌ No logo found for '{app_name}'")
        return None

def make_square_logo(image_path, output_size=512):
    """Create square version of logo with padding"""
    try:
        with Image.open(image_path) as img:
            # Convert to RGBA if not already
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            # Get current size
            width, height = img.size
            
            # If already square, just resize
            if width == height:
                square_img = img.resize((output_size, output_size), Image.Resampling.LANCZOS)
            else:
                # Create square canvas with transparent background
                max_dim = max(width, height)
                square_img = Image.new('RGBA', (max_dim, max_dim), (255, 255, 255, 0))
                
                # Paste original image centered
                paste_x = (max_dim - width) // 2
                paste_y = (max_dim - height) // 2
                square_img.paste(img, (paste_x, paste_y), img if img.mode == 'RGBA' else None)
                
                # Resize to target size
                square_img = square_img.resize((output_size, output_size), Image.Resampling.LANCZOS)
            
            # Convert to bytes
            img_buffer = io.BytesIO()
            square_img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            return img_buffer.getvalue()
    except Exception as e:
        print_progress(f"❌ Error processing logo {image_path}: {e}")
        return None

def try_media_upload_approaches(logo_data, filename):
    """Try different approaches to upload media to Authentik"""
    
    # Approach 1: Try direct file upload with multipart
    print_progress(f"   Trying multipart file upload...")
    try:
        files = {'file': (filename, logo_data, 'image/png')}
        headers = {"Authorization": f"Bearer {AUTHENTIK_TOKEN}"}
        
        # Try the media upload endpoint pattern
        response = requests.post(
            f"{AUTHENTIK_BASE_URL}/media/public/application-icons/",
            headers=headers,
            files=files,
            timeout=30
        )
        
        print_progress(f"   Multipart upload response: {response.status_code}")
        if response.status_code in [200, 201]:
            return f"/media/public/application-icons/{filename}"
            
    except Exception as e:
        print_progress(f"   Multipart upload error: {e}")
    
    # Approach 2: Try base64 data URL  
    print_progress(f"   Trying base64 data URL...")
    try:
        b64_data = base64.b64encode(logo_data).decode()
        data_url = f"data:image/png;base64,{b64_data}"
        return data_url
    except Exception as e:
        print_progress(f"   Base64 error: {e}")
    
    # Approach 3: Create application first, then try to update with logo
    print_progress(f"   Will create app without logo and try to add later...")
    return None

def main():
    print_progress("🚀 Starting single app migration test - Airfocus")
    
    # Step 1: Get Duo integrations and find Airfocus
    print_progress("📥 Fetching integrations from Duo...")
    
    all_integrations = get_duo_integrations()
    if not all_integrations:
        print_progress("❌ Unable to fetch integrations from Duo API")
        return
    
    # Find Airfocus integration
    airfocus_integration = None
    for integration in all_integrations:
        if 'airfocus' in integration.get('name', '').lower():
            airfocus_integration = integration
            break
    
    if not airfocus_integration:
        print_progress("❌ Airfocus integration not found in Duo")
        return
    
    app_name = airfocus_integration.get('name', 'Airfocus')
    integration_key = airfocus_integration.get('integration_key')
    
    # Construct SSO URL
    host_id = DUO_API_HOSTNAME.split('-')[1].split('.')[0]
    sso_url = f"https://sso-{host_id}.sso.duosecurity.com/saml2/sp/{integration_key}/sso"
    
    print_progress(f"✅ Found Airfocus integration:")
    print_progress(f"   Name: {app_name}")
    print_progress(f"   Integration Key: {integration_key}")
    print_progress(f"   SSO URL: {sso_url}")
    
    # Step 2: Find logo
    logo_path = find_logo_file(app_name)
    if not logo_path:
        print_progress("❌ No logo found for Airfocus, stopping")
        return
    
    # Step 3: Process logo
    logo_data = make_square_logo(logo_path)
    if not logo_data:
        print_progress("❌ Failed to process logo, stopping")
        return
    
    # Step 4: Try to upload logo 
    logo_filename = f"{normalize_name(app_name)}_logo.png"
    logo_url = try_media_upload_approaches(logo_data, logo_filename)
    
    # Step 5: Create application
    app_data = {
        'name': app_name,
        'slug': re.sub(r'[^a-z0-9-]', '-', app_name.lower().replace(' ', '-')),
        'launch_url': sso_url,
        'open_in_new_tab': True,
        'meta_launch_url': sso_url,
        'meta_description': '',
        'meta_publisher': '',
        'policy_engine_mode': 'any',
        'group': ''
    }
    
    if logo_url:
        app_data['meta_icon'] = logo_url
        print_progress(f"   Will create application with logo: {logo_url}")
    else:
        print_progress(f"   Will create application without logo")
    
    # Create the application
    result = authentik_request('POST', '/api/v3/core/applications/', app_data)
    
    if result:
        print_progress(f"✅ Created application: {app_name}")
        print_progress(f"   Application PK: {result.get('pk')}")
        print_progress(f"   Slug: {result.get('slug')}")
        
        # If we created without logo, try to update with logo
        if not logo_url and logo_data:
            print_progress("   Trying to add logo after creation...")
            # Save logo to a temp location and try different approaches
            temp_logo_path = f"/tmp/{logo_filename}"
            with open(temp_logo_path, 'wb') as f:
                f.write(logo_data)
            print_progress(f"   Logo saved to: {temp_logo_path}")
            print_progress(f"   You may need to manually upload this logo to Authentik")
    else:
        print_progress(f"❌ Failed to create application: {app_name}")

if __name__ == "__main__":
    main()