#!/usr/bin/env python3
"""
Duo to Authentik Migration Script
Migrates SSO applications from Duo to Authentik as bookmarks
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

def get_integration_groups(integration_key):
    """Get groups assigned to an integration"""
    try:
        client = create_duo_client()
        # Use api_call for custom endpoints
        response = client.api_call('GET', f'/admin/v1/integrations/{integration_key}/groups', {})
        return response
    except Exception as e:
        print_progress(f"❌ Failed to get groups for integration {integration_key}: {e}")
        return None

def normalize_name(name):
    """Normalize name for fuzzy matching"""
    # Remove common words and normalize
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
    """Create square version of logo with padding and save as new file"""
    try:
        # Generate output filename (add _square suffix)
        path_obj = Path(image_path)
        output_filename = f"{path_obj.stem}_square{path_obj.suffix}"
        output_path = path_obj.parent / output_filename
        
        # Check if square version already exists
        if output_path.exists():
            print_progress(f"   Using existing square logo: {output_filename}")
            with open(output_path, 'rb') as f:
                return f.read()
        
        with Image.open(image_path) as img:
            # Convert to RGBA if not already
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            # Get current size
            width, height = img.size
            
            # If already square, just resize
            if width == height:
                square_img = img.resize((output_size, output_size), Image.Resampling.LANCZOS)
                print_progress(f"   Logo already square, resized to {output_size}x{output_size}")
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
                print_progress(f"   Logo padded from {width}x{height} to {output_size}x{output_size}")
            
            # Save square version as new file
            square_img.save(output_path, format='PNG')
            print_progress(f"✅ Square logo saved: {output_filename}")
            
            # Convert to bytes for return
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
            # Create small version for embedding
            small_img = img.resize((max_size, max_size), Image.Resampling.LANCZOS)
            
            # Convert back to bytes
            output_buffer = io.BytesIO()
            small_img.save(output_buffer, format='PNG', optimize=True)
            output_buffer.seek(0)
            
            small_data = output_buffer.getvalue()
            print_progress(f"   Created small logo: {len(small_data)} bytes (was {len(logo_data)})")
            
            # Create base64 data URL
            b64_data = base64.b64encode(small_data).decode()
            data_url = f"data:image/png;base64,{b64_data}"
            print_progress(f"✅ Small logo embedded as data URL ({len(data_url)} chars)")
            return data_url
            
    except Exception as e:
        print_progress(f"❌ Error creating small embedded logo: {e}")
        return None

def fuzzy_match_groups(duo_group_names, authentik_groups):
    """Match Duo groups to Authentik groups using fuzzy matching"""
    matched_groups = []
    
    for duo_group in duo_group_names:
        normalized_duo = normalize_name(duo_group)
        
        best_match = None
        best_score = 0
        
        for authentik_group in authentik_groups:
            normalized_authentik = normalize_name(authentik_group['name'])
            
            # Calculate similarity
            if normalized_duo in normalized_authentik or normalized_authentik in normalized_duo:
                score = len(set(normalized_duo) & set(normalized_authentik)) / len(set(normalized_duo) | set(normalized_authentik))
                if score > best_score:
                    best_score = score
                    best_match = authentik_group
        
        if best_match and best_score > 0.4:  # Threshold for group matching
            matched_groups.append(best_match['pk'])
            print_progress(f"✅ Matched group: '{duo_group}' -> '{best_match['name']}' (score: {best_score:.2f})")
        else:
            print_progress(f"❌ No group match found for '{duo_group}'")
    
    return matched_groups

def main():
    print_progress("🚀 Starting Duo to Authentik migration")
    
    # Step 1: Get Duo integrations (SSO applications)
    print_progress("📥 Fetching integrations from Duo...")
    
    all_integrations = get_duo_integrations()
    if not all_integrations:
        print_progress("❌ Unable to fetch integrations from Duo API")
        return
    
    # Filter for SSO integrations with proper SSO types
    sso_integrations = []
    for integration in all_integrations:
        int_type = integration.get('type', '')
        int_name = integration.get('name', '').lower()
        
        # Look for SSO-specific types or names
        if ('sso' in int_type or 
            'sso' in int_name or 
            'saml' in int_name):
            sso_integrations.append(integration)
    
    print_progress(f"✅ Found {len(all_integrations)} total integrations, {len(sso_integrations)} SSO integrations")
    
    # Step 2: Get Authentik groups for matching
    print_progress("📥 Fetching groups from Authentik...")
    authentik_groups_data = authentik_request('GET', '/api/v3/core/groups/')
    if not authentik_groups_data:
        print_progress("❌ Unable to fetch groups from Authentik")
        return
    
    authentik_groups = authentik_groups_data.get('results', [])
    print_progress(f"✅ Found {len(authentik_groups)} Authentik groups")
    
    # Step 3: Process each SSO integration
    print_progress(f"🔄 Processing {len(sso_integrations)} SSO integrations")
    
    for integration in sso_integrations:
        try:
            app_name = integration.get('name', 'Unknown App')
            integration_key = integration.get('integration_key')
            
            # Skip internal VisiQuate SSO integrations (these are for platform auth, not individual apps)
            if 'internal visiquate sso' in app_name.lower():
                print_progress(f"⚠️ Skipping internal platform SSO: {app_name}")
                continue
                
            # Construct SSO URL using Duo's pattern: https://sso-{host_id}.sso.duosecurity.com/saml2/sp/{integration_key}/sso
            host_id = DUO_API_HOSTNAME.split('-')[1].split('.')[0]  # Extract 8090a1e6 from api-8090a1e6.duosecurity.com
            sso_url = f"https://sso-{host_id}.sso.duosecurity.com/saml2/sp/{integration_key}/sso"
            
            if not integration_key:
                print_progress(f"⚠️ No integration key found for '{app_name}', skipping")
                continue
            
            print_progress(f"\n🔄 Processing integration: {app_name}")
            print_progress(f"   Type: {integration.get('type', 'unknown')}")
            print_progress(f"   SSO URL: {sso_url}")
            
            # Get group access for this integration
            integration_key = integration.get('integration_key')
            duo_group_names = []
            
            if integration_key:
                groups_response = get_integration_groups(integration_key)
                if groups_response and isinstance(groups_response, list):
                    duo_group_names = [g.get('name') for g in groups_response if g.get('name')]
                elif groups_response and 'response' in groups_response:
                    duo_group_names = [g.get('name') for g in groups_response['response'] if g.get('name')]
            
            print_progress(f"   Assigned groups: {duo_group_names}")
            
            # Match groups
            matched_group_pks = fuzzy_match_groups(duo_group_names, authentik_groups)
            
            # Find and process logo - REQUIRED for migration
            logo_path = find_logo_file(app_name)
            
            # Skip if no logo found (per user requirement)
            if not logo_path:
                print_progress(f"⚠️ Skipping '{app_name}' - no logo found")
                continue
            
            logo_data = make_square_logo(logo_path)
            if not logo_data:
                print_progress(f"⚠️ Skipping '{app_name}' - failed to process logo")
                continue
            
            # Create small embedded logo from the square logo
            small_logo_url = create_small_logo_for_embedding(logo_data, 64)
            if not small_logo_url:
                print_progress(f"⚠️ Skipping '{app_name}' - failed to create small logo")
                continue
            
            # Create slug and check if application already exists
            slug = re.sub(r'[^a-z0-9-]', '-', app_name.lower().replace(' ', '-'))
            
            # Check if application with this slug already exists
            existing_apps = authentik_request('GET', f'/api/v3/core/applications/?slug={slug}')
            if existing_apps and existing_apps.get('results'):
                print_progress(f"⚠️ Application with slug '{slug}' already exists, skipping")
                continue
            
            # Create bookmark application in Authentik with embedded small logo
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
                'meta_icon': small_logo_url  # Embedded small logo
            }
            
            # Create the application
            result = authentik_request('POST', '/api/v3/core/applications/', app_data)
            
            if result:
                app_pk = result.get('pk')
                print_progress(f"✅ Created application: {app_name}")
                
                # Assign groups
                if matched_group_pks and app_pk:
                    for group_pk in matched_group_pks:
                        group_assignment = {
                            'group': group_pk,
                            'application': app_pk
                        }
                        # Note: This might need adjustment based on Authentik's group assignment API
                        assignment_result = authentik_request('POST', '/api/v3/core/application_entitlements/', group_assignment)
                        if assignment_result:
                            print_progress(f"✅ Assigned group access")
                        else:
                            print_progress(f"❌ Failed to assign group access")
            else:
                print_progress(f"❌ Failed to create application: {app_name}")
                
        except Exception as e:
            print_progress(f"❌ Error processing {app_name}: {e}")
    
    print_progress("\n🎉 Migration completed!")

if __name__ == "__main__":
    main()