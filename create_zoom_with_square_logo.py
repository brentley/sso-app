#!/usr/bin/env python3
"""
Create Zoom app with properly squared logo
"""

import requests
import base64
from PIL import Image
import io
import os
from pathlib import Path

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def make_square_logo(image_path, output_size=512):
    """Create square version of logo with padding and save as new file"""
    try:
        # Generate output filename (add _square suffix)
        path_obj = Path(image_path)
        output_filename = f"{path_obj.stem}_square{path_obj.suffix}"
        output_path = path_obj.parent / output_filename
        
        # Check if square version already exists
        if output_path.exists():
            print(f"   Using existing square logo: {output_filename}")
            with open(output_path, 'rb') as f:
                return f.read(), str(output_path)
        
        with Image.open(image_path) as img:
            # Convert to RGBA if not already
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            # Get current size
            width, height = img.size
            print(f"   Original logo size: {width}x{height}")
            
            # If already square, just resize
            if width == height:
                square_img = img.resize((output_size, output_size), Image.Resampling.LANCZOS)
                print(f"   Logo already square, resized to {output_size}x{output_size}")
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
                print(f"   Logo padded from {width}x{height} to {output_size}x{output_size}")
            
            # Save square version as new file
            square_img.save(output_path, format='PNG')
            print(f"✅ Square logo saved: {output_filename}")
            
            # Convert to bytes for return
            img_buffer = io.BytesIO()
            square_img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            return img_buffer.getvalue(), str(output_path)
    except Exception as e:
        print(f"❌ Error processing logo {image_path}: {e}")
        return None, None

def create_small_square_logo(square_logo_data, max_size=64):
    """Create a small version of the square logo for embedding"""
    try:
        img_buffer = io.BytesIO(square_logo_data)
        with Image.open(img_buffer) as img:
            # Create small version for embedding
            small_img = img.resize((max_size, max_size), Image.Resampling.LANCZOS)
            
            # Convert back to bytes
            output_buffer = io.BytesIO()
            small_img.save(output_buffer, format='PNG', optimize=True)
            output_buffer.seek(0)
            
            return output_buffer.getvalue()
    except Exception as e:
        print(f"Error creating small logo: {e}")
        return None

def create_zoom_app():
    """Create Zoom app with square logo"""
    
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"  
    }
    
    # Create square logo
    logo_path = "/Users/brent/Documents/Logos/zoom.png"
    if not os.path.exists(logo_path):
        print("Zoom logo not found")
        return
        
    print("Creating square version of Zoom logo...")
    square_logo_data, square_logo_path = make_square_logo(logo_path)
    if not square_logo_data:
        return
        
    # Create small version for embedding
    print("Creating small version for embedding...")
    small_logo_data = create_small_square_logo(square_logo_data, 64)
    if not small_logo_data:
        return
        
    print(f"Small logo: {len(small_logo_data)} bytes")
    
    # Create base64 data URL with small version
    b64_data = base64.b64encode(small_logo_data).decode()
    data_url = f"data:image/png;base64,{b64_data}"
    
    print(f"Data URL length: {len(data_url)} characters")
    
    # Check if Zoom app already exists
    existing_response = requests.get(f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/?slug=zoom-video-conferencing", headers=headers)
    if existing_response.status_code == 200 and existing_response.json().get('results'):
        print("Zoom app already exists, skipping...")
        return
    
    # Create app data
    app_data = {
        'name': 'Zoom - Video Conferencing',
        'slug': 'zoom-video-conferencing',
        'launch_url': 'https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIXOG62NLHB6A8QJBSVB/sso',
        'open_in_new_tab': True,
        'meta_launch_url': 'https://sso-8090a1e6.sso.duosecurity.com/saml2/sp/DIXOG62NLHB6A8QJBSVB/sso',
        'meta_description': f'Migrated from Duo SSO. Square logo available at: {square_logo_path}',
        'meta_publisher': 'Duo Migration',
        'policy_engine_mode': 'any',
        'group': '',
        'meta_icon': data_url
    }
    
    try:
        response = requests.post(
            f"{AUTHENTIK_BASE_URL}/api/v3/core/applications/",
            headers=headers,
            json=app_data
        )
        
        print(f"Create Zoom response: {response.status_code}")
        if response.status_code == 201:
            print("✅ Successfully created Zoom with square logo!")
            result = response.json()
            print(f"PK: {result['pk']}")
            print(f"Square logo file: {square_logo_path}")
            if result.get('meta_icon'):
                print("✅ Logo successfully embedded!")
            else:
                print("❌ No logo in result")
        else:
            print(f"❌ Failed: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    create_zoom_app()