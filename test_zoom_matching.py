#!/usr/bin/env python3
"""
Test if Zoom matching works now
"""

import os
import re
from pathlib import Path

LOGO_DIR = "/Users/brent/Documents/Logos"

def normalize_name(name):
    """Normalize name for fuzzy matching"""
    # Remove common words and normalize
    normalized = re.sub(r'[^a-zA-Z0-9]', '', name.lower())
    normalized = re.sub(r'(sso|app|application|test|stage|staging|stg|prod|production|videoconferencing|singlesignon)', '', normalized)
    return normalized

def find_logo_file(app_name):
    """Find logo file using fuzzy matching"""
    if not os.path.exists(LOGO_DIR):
        print(f"⚠️ Logo directory not found: {LOGO_DIR}")
        return None
    
    normalized_app = normalize_name(app_name)
    print(f"🔍 Looking for logo for '{app_name}' (normalized: '{normalized_app}')")
    
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
                print(f"   Match: {logo_file.name} -> score: {score:.2f}")
    
    if best_match and best_score > 0.3:
        print(f"✅ Found logo: {best_match.name} (score: {best_score:.2f})")
        return str(best_match)
    else:
        print(f"❌ No logo found for '{app_name}'")
        return None

# Test the problematic apps
test_apps = [
    "Zoom - Video Conferencing", 
    "AirFocus",
    "Amazon Web Services",
    "Jamf"
]

print("Testing logo matching with improved normalization:")
for app in test_apps:
    result = find_logo_file(app)
    print()

# Show what zoom files exist
print("Available logo files containing 'zoom':")
logo_files = list(Path(LOGO_DIR).glob("*zoom*"))
for f in logo_files:
    print(f"  {f.name}")