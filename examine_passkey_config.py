#!/usr/bin/env python3
"""
Examine the passkey app and flow configuration in Authentik
"""

import requests
import json
from pprint import pprint

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

def find_passkey_application():
    """Find applications related to passkey"""
    print("🔍 Searching for passkey-related applications...")
    
    response = authentik_request('GET', '/api/v3/core/applications/')
    
    if response.status_code == 200:
        apps = response.json().get('results', [])
        print(f"✅ Found {len(apps)} total applications")
        
        passkey_apps = []
        
        for app in apps:
            name = app.get('name', '').lower()
            slug = app.get('slug', '').lower()
            
            if 'passkey' in name or 'passkey' in slug:
                passkey_apps.append(app)
                print(f"\n📱 Found passkey app: {app.get('name')}")
                print(f"   Slug: {app.get('slug')}")
                print(f"   UUID: {app.get('pk')}")
                print(f"   Provider: {app.get('provider')}")
                print(f"   Authorization Flow: {app.get('authorization_flow')}")
                print(f"   Authentication Flow: {app.get('authentication_flow')}")
        
        if not passkey_apps:
            print("❌ No passkey applications found")
            print("\n📋 All applications:")
            for app in apps:
                print(f"   - {app.get('name')} (slug: {app.get('slug')})")
        
        return passkey_apps
    else:
        print(f"❌ Failed to get applications: {response.status_code}")
        print(f"   Response: {response.text}")
        return []

def examine_authentication_flows():
    """Examine authentication flows"""
    print(f"\n🔄 Examining authentication flows...")
    
    response = authentik_request('GET', '/api/v3/flows/instances/')
    
    if response.status_code == 200:
        flows = response.json().get('results', [])
        print(f"✅ Found {len(flows)} flows")
        
        auth_flows = []
        
        for flow in flows:
            designation = flow.get('designation', '')
            title = flow.get('title', '')
            slug = flow.get('slug', '')
            
            # Look for authentication flows or passkey-related flows
            if designation == 'authentication' or 'passkey' in title.lower() or 'passkey' in slug.lower():
                auth_flows.append(flow)
                print(f"\n🔄 Authentication flow: {title}")
                print(f"   Slug: {slug}")
                print(f"   UUID: {flow.get('pk')}")
                print(f"   Designation: {designation}")
                print(f"   Policy Engine Mode: {flow.get('policy_engine_mode')}")
                print(f"   Compatibility Mode: {flow.get('compatibility_mode')}")
        
        return auth_flows
    else:
        print(f"❌ Failed to get flows: {response.status_code}")
        return []

def examine_flow_stages(flow_uuid):
    """Examine the stages in a specific flow"""
    print(f"\n🎭 Examining stages for flow {flow_uuid}...")
    
    response = authentik_request('GET', f'/api/v3/flows/bindings/?target={flow_uuid}')
    
    if response.status_code == 200:
        bindings = response.json().get('results', [])
        print(f"✅ Found {len(bindings)} stage bindings")
        
        for binding in sorted(bindings, key=lambda x: x.get('order', 0)):
            stage_uuid = binding.get('stage')
            order = binding.get('order', 0)
            evaluate_on_plan = binding.get('evaluate_on_plan', False)
            re_evaluate_policies = binding.get('re_evaluate_policies', False)
            
            print(f"\n   📍 Stage {order}: {stage_uuid}")
            print(f"      Evaluate on plan: {evaluate_on_plan}")
            print(f"      Re-evaluate policies: {re_evaluate_policies}")
            
            # Get stage details
            stage_response = authentik_request('GET', f'/api/v3/stages/all/{stage_uuid}/')
            if stage_response.status_code == 200:
                stage = stage_response.json()
                stage_type = stage.get('component', 'unknown')
                stage_name = stage.get('name', 'unknown')
                
                print(f"      Stage type: {stage_type}")
                print(f"      Stage name: {stage_name}")
                
                # Show specific configuration for WebAuthn stages
                if 'webauthn' in stage_type.lower():
                    print(f"      🔐 WebAuthn Configuration:")
                    for key, value in stage.items():
                        if key not in ['pk', 'component', 'verbose_name', 'meta_model_name']:
                            print(f"         {key}: {value}")
        
        return bindings
    else:
        print(f"❌ Failed to get flow stages: {response.status_code}")
        return []

def examine_webauthn_stages():
    """Find and examine WebAuthn stages"""
    print(f"\n🔐 Searching for WebAuthn stages...")
    
    response = authentik_request('GET', '/api/v3/stages/authenticator_webauthn/')
    
    if response.status_code == 200:
        stages = response.json().get('results', [])
        print(f"✅ Found {len(stages)} WebAuthn stages")
        
        for stage in stages:
            print(f"\n🔐 WebAuthn Stage: {stage.get('name')}")
            print(f"   UUID: {stage.get('pk')}")
            print(f"   User verification: {stage.get('user_verification')}")
            print(f"   Authenticator attachment: {stage.get('authenticator_attachment')}")
            print(f"   Resident key requirement: {stage.get('resident_key_requirement')}")
            
        return stages
    else:
        print(f"❌ Failed to get WebAuthn stages: {response.status_code}")
        return []

def examine_policies():
    """Examine policies that might affect authentication"""
    print(f"\n📋 Examining policies...")
    
    response = authentik_request('GET', '/api/v3/policies/all/')
    
    if response.status_code == 200:
        policies = response.json().get('results', [])
        print(f"✅ Found {len(policies)} policies")
        
        passkey_policies = []
        
        for policy in policies:
            name = policy.get('name', '').lower()
            if 'passkey' in name or 'webauthn' in name:
                passkey_policies.append(policy)
                print(f"\n📋 Policy: {policy.get('name')}")
                print(f"   Type: {policy.get('component')}")
                print(f"   UUID: {policy.get('pk')}")
        
        return passkey_policies
    else:
        print(f"❌ Failed to get policies: {response.status_code}")
        return []

def main():
    print("🚀 Examining Passkey Configuration in Authentik")
    
    try:
        # Test API connection
        response = authentik_request('GET', '/api/v3/core/users/me/')
        if response.status_code != 200:
            print(f"❌ API test failed: {response.status_code}")
            return
        print("✅ API connection confirmed")
        
        # Find passkey applications
        passkey_apps = find_passkey_application()
        
        # Examine authentication flows
        auth_flows = examine_authentication_flows()
        
        # Examine flow stages for each authentication flow
        for flow in auth_flows:
            flow_uuid = flow.get('pk')
            examine_flow_stages(flow_uuid)
        
        # Examine WebAuthn stages specifically
        examine_webauthn_stages()
        
        # Examine policies
        examine_policies()
        
        print(f"\n📊 ANALYSIS SUMMARY:")
        print(f"   🔍 Passkey apps found: {len(passkey_apps)}")
        print(f"   🔄 Authentication flows found: {len(auth_flows)}")
        
        if passkey_apps:
            print(f"\n🎯 NEXT STEPS TO INVESTIGATE:")
            for app in passkey_apps:
                auth_flow = app.get('authentication_flow')
                if auth_flow:
                    print(f"   - Examine authentication flow {auth_flow} for app {app.get('name')}")
                else:
                    print(f"   - App {app.get('name')} has no authentication flow set")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()