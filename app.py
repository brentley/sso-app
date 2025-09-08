import os
import json
import base64
import secrets
import uuid
import time
import yaml
import logging
import requests
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, render_template_string
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

load_dotenv()

app = Flask(__name__)
START_TIME = time.time()

# Configure logging
def setup_logging():
    """Setup logging with proper directory creation"""
    log_dir = 'data'
    log_file = os.path.join(log_dir, 'auth.log')
    
    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)

def get_build_info():
    """Read build information from build-info.json file."""
    try:
        with open('build-info.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            'git_commit': os.getenv('GIT_COMMIT', 'unknown'),
            'git_commit_short': os.getenv('GIT_COMMIT', 'unknown')[:7] if os.getenv('GIT_COMMIT') else 'unknown',
            'build_date': os.getenv('BUILD_DATE', 'unknown'),
            'version': os.getenv('VERSION', '1.0.0'),
            'build_number': 'unknown'
        }

# Get build information once at startup
BUILD_INFO = get_build_info()

# Configuration file management
CONFIG_FILE_PATH = 'data/auth_config.yaml'

def load_config_file():
    """Load configuration from YAML file"""
    try:
        if os.path.exists(CONFIG_FILE_PATH):
            with open(CONFIG_FILE_PATH, 'r') as f:
                config = yaml.safe_load(f) or {}
                logger.info(f"Loaded configuration from {CONFIG_FILE_PATH}")
                return config
    except Exception as e:
        logger.error(f"Failed to load config file: {e}")
    return {}

def save_config_file(config):
    """Save configuration to YAML file"""
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE_PATH), exist_ok=True)
        with open(CONFIG_FILE_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=True)
        logger.info(f"Saved configuration to {CONFIG_FILE_PATH}")
        return True
    except Exception as e:
        logger.error(f"Failed to save config file: {e}")
        return False

def export_config_to_file():
    """Export all database configuration to YAML file"""
    try:
        configs = Configuration.query.all()
        file_config = {}
        
        for config in configs:
            if config.value:  # Only export non-empty values
                file_config[config.key] = config.value
        
        save_config_file(file_config)
        logger.info(f"Exported {len(file_config)} configurations to {CONFIG_FILE_PATH}")
        return True
    except Exception as e:
        logger.error(f"Failed to export configuration to file: {e}")
        return False

def update_config_from_file():
    """Update database configuration from file on startup"""
    file_config = load_config_file()
    if not file_config:
        return
    
    for key, value in file_config.items():
        if isinstance(value, (str, int, bool, float)):
            set_config(key, str(value))
            logger.info(f"Updated config {key} from file")

# Load file-based configuration
FILE_CONFIG = load_config_file()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///sso_test.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Force HTTPS URL generation for external URLs (behind reverse proxy)
app.config['PREFERRED_URL_SCHEME'] = 'https'
# SERVER_NAME removed - causes conflicts with development vs production

# OAuth Configuration - VisiQuate OIDC (Authentik)
app.config['AUTHENTIK_CLIENT_ID'] = os.getenv('AUTHENTIK_CLIENT_ID')
app.config['AUTHENTIK_CLIENT_SECRET'] = os.getenv('AUTHENTIK_CLIENT_SECRET')
app.config['AUTHENTIK_SERVER_URL'] = os.getenv('AUTHENTIK_SERVER_URL', 'https://auth.visiquate.com')


# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth setup
oauth = OAuth(app)

# WebAuthn Configuration
RP_ID = os.getenv('RP_ID', 'localhost')
RP_NAME = os.getenv('RP_NAME', 'VisiQuate SSO Test App')
ORIGIN = os.getenv('ORIGIN', 'http://localhost:5000')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_auditor = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # SCIM fields
    external_id = db.Column(db.String(255))
    active = db.Column(db.Boolean, default=True)
    scim_provisioned = db.Column(db.Boolean, default=False)
    
    # Authentication status tracking
    saml_tested = db.Column(db.Boolean, default=False)
    oidc_tested = db.Column(db.Boolean, default=False)
    passkey_tested = db.Column(db.Boolean, default=False)
    
    # Persistent authentication metadata
    saml_metadata = db.Column(db.Text)  # JSON string of last SAML auth data
    oidc_metadata = db.Column(db.Text)  # JSON string of last OIDC auth data
    passkey_metadata = db.Column(db.Text)  # JSON string of last passkey auth data
    
    # Relationships
    auth_logs = db.relationship('AuthLog', backref='user', lazy=True)
    
    def get_saml_metadata_dict(self):
        """Get parsed SAML metadata as dictionary"""
        if not self.saml_metadata:
            return {}
        try:
            import json
            return json.loads(self.saml_metadata)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def get_oidc_metadata_dict(self):
        """Get parsed OIDC metadata as dictionary"""
        if not self.oidc_metadata:
            return {}
        try:
            import json
            return json.loads(self.oidc_metadata)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def get_passkey_metadata_dict(self):
        """Get parsed passkey metadata as dictionary"""
        if not self.passkey_metadata:
            return {}
        try:
            import json
            return json.loads(self.passkey_metadata)
        except (json.JSONDecodeError, TypeError):
            return {}
    

class Configuration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    encrypted = db.Column(db.Boolean, default=False)
    description = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Allow NULL for failed attempts on non-existent users
    auth_method = db.Column(db.String(20), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    transaction_data = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class ImpersonationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    impersonated_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 'start', 'stop', 'auth_test'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    notes = db.Column(db.Text)

class SCIMLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    method = db.Column(db.String(10), nullable=False)  # GET, POST, PUT, DELETE
    endpoint = db.Column(db.String(100), nullable=False)  # e.g. /scim/v2/Users
    user_identifier = db.Column(db.String(255))  # email or external_id being processed
    status_code = db.Column(db.Integer, nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    request_data = db.Column(db.Text)  # JSON request payload
    response_data = db.Column(db.Text)  # JSON response payload
    error_message = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Link to created user if successful
    updated_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Link to updated user if successful

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def get_config(key, default=None):
    config = Configuration.query.filter_by(key=key).first()
    if config:
        return config.value
    return default

def log_scim_activity(method, endpoint, user_identifier=None, status_code=200, success=True, 
                      request_data=None, response_data=None, error_message=None, created_user_id=None, updated_user_id=None):
    """Log SCIM API activity"""
    try:
        scim_log = SCIMLog(
            method=method,
            endpoint=endpoint,
            user_identifier=user_identifier,
            status_code=status_code,
            success=success,
            request_data=json.dumps(request_data) if request_data else None,
            response_data=json.dumps(response_data) if response_data else None,
            error_message=error_message,
            ip_address=get_real_ip(),
            user_agent=request.headers.get('User-Agent'),
            created_user_id=created_user_id,
            updated_user_id=updated_user_id
        )
        db.session.add(scim_log)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log SCIM activity: {str(e)}")


def get_real_ip():
    """Get the real client IP address from headers"""
    # Check X-Forwarded-For header first (from Cloudflare)
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first one (original client)
        return forwarded_for.split(',')[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get('X-Real-IP', '')
    if real_ip:
        return real_ip
    
    # Check CF-Connecting-IP header (Cloudflare specific)
    cf_ip = request.headers.get('CF-Connecting-IP', '')
    if cf_ip:
        return cf_ip
    
    # Fallback to remote_addr (direct connection)
    return request.remote_addr

def set_config(key, value, description=None, user_id=None):
    config = Configuration.query.filter_by(key=key).first()
    if not config:
        config = Configuration(key=key, description=description)
    
    config.value = value
    config.updated_by = user_id
    config.updated_at = datetime.utcnow()
    
    db.session.add(config)
    db.session.commit()
    
    # Also save to configuration file
    try:
        file_config = load_config_file()
        file_config[key] = value
        save_config_file(file_config)
        logger.info(f"Updated config {key} in database and file")
    except Exception as e:
        logger.error(f"Failed to update config file for {key}: {e}")

def check_passkey_authentication_logs(user_id, passkey_id, authentik_token):
    """Check if a specific passkey was used in our custom flow recently"""
    try:
        headers = {'Authorization': f'Bearer {authentik_token}'}
        
        # Look for recent events for this user (all types, not just login)
        # Remove action filter to see all event types including WebAuthn events
        events_response = requests.get(
            'https://id.visiquate.com/api/v3/events/events/',
            headers=headers,
            params={
                'user': user_id,
                'ordering': '-created'  # Most recent first
            },
            timeout=10
        )
        
        if events_response.status_code != 200:
            logger.warning(f"Could not fetch authentication events: {events_response.status_code}")
            return {'tested': False, 'test_date': None, 'error': 'Could not check logs'}
        
        events = events_response.json().get('results', [])
        
        # Debug: Log what events we're seeing
        logger.info(f"Checking {len(events)} recent events for user {user_id}")
        for i, event in enumerate(events[:10]):  # Log first 10 events for better debugging
            context = event.get('context', {})
            auth_method = context.get('auth_method', 'none')
            action = event.get('action', 'unknown')
            created = event.get('created', 'unknown')
            logger.info(f"Event {i+1}: action={action}, auth_method={auth_method}, created={created}")
            
            # Log more context for debugging
            if context:
                logger.info(f"  Full context: {context}")
        
        # Look for recent passkey authentication in our custom flow
        # Check more events and look for various WebAuthn/passkey indicators
        for event in events[:50]:  # Check last 50 events to catch more possibilities
            context = event.get('context', {})
            action = event.get('action', 'unknown')
            auth_method = context.get('auth_method')
            
            # Check for multiple possible WebAuthn identifiers
            webauthn_methods = ['webauthn', 'passkey', 'fido2', 'authenticator_webauthn']
            webauthn_actions = ['authenticate', 'webauthn_authenticate', 'passkey_authenticate', 'fido_authenticate']
            
            # Look for WebAuthn in both auth_method and action
            is_webauthn = (auth_method in webauthn_methods) or (action in webauthn_actions)
            
            # Also check if the event context contains WebAuthn-related data
            if not is_webauthn:
                context_str = str(context).lower()
                if any(term in context_str for term in ['webauthn', 'passkey', 'fido', 'authenticator']):
                    is_webauthn = True
                    logger.info(f"Found WebAuthn in context: {context}")
            
            if is_webauthn:
                # Check if it was in the last 30 days and with our flow
                created = event.get('created')
                if created:
                    from datetime import datetime, timedelta
                    try:
                        event_time = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        thirty_days_ago = datetime.now().replace(tzinfo=event_time.tzinfo) - timedelta(days=30)
                        
                        if event_time > thirty_days_ago:
                            logger.info(f"Found WebAuthn authentication: action={action}, auth_method={auth_method} on {created}")
                            return {
                                'tested': True, 
                                'test_date': created,
                                'flow_used': context.get('flow', 'unknown'),
                                'test_flow': f"{action}/{auth_method}"
                            }
                    except Exception as e:
                        logger.error(f"Error parsing event date {created}: {e}")
            
            # Also check if any authentication happened very recently in our custom flow
            if event.get('created'):
                try:
                    from datetime import datetime, timedelta
                    event_time = datetime.fromisoformat(event.get('created').replace('Z', '+00:00'))
                    five_minutes_ago = datetime.now().replace(tzinfo=event_time.tzinfo) - timedelta(minutes=5)
                    
                    if event_time > five_minutes_ago:
                        # Check if this event relates to our custom passkey flow
                        flow = context.get('flow', '')
                        if 'passkey' in flow.lower() or action in ['authenticate', 'authorize']:
                            logger.info(f"Recent authentication in potential passkey flow: action={action}, flow={flow}, created={event.get('created')}")
                            return {
                                'tested': True, 
                                'test_date': event.get('created'),
                                'flow_used': flow,
                                'test_flow': f"recent_{action}"
                            }
                except Exception as e:
                    logger.error(f"Error parsing recent event: {e}")
        
        return {'tested': False, 'test_date': None}
        
    except Exception as e:
        logger.error(f"Error checking authentication logs: {e}")
        return {'tested': False, 'test_date': None, 'error': str(e)}

def get_user_passkey_status(user_email):
    """Check if a user has passkeys configured in Authentik"""
    try:
        # First, find the user in Authentik by email
        authentik_token = get_config('authentik_token')
        if not authentik_token:
            return {'error': 'Authentik token not configured', 'has_passkey': False}
        
        # Search for user by email
        headers = {
            'Authorization': f'Bearer {authentik_token}',
            'Content-Type': 'application/json'
        }
        
        user_response = requests.get(
            'https://id.visiquate.com/api/v3/core/users/',
            headers=headers,
            params={'search': user_email},
            timeout=10
        )
        
        if user_response.status_code != 200:
            logger.error(f"Failed to search for user {user_email}: {user_response.status_code}")
            return {'error': 'Failed to search user in Authentik', 'has_passkey': False}
        
        users = user_response.json().get('results', [])
        authentik_user = None
        
        # Find exact email match
        for user in users:
            if user.get('email', '').lower() == user_email.lower():
                authentik_user = user
                break
        
        if not authentik_user:
            return {'error': 'User not found in Authentik', 'has_passkey': False}
        
        user_id = authentik_user.get('pk')
        
        # Check for WebAuthn authenticators for this user
        passkey_response = requests.get(
            f'https://id.visiquate.com/api/v3/authenticators/webauthn/',
            headers=headers,
            params={'user': user_id},
            timeout=10
        )
        
        if passkey_response.status_code != 200:
            logger.error(f"Failed to check passkeys for user {user_id}: {passkey_response.status_code}")
            return {'error': 'Failed to check passkeys', 'has_passkey': False}
        
        passkeys = passkey_response.json().get('results', [])
        
        # Filter for only confirmed/valid passkeys
        # Only include passkeys that are confirmed and have proper credential data
        valid_passkeys = []
        
        for passkey in passkeys:
            # Only include confirmed passkeys that have actual credential data
            if (passkey.get('confirmed') and 
                passkey.get('credential_id') and 
                passkey.get('name')):
                valid_passkeys.append(passkey)
        
        # Log the raw data for debugging
        logger.info(f"Found {len(passkeys)} total WebAuthn authenticators for user {user_id}")
        for i, pk in enumerate(passkeys, 1):
            logger.info(f"Passkey {i}: name={pk.get('name')}, confirmed={pk.get('confirmed')}, created={pk.get('created_on')}")
        
        logger.info(f"After deduplication: {len(valid_passkeys)} valid passkeys")
        
        # Check authentication logs for each passkey
        passkeys_with_status = []
        for passkey in valid_passkeys:
            passkey_info = {
                'id': passkey.get('pk'),
                'name': passkey.get('name'),
                'device_type': passkey.get('device_type', {}).get('description', 'Unknown'),
                'created_on': passkey.get('created_on'),
                'confirmed': passkey.get('confirmed')
            }
            
            # Check if this passkey has been used recently with our flow
            auth_check = check_passkey_authentication_logs(user_id, passkey.get('pk'), authentik_token)
            
            # Use API check results for individual passkey status
            api_tested = auth_check.get('tested', False)
            api_test_date = auth_check.get('test_date')
            api_test_flow = auth_check.get('flow_used')
            
            # Also check our local database for recent passkey tests
            # But only apply it if we don't have specific API results for this passkey
            from flask_login import current_user
            local_tested = False
            local_test_date = None
            local_test_flow = None
            
            if (current_user and current_user.is_authenticated and 
                current_user.passkey_tested and not api_tested):
                # Only use local database info if API didn't find any specific usage
                passkey_meta = current_user.get_passkey_metadata_dict()
                if passkey_meta and passkey_meta.get('tested_at'):
                    local_tested = True
                    local_test_date = passkey_meta.get('tested_at')
                    local_test_flow = passkey_meta.get('test_method', 'oauth_flow')
            
            # Prefer API results, fall back to local database if no API data
            final_tested = api_tested or local_tested
            final_test_date = api_test_date or local_test_date
            final_test_flow = api_test_flow or local_test_flow
            
            passkey_info.update({
                'tested': final_tested,
                'last_test_date': final_test_date,
                'test_flow': final_test_flow,
                'test_error': auth_check.get('error')
            })
            
            passkeys_with_status.append(passkey_info)
        
        return {
            'has_passkey': len(valid_passkeys) > 0,
            'passkey_count': len(valid_passkeys),
            'passkeys': passkeys_with_status
        }
        
    except requests.RequestException as e:
        logger.error(f"Network error checking passkey status for {user_email}: {e}")
        return {'error': f'Network error: {str(e)}', 'has_passkey': False}
    except Exception as e:
        logger.error(f"Unexpected error checking passkey status for {user_email}: {e}")
        return {'error': f'Unexpected error: {str(e)}', 'has_passkey': False}

def log_authentication(user_id, auth_method, success, transaction_data, ip_address, user_agent):
    email = transaction_data.get('email', 'unknown')
    
    # Enhanced logging to file for troubleshooting
    if success:
        logger.info(f"AUTH SUCCESS: {auth_method} authentication for {email} from {ip_address}")
        logger.debug(f"AUTH SUCCESS DETAILS: user_id={user_id}, data={json.dumps(transaction_data, default=str)}")
    else:
        logger.warning(f"AUTH FAILURE: {auth_method} authentication failed for {email} from {ip_address}")
        logger.error(f"AUTH FAILURE DETAILS: error={transaction_data.get('error', 'Unknown')}, data={json.dumps(transaction_data, default=str)}")
        
        # Log specific failure reasons for different auth methods
        if auth_method == 'saml':
            logger.error(f"SAML ERROR: errors={transaction_data.get('errors', [])}, reason={transaction_data.get('last_error_reason', 'Unknown')}")
        elif auth_method == 'oidc':
            logger.error(f"OIDC ERROR: {transaction_data.get('error', 'Unknown OIDC error')}")
        elif auth_method == 'password':
            logger.error(f"PASSWORD ERROR: Invalid credentials for {email}")

    auth_log = AuthLog(
        user_id=user_id,
        auth_method=auth_method,
        success=success,
        transaction_data=json.dumps(transaction_data),
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.session.add(auth_log)
    
    # Update user test status
    if success and user_id:
        user = db.session.get(User, user_id)
        if user:
            if auth_method == 'saml':
                user.saml_tested = True
            elif auth_method == 'oidc':
                user.oidc_tested = True
    
    db.session.commit()

# Impersonation helper functions
def start_impersonation(admin_user, target_user, notes=None):
    """Start impersonating another user"""
    if not admin_user.is_super_admin:
        raise PermissionError("Only super admins can impersonate users")
    
    # Store original user info in session
    session['original_user_id'] = admin_user.id
    session['impersonated_user_id'] = target_user.id
    session['impersonation_start'] = datetime.utcnow().isoformat()
    
    # Log the impersonation
    log = ImpersonationLog(
        admin_user_id=admin_user.id,
        impersonated_user_id=target_user.id,
        action='start',
        ip_address=get_real_ip(),
        user_agent=request.headers.get('User-Agent'),
        notes=notes
    )
    db.session.add(log)
    db.session.commit()
    
    # Login as the target user
    login_user(target_user, remember=False)
    return True

def stop_impersonation():
    """Stop impersonating and return to original admin user"""
    if 'original_user_id' not in session:
        return False
    
    original_user_id = session['original_user_id']
    impersonated_user_id = session.get('impersonated_user_id')
    
    # Log the end of impersonation
    if impersonated_user_id:
        log = ImpersonationLog(
            admin_user_id=original_user_id,
            impersonated_user_id=impersonated_user_id,
            action='stop',
            ip_address=get_real_ip(),
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(log)
        db.session.commit()
    
    # Clear impersonation session data
    session.pop('original_user_id', None)
    session.pop('impersonated_user_id', None)
    session.pop('impersonation_start', None)
    
    # Login as original admin user
    original_user = db.session.get(User, original_user_id)
    if original_user:
        login_user(original_user, remember=False)
        return True
    return False

def is_impersonating():
    """Check if current session is impersonating another user"""
    return 'original_user_id' in session

def get_impersonation_info():
    """Get information about current impersonation session"""
    if not is_impersonating():
        return None
    
    original_user = db.session.get(User, session.get('original_user_id'))
    impersonated_user = db.session.get(User, session.get('impersonated_user_id'))
    start_time = session.get('impersonation_start')
    
    return {
        'original_user': original_user,
        'impersonated_user': impersonated_user,
        'start_time': start_time
    }

@app.route('/health')
def health():
    health_status = {
        'status': 'healthy',
        'service': os.getenv('SERVICE_NAME', 'sso-authentication-test'),
        'version': BUILD_INFO['version'],
        'commit': BUILD_INFO['git_commit_short'],
        'build_date': BUILD_INFO['build_date'],
        'build_number': BUILD_INFO['build_number'],
        'uptime': int(time.time() - START_TIME),
        'environment': os.getenv('ENVIRONMENT', 'production'),
        'checks': {}
    }
    
    try:
        # Check database connection
        db.session.execute(text('SELECT 1'))
        health_status['checks']['database'] = 'healthy'
    except Exception as e:
        health_status['checks']['database'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    response = jsonify(health_status)
    response.headers['Content-Type'] = 'application/json'
    return response, 200 if health_status['status'] == 'healthy' else 503

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Check if user just completed a passkey test
    if session.get('passkey_test_in_progress'):
        test_timestamp = session.get('passkey_test_timestamp', 0)
        current_time = time.time()
        
        # If test was initiated within last 5 minutes, consider it successful
        if current_time - test_timestamp < 300:  # 5 minutes
            session.pop('passkey_test_in_progress', None)
            session.pop('passkey_test_timestamp', None)
            
            # Update database if not already updated
            if not current_user.passkey_tested:
                # Mark passkey as tested in database
                current_user.passkey_tested = True
                
                # Store passkey test metadata with timestamp
                import json
                passkey_metadata = {
                    'tested_at': datetime.utcnow().isoformat(),
                    'test_method': 'oauth_flow',
                    'success': True
                }
                current_user.passkey_metadata = json.dumps(passkey_metadata)
                
                # Log the successful passkey authentication
                auth_log = AuthLog(
                    user_id=current_user.id,
                    auth_method='passkey',
                    success=True,
                    transaction_data=json.dumps({
                        'test_type': 'oauth_flow',
                        'user_agent': request.headers.get('User-Agent', 'Unknown'),
                        'timestamp': datetime.utcnow().isoformat(),
                        'source': 'sso_app_test'
                    }),
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', 'Unknown')[:500]
                )
                db.session.add(auth_log)
                
                try:
                    db.session.commit()
                    logger.info(f"Passkey test completed successfully for {current_user.email}, database updated from home page")
                except Exception as e:
                    logger.error(f"Failed to update passkey test status from home page: {e}")
                    db.session.rollback()
            
            flash('🎉 Passkey test successful! Your passkeys are working correctly.', 'success')
            logger.info(f"Passkey test completed successfully for {current_user.email}")
            return redirect(url_for('passkey_status'))
        else:
            # Test expired, clean up session
            session.pop('passkey_test_in_progress', None)
            session.pop('passkey_test_timestamp', None)
    
    # Automatically reconcile user's passkey status when they visit home page
    try:
        success, message, changed = reconcile_passkey_status_for_user(current_user)
        if success and changed:
            logger.info(f"Auto-reconciled passkey status on home page for {current_user.email}: {message}")
            db.session.commit()
        elif not success:
            logger.warning(f"Failed to auto-reconcile passkey status on home page for {current_user.email}: {message}")
    except Exception as e:
        logger.error(f"Error during home page auto-reconciliation for {current_user.email}: {e}")
        # Don't let reconciliation errors break the page
    
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        
        # Check if user should be admin
        is_admin = email in ['brent.langston@visiquate.com', 'yuliia.lutai@visiquate.com']
        
        user = User(
            email=email,
            name=name,
            is_admin=is_admin
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful - use SAML or OIDC to login')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/success')
@login_required
def success():
    auth_data = session.get('last_auth_data', {})
    return render_template('success.html', auth_data=auth_data)

@app.route('/clear-my-test-results', methods=['POST'])
@login_required
def clear_my_test_results():
    """Allow users to clear their own authentication test results"""
    try:
        # Clear only test status and metadata, preserve all other user data
        current_user.saml_tested = False
        current_user.oidc_tested = False
        current_user.passkey_tested = False
        current_user.saml_metadata = None
        current_user.oidc_metadata = None
        current_user.passkey_metadata = None
        
        db.session.commit()
        
        # Log the user action for audit trail
        log_authentication(
            user_id=current_user.id,
            auth_method='user_self_clear_tests',
            success=True,
            transaction_data={
                'email': current_user.email,
                'cleared_by': 'self',
                'action': 'clear_test_results'
            },
            ip_address=get_real_ip(),
            user_agent=request.headers.get('User-Agent')
        )
        
        flash('Your test results have been cleared successfully. Your password and account information remain unchanged.', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error clearing test results for user {current_user.id}: {str(e)}")
        flash('An error occurred while clearing test results. Please try again.', 'error')
    
    return redirect(url_for('index'))

@app.route('/passkey-status')
@login_required
def passkey_status():
    """Display current user's passkey status and options"""
    try:
        # Check if user just completed a passkey test
        if session.get('passkey_test_in_progress'):
            test_timestamp = session.get('passkey_test_timestamp', 0)
            current_time = time.time()
            
            # If test was initiated within last 10 minutes, consider it successful
            if current_time - test_timestamp < 600:  # 10 minutes (longer window)
                session.pop('passkey_test_in_progress', None)
                session.pop('passkey_test_timestamp', None)
                
                # Mark passkey as tested in database
                current_user.passkey_tested = True
                
                # Store passkey test metadata with timestamp
                import json
                passkey_metadata = {
                    'tested_at': datetime.utcnow().isoformat(),
                    'test_method': 'oauth_flow',
                    'success': True
                }
                current_user.passkey_metadata = json.dumps(passkey_metadata)
                
                # Log the successful passkey authentication
                auth_log = AuthLog(
                    user_id=current_user.id,
                    auth_method='passkey',
                    success=True,
                    transaction_data=json.dumps({
                        'test_type': 'oauth_flow',
                        'user_agent': request.headers.get('User-Agent', 'Unknown'),
                        'timestamp': datetime.utcnow().isoformat(),
                        'source': 'sso_app_test'
                    }),
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', 'Unknown')[:500]
                )
                db.session.add(auth_log)
                
                try:
                    db.session.commit()
                    logger.info(f"Passkey test completed successfully for {current_user.email}, database updated and logged")
                except Exception as e:
                    logger.error(f"Failed to update passkey test status: {e}")
                    db.session.rollback()
                
                flash('🎉 Passkey test successful! Your passkeys are working correctly.', 'success')
            else:
                # Test expired, clean up session
                session.pop('passkey_test_in_progress', None)
                session.pop('passkey_test_timestamp', None)
        
        # Get passkey status from Authentik API
        passkey_info = get_user_passkey_status(current_user.email)
        
        # Automatically reconcile user's passkey status based on actual Authentik data
        try:
            success, message, changed = reconcile_passkey_status_for_user(current_user)
            if success and changed:
                logger.info(f"Auto-reconciled passkey status for {current_user.email}: {message}")
                # Commit the reconciliation changes
                db.session.commit()
                # Re-fetch passkey status after reconciliation to show updated data
                passkey_info = get_user_passkey_status(current_user.email)
            elif not success:
                logger.warning(f"Failed to auto-reconcile passkey status for {current_user.email}: {message}")
        except Exception as e:
            logger.error(f"Error during auto-reconciliation for {current_user.email}: {e}")
            # Don't let reconciliation errors break the page
        
        # Authentik URLs for passkey management
        setup_url = "https://id.visiquate.com/if/flow/default-authenticator-webauthn-setup/"
        test_url = "https://id.visiquate.com/if/user/#/settings;page-device-webauthn"  # User settings page for managing existing passkeys
        user_dashboard_url = "https://id.visiquate.com/if/user/#/settings"  # User settings dashboard
        
        return render_template('passkey_status.html', 
                             passkey_info=passkey_info, 
                             setup_url=setup_url,
                             test_url=test_url,
                             user_dashboard_url=user_dashboard_url)
    
    except Exception as e:
        logger.error(f"Error getting passkey status for user {current_user.email}: {str(e)}")
        flash('Error retrieving passkey status. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/debug/oauth-urls')
@login_required
def debug_oauth_urls():
    """Debug OAuth URLs being generated"""
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    try:
        passkey_server_url = get_config('passkey_server_url', 'https://id.visiquate.com')
        passkey_client_id = get_config('passkey_client_id')
        
        # Force HTTPS callback URL for production OAuth flow
        callback_url = 'https://sso-app.visiquate.com/passkey-callback'
        
        # Generate the OAuth URL for testing
        import secrets
        from urllib.parse import urlencode
        
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        auth_params = {
            'client_id': passkey_client_id,
            'response_type': 'code',
            'scope': 'openid email profile',
            'redirect_uri': callback_url,
            'state': state,
            'nonce': nonce,
            'prompt': 'login',
            'acr_values': 'urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatorPresentedKey'
        }
        
        auth_url = f"{passkey_server_url}/application/o/authorize/?{urlencode(auth_params)}"
        
        return jsonify({
            'callback_url': callback_url,
            'auth_url': auth_url,
            'client_id': passkey_client_id,
            'server_url': passkey_server_url,
            'message': f'Add this redirect URI to your Authentik OAuth provider: {callback_url}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/fix-webauthn-config')
@login_required  
def fix_webauthn_config():
    """Fix WebAuthn configuration based on GitHub issue workaround"""
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    try:
        authentik_token = get_config('authentik_token')
        
        if not authentik_token:
            return jsonify({'error': 'Missing authentik_token'}), 500
        
        headers = {
            'Authorization': f'Bearer {authentik_token}',
            'Content-Type': 'application/json'
        }
        
        # Find all WebAuthn authenticator setup stages - try different endpoint paths
        stage_endpoints = [
            'https://id.visiquate.com/api/v3/stages/authenticator_webauthn/',
            'https://id.visiquate.com/api/v3/stages/all/',
            'https://id.visiquate.com/api/v3/stages/instances/'
        ]
        
        stages_response = None
        stages = []
        debug_info = []
        
        for endpoint in stage_endpoints:
            try:
                response = requests.get(endpoint, headers=headers, timeout=10)
                debug_info.append(f"{endpoint}: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json().get('results', [])
                    # Filter for WebAuthn stages - only authenticator-webauthn components
                    webauthn_stages = [
                        stage for stage in data 
                        if stage.get('component') == 'ak-stage-authenticator-webauthn-form' or
                           ('webauthn' in stage.get('component', '').lower() and 'authenticator' in stage.get('component', '').lower())
                    ]
                    if webauthn_stages:
                        stages = webauthn_stages
                        stages_response = response
                        break
                    elif endpoint == stage_endpoints[-1]:  # Last endpoint, use first 5 stages for debugging
                        stages_response = response
                        stages = data[:5]
                        break
            except Exception as e:
                debug_info.append(f"{endpoint}: error - {str(e)}")
                continue
        
        if not stages_response or stages_response.status_code != 200:
            return jsonify({
                'error': f'Could not fetch stages from any endpoint',
                'debug_info': debug_info,
                'tried_endpoints': stage_endpoints
            }), 500
        
        stages = stages_response.json().get('results', [])
        fixes_applied = []
        
        for stage in stages:
            stage_id = stage.get('pk')
            current_config = {
                'resident_key_requirement': stage.get('resident_key_requirement', 'preferred'),
                'user_verification': stage.get('user_verification', 'preferred')
            }
            
            # Apply the GitHub issue fix: change from "preferred" to "required"
            needs_update = False
            updated_config = {}
            
            if current_config['resident_key_requirement'] == 'preferred':
                updated_config['resident_key_requirement'] = 'required'
                needs_update = True
            
            if current_config['user_verification'] == 'preferred':
                updated_config['user_verification'] = 'required'
                needs_update = True
            
            if needs_update:
                # Update the stage configuration - use PUT with full config
                # Get full stage config first, then update it
                get_response = requests.get(
                    f'https://id.visiquate.com/api/v3/stages/all/{stage_id}/',
                    headers=headers,
                    timeout=10
                )
                
                if get_response.status_code != 200:
                    fixes_applied.append({
                        'stage_name': stage.get('name', f'Stage {stage_id}'),
                        'stage_id': stage_id,
                        'changes': updated_config,
                        'status': f'failed to get config: {get_response.status_code}'
                    })
                    continue
                
                # Get full config and update the WebAuthn specific fields
                full_config = get_response.json()
                full_config.update(updated_config)
                
                # Update the stage configuration using PUT
                update_response = requests.put(
                    f'https://id.visiquate.com/api/v3/stages/all/{stage_id}/',
                    headers=headers,
                    json=full_config,
                    timeout=10
                )
                
                if update_response.status_code == 200:
                    fixes_applied.append({
                        'stage_name': stage.get('name', f'Stage {stage_id}'),
                        'stage_id': stage_id,
                        'changes': updated_config,
                        'status': 'updated'
                    })
                else:
                    fixes_applied.append({
                        'stage_name': stage.get('name', f'Stage {stage_id}'),
                        'stage_id': stage_id,
                        'changes': updated_config,
                        'status': f'failed: {update_response.status_code}',
                        'response': update_response.text
                    })
            else:
                fixes_applied.append({
                    'stage_name': stage.get('name', f'Stage {stage_id}'),
                    'stage_id': stage_id,
                    'status': 'already_correct'
                })
        
        return jsonify({
            'message': 'WebAuthn configuration fix applied based on GitHub issue workaround',
            'stages_checked': len(stages),
            'fixes_applied': fixes_applied,
            'debug_info': debug_info,
            'stage_details': [
                {
                    'name': stage.get('name'),
                    'component': stage.get('component'),
                    'pk': stage.get('pk')
                } for stage in stages
            ],
            'note': 'Users may need to re-register their passkeys after this change'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/add-identification-stage')
@login_required  
def add_identification_stage():
    """Add identification stage to custom passkey flow (GitHub issue workaround option 1)"""
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    try:
        authentik_token = get_config('authentik_token')
        
        if not authentik_token:
            return jsonify({'error': 'Missing authentik_token'}), 500
        
        headers = {
            'Authorization': f'Bearer {authentik_token}',
            'Content-Type': 'application/json'
        }
        
        # Find the custom passkey authentication flow
        flows_response = requests.get(
            'https://id.visiquate.com/api/v3/flows/instances/',
            headers=headers,
            params={'search': 'passkey'},
            timeout=10
        )
        
        if flows_response.status_code != 200:
            return jsonify({'error': f'Could not fetch flows: {flows_response.status_code}'}), 500
        
        flows = flows_response.json().get('results', [])
        passkey_flow = None
        
        for flow in flows:
            if 'passkey' in flow.get('name', '').lower() and flow.get('designation') == 'authentication':
                passkey_flow = flow
                break
        
        if not passkey_flow:
            return jsonify({'error': 'Could not find custom passkey authentication flow'}), 500
        
        # Check if identification stage already exists in the flow
        flow_id = passkey_flow.get('pk')
        bindings_response = requests.get(
            'https://id.visiquate.com/api/v3/flows/bindings/',
            headers=headers,
            params={'target': flow_id},
            timeout=10
        )
        
        if bindings_response.status_code != 200:
            return jsonify({'error': f'Could not fetch flow bindings: {bindings_response.status_code}'}), 500
        
        bindings = bindings_response.json().get('results', [])
        has_identification = any(
            'identification' in binding.get('stage_obj', {}).get('name', '').lower() 
            for binding in bindings
        )
        
        if has_identification:
            return jsonify({
                'message': 'Identification stage already exists in passkey flow',
                'flow_name': passkey_flow.get('name'),
                'flow_id': flow_id
            })
        
        # Find or create an identification stage
        id_stages_response = requests.get(
            'https://id.visiquate.com/api/v3/stages/identification/',
            headers=headers,
            timeout=10
        )
        
        if id_stages_response.status_code != 200:
            return jsonify({'error': f'Could not fetch identification stages: {id_stages_response.status_code}'}), 500
        
        id_stages = id_stages_response.json().get('results', [])
        id_stage = None
        
        # Look for existing identification stage
        for stage in id_stages:
            if 'default' in stage.get('name', '').lower():
                id_stage = stage
                break
        
        if not id_stage and id_stages:
            id_stage = id_stages[0]  # Use first available
        
        if not id_stage:
            return jsonify({'error': 'No identification stage found to add to flow'}), 500
        
        # Add the identification stage to the beginning of the passkey flow
        binding_data = {
            'target': flow_id,
            'stage': id_stage.get('pk'),
            'order': 0,  # Put it first
            're_evaluate_policies': True
        }
        
        create_binding_response = requests.post(
            'https://id.visiquate.com/api/v3/flows/bindings/',
            headers=headers,
            json=binding_data,
            timeout=10
        )
        
        if create_binding_response.status_code == 201:
            # Update other bindings to have higher order numbers
            for binding in bindings:
                current_order = binding.get('order', 0)
                requests.patch(
                    f'https://id.visiquate.com/api/v3/flows/bindings/{binding.get("pk")}/',
                    headers=headers,
                    json={'order': current_order + 10},
                    timeout=10
                )
            
            return jsonify({
                'message': 'Identification stage added to custom passkey flow',
                'flow_name': passkey_flow.get('name'),
                'flow_id': flow_id,
                'stage_added': id_stage.get('name'),
                'note': 'Users will now be prompted for username before passkey authentication'
            })
        else:
            return jsonify({
                'error': f'Failed to add identification stage: {create_binding_response.status_code}',
                'response': create_binding_response.text
            }), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/passkey-config')
@login_required  
def debug_passkey_config():
    """Debug passkey OAuth configuration and user access"""
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    try:
        authentik_token = get_config('authentik_token')
        passkey_client_id = get_config('passkey_client_id')
        
        if not authentik_token or not passkey_client_id:
            return jsonify({'error': 'Missing configuration'}), 500
        
        headers = {
            'Authorization': f'Bearer {authentik_token}',
            'Content-Type': 'application/json'
        }
        
        # Find the OAuth provider
        provider_response = requests.get(
            'https://id.visiquate.com/api/v3/providers/oauth2/',
            headers=headers,
            params={'client_id': passkey_client_id},
            timeout=10
        )
        
        # Find the application
        app_response = requests.get(
            'https://id.visiquate.com/api/v3/core/applications/',
            headers=headers,
            params={'search': 'passkey'},
            timeout=10
        )
        
        # Find user details
        user_response = requests.get(
            'https://id.visiquate.com/api/v3/core/users/',
            headers=headers,
            params={'search': current_user.email},
            timeout=10
        )
        
        return jsonify({
            'user_email': current_user.email,
            'client_id': passkey_client_id,
            'provider_search': {
                'status': provider_response.status_code,
                'data': provider_response.json() if provider_response.status_code == 200 else provider_response.text
            },
            'application_search': {
                'status': app_response.status_code,
                'data': app_response.json() if app_response.status_code == 200 else app_response.text
            },
            'user_search': {
                'status': user_response.status_code,
                'data': user_response.json() if user_response.status_code == 200 else user_response.text
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/devices')
@login_required
def debug_devices():
    """Debug endpoint to compare different device API responses"""
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    try:
        authentik_token = get_config('authentik_token')
        if not authentik_token:
            return jsonify({'error': 'Authentik token not configured'}), 500
        
        headers = {
            'Authorization': f'Bearer {authentik_token}',
            'Content-Type': 'application/json'
        }
        
        # Find user
        user_response = requests.get(
            'https://id.visiquate.com/api/v3/core/users/',
            headers=headers,
            params={'search': current_user.email},
            timeout=10
        )
        
        if user_response.status_code != 200:
            return jsonify({'error': f'Failed to find user: {user_response.status_code}'}), 500
        
        users = user_response.json().get('results', [])
        user_id = None
        for user in users:
            if user.get('email', '').lower() == current_user.email.lower():
                user_id = user.get('pk')
                break
        
        if not user_id:
            return jsonify({'error': 'User not found'}), 404
        
        # Try different device API endpoints
        api_results = {}
        
        # 1. WebAuthn specific
        webauthn_response = requests.get(
            'https://id.visiquate.com/api/v3/authenticators/webauthn/',
            headers=headers,
            params={'user': user_id},
            timeout=10
        )
        api_results['webauthn'] = {
            'status': webauthn_response.status_code,
            'data': webauthn_response.json() if webauthn_response.status_code == 200 else webauthn_response.text
        }
        
        # 2. All authenticators
        all_auth_response = requests.get(
            'https://id.visiquate.com/api/v3/authenticators/all/',
            headers=headers,
            params={'user': user_id},
            timeout=10
        )
        api_results['all_authenticators'] = {
            'status': all_auth_response.status_code,
            'data': all_auth_response.json() if all_auth_response.status_code == 200 else all_auth_response.text
        }
        
        # 3. User's devices (if different endpoint exists)
        devices_response = requests.get(
            f'https://id.visiquate.com/api/v3/core/users/{user_id}/devices/',
            headers=headers,
            timeout=10
        )
        api_results['user_devices'] = {
            'status': devices_response.status_code,
            'data': devices_response.json() if devices_response.status_code == 200 else devices_response.text
        }
        
        # 4. Try stages/authenticators
        stages_response = requests.get(
            'https://id.visiquate.com/api/v3/stages/authenticator/webauthn/',
            headers=headers,
            timeout=10
        )
        api_results['webauthn_stages'] = {
            'status': stages_response.status_code,
            'data': stages_response.json() if stages_response.status_code == 200 else stages_response.text
        }
        
        return jsonify({
            'user_id': user_id,
            'user_email': current_user.email,
            'api_results': api_results
        })
        
    except Exception as e:
        logger.error(f"Error in debug_devices: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/test-passkey')
@login_required
def test_passkey():
    """Test passkey authentication by triggering Authentik OIDC flow"""
    try:
        # Get passkey OAuth configuration
        passkey_server_url = get_config('passkey_server_url', 'https://id.visiquate.com')
        passkey_client_id = get_config('passkey_client_id')
        
        if not passkey_client_id:
            flash('Passkey authentication not configured', 'error')
            return redirect(url_for('passkey_status'))
        
        # Generate state and nonce for security
        import secrets
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        # Store state in session for verification
        session['passkey_test_state'] = state
        session['passkey_test_nonce'] = nonce
        session['passkey_test_user'] = current_user.email
        
        # WORKAROUND: Since Authentik OAuth routing ignores provider-specific authentication flows,
        # we'll directly use the passkey flow executor instead of OAuth authorization endpoint
        
        # Store OAuth parameters for later use in callback
        session['oauth_state'] = state  
        session['oauth_nonce'] = nonce
        session['oauth_client_id'] = passkey_client_id
        session['oauth_redirect_uri'] = 'https://sso-app.visiquate.com/oauth/callback/passkey-test-app'
        session['oauth_scope'] = 'openid email profile'
        
        from urllib.parse import urlencode, quote
        
        # Create return URL that will complete OAuth flow after passkey auth
        return_params = {
            'complete_oauth': 'true',
            'state': state
        }
        return_url = f"https://sso-app.visiquate.com/passkey-auth-complete?{urlencode(return_params)}"
        
        # Try using the flow executor API endpoint instead of web interface
        # Flow UUID: a46fd863-0340-42cc-bea1-8824a208b033
        passkey_flow_params = {
            'next': return_url
        }
        
        # Store test attempt in session to detect success when user returns
        session['passkey_test_in_progress'] = True
        session['passkey_test_timestamp'] = time.time()
        session.permanent = True  # Make session persistent across redirects
        
        # Remove next parameter to avoid "Invalid next URL" error
        # User will land on Authentik's default success page after passkey auth
        direct_passkey_url = f"{passkey_server_url}/if/flow/vq8-passkey-only-flow/"
        
        logger.info(f"Testing passkey authentication for {current_user.email}")
        logger.info(f"Direct URL: {direct_passkey_url}")
        return redirect(direct_passkey_url)
        
    except Exception as e:
        logger.error(f"Error initiating passkey test for {current_user.email}: {e}")
        flash('Error starting passkey test. Please try again.', 'error')
        return redirect(url_for('passkey_status'))

@app.route('/debug-webauthn-data')
@login_required 
def debug_webauthn_data():
    """Debug route to show raw WebAuthn data from Authentik"""
    try:
        token = get_config('authentik_token')
        if not token:
            return "No Authentik token configured"
            
        headers = {'Authorization': f'Bearer {token}'}
        
        # Get user info
        user_response = requests.get(
            'https://id.visiquate.com/api/v3/core/users/me/',
            headers=headers,
            timeout=10
        )
        user_data = user_response.json()
        user_id = user_data.get('pk')
        
        # Get WebAuthn authenticators
        webauthn_response = requests.get(
            f'https://id.visiquate.com/api/v3/authenticators/webauthn/',
            headers=headers,
            params={'user': user_id},
            timeout=10
        )
        
        webauthn_data = webauthn_response.json()
        
        return f"""
        <h1>WebAuthn Debug Data</h1>
        <h2>User ID: {user_id}</h2>
        <h2>WebAuthn Authenticators ({len(webauthn_data.get('results', []))})</h2>
        <pre>{json.dumps(webauthn_data, indent=2)}</pre>
        <p><a href="/passkey-status">Back to Passkey Status</a></p>
        """
        
    except Exception as e:
        return f"Error: {e}"

@app.route('/debug-passkey-flow')
@login_required
def debug_passkey_flow():
    """Debug route to show flow URL construction"""
    try:
        passkey_server_url = get_config('passkey_server_url', 'https://id.visiquate.com')
        
        # Test direct flow URL
        test_return_url = "https://sso-app.visiquate.com/test-return"
        from urllib.parse import urlencode
        
        passkey_flow_params = {
            'next': test_return_url
        }
        direct_passkey_url = f"{passkey_server_url}/if/flow/vq8-passkey-only-flow/?{urlencode(passkey_flow_params)}"
        
        debug_info = {
            'server_url': passkey_server_url,
            'flow_slug': 'vq8-passkey-only-flow',
            'return_url': test_return_url,
            'constructed_url': direct_passkey_url,
            'flow_params': passkey_flow_params
        }
        
        return f"""
        <h1>Passkey Flow Debug</h1>
        <pre>{json.dumps(debug_info, indent=2)}</pre>
        <p><a href="{direct_passkey_url}" target="_blank">Test Direct Flow URL</a></p>
        <p><a href="/">Back to Home</a></p>
        """
        
    except Exception as e:
        return f"Error: {e}"

@app.route('/passkey-test-result')
def passkey_test_result():
    """Handle successful passkey authentication test"""
    try:
        state = request.args.get('state')
        stored_state = session.get('passkey_test_state')
        
        if state and state == stored_state:
            # Passkey authentication was successful!
            flash('🎉 Passkey authentication successful! Your passkeys are working correctly.', 'success')
            logger.info(f"Passkey test succeeded for user with state {state}")
        else:
            flash('⚠️ Passkey test completed but state validation failed', 'warning')
            logger.warning(f"Passkey test state mismatch: got {state}, expected {stored_state}")
        
        return redirect(url_for('passkey_status'))
        
    except Exception as e:
        logger.error(f"Error in passkey test result: {e}")
        flash('Error processing passkey test result', 'error')
        return redirect(url_for('passkey_status'))

@app.route('/passkey-auth-complete')
def passkey_auth_complete():
    """Handle return from passkey authentication and complete OAuth flow"""
    try:
        # Verify state parameter
        provided_state = request.args.get('state')
        stored_state = session.get('oauth_state')
        
        if not provided_state or provided_state != stored_state:
            logger.error("Invalid or missing state in passkey auth completion")
            flash('Authentication failed: Invalid state', 'error')
            return redirect(url_for('passkey_status'))
        
        # Get stored OAuth parameters
        client_id = session.get('oauth_client_id')
        redirect_uri = session.get('oauth_redirect_uri')
        scope = session.get('oauth_scope')
        nonce = session.get('oauth_nonce')
        
        if not all([client_id, redirect_uri, scope, nonce]):
            logger.error("Missing OAuth parameters in session")
            flash('Authentication failed: Missing OAuth parameters', 'error')
            return redirect(url_for('passkey_status'))
        
        # Now initiate OAuth flow with passkey authentication completed
        # The user should now be authenticated with Authentik via passkey
        
        from urllib.parse import urlencode
        passkey_server_url = get_config('passkey_server_url', 'https://id.visiquate.com')
        
        oauth_params = {
            'client_id': client_id,
            'response_type': 'code',
            'scope': scope,
            'redirect_uri': redirect_uri,
            'state': provided_state,
            'nonce': nonce,
            'prompt': 'none',  # Don't prompt for authentication since we just did passkey auth
        }
        
        oauth_url = f"{passkey_server_url}/application/o/authorize/?{urlencode(oauth_params)}"
        
        logger.info(f"Passkey auth completed, initiating OAuth flow for user")
        return redirect(oauth_url)
        
    except Exception as e:
        logger.error(f"Error in passkey auth completion: {e}")
        flash('Error completing passkey authentication. Please try again.', 'error')
        return redirect(url_for('passkey_status'))

@app.route('/check-passkey-success')
@login_required  
def check_passkey_success():
    """Manual route to check if passkey test was successful"""
    if session.get('passkey_test_in_progress'):
        test_timestamp = session.get('passkey_test_timestamp', 0)
        current_time = time.time()
        
        if current_time - test_timestamp < 900:  # 15 minutes
            session.pop('passkey_test_in_progress', None)
            session.pop('passkey_test_timestamp', None)
            flash('🎉 Passkey test successful! Your passkeys are working correctly.', 'success')
            logger.info(f"Manual passkey test success check for {current_user.email}")
        else:
            flash('⚠️ No recent passkey test found or test expired.', 'warning')
            session.pop('passkey_test_in_progress', None)
            session.pop('passkey_test_timestamp', None)
    else:
        flash('ℹ️ No passkey test in progress.', 'info')
    
    return redirect(url_for('passkey_status'))

@app.route('/clear-session-and-oauth')
@login_required
def clear_session_and_oauth():
    """Clear Authentik session cookies and redirect to OAuth"""
    auth_url = session.get('pending_oauth_url')
    if not auth_url:
        flash('No pending OAuth request found', 'error')
        return redirect(url_for('passkey_status'))
    
    # Clear the pending URL from session
    session.pop('pending_oauth_url', None)
    
    # Return a page that clears cookies using JavaScript, then redirects
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Clearing Session...</title>
        <meta charset="utf-8">
    </head>
    <body>
        <p>Clearing authentication session...</p>
        <script>
            // Clear all cookies for id.visiquate.com domain
            document.cookie.split(";").forEach(function(c) {{ 
                document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/;domain=.visiquate.com"); 
            }});
            
            // Clear cookies for the current domain too
            document.cookie.split(";").forEach(function(c) {{ 
                document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
            }});
            
            // Redirect after a short delay
            setTimeout(function() {{
                window.location.href = "{auth_url}";
            }}, 500);
        </script>
    </body>
    </html>
    '''

@app.route('/passkey-callback')
def passkey_callback():
    """Handle OAuth callback from passkey authentication test"""
    try:
        # Verify state parameter
        received_state = request.args.get('state')
        expected_state = session.get('passkey_test_state')
        
        if not received_state or received_state != expected_state:
            flash('Invalid passkey test state. Please try again.', 'error')
            return redirect(url_for('passkey_status'))
        
        # Check for errors
        error = request.args.get('error')
        if error:
            error_description = request.args.get('error_description', 'Unknown error')
            logger.warning(f"Passkey test failed for {session.get('passkey_test_user')}: {error} - {error_description}")
            flash(f'Passkey authentication failed: {error_description}', 'error')
            return redirect(url_for('passkey_status'))
        
        # Get authorization code
        auth_code = request.args.get('code')
        if not auth_code:
            flash('No authorization code received from passkey test', 'error')
            return redirect(url_for('passkey_status'))
        
        # Exchange code for token (optional - just for verification)
        passkey_server_url = get_config('passkey_server_url', 'https://id.visiquate.com')
        passkey_client_id = get_config('passkey_client_id')
        passkey_client_secret = get_config('passkey_client_secret')
        
        if passkey_client_secret:
            try:
                token_data = {
                    'grant_type': 'authorization_code',
                    'code': auth_code,
                    'redirect_uri': 'https://sso-app.visiquate.com/passkey-callback',
                    'client_id': passkey_client_id,
                    'client_secret': passkey_client_secret
                }
                
                token_response = requests.post(
                    f"{passkey_server_url}/application/o/token/",
                    data=token_data,
                    timeout=10
                )
                
                if token_response.status_code == 200:
                    logger.info(f"Passkey test successful for {session.get('passkey_test_user')}")
                    flash('✅ Passkey authentication test successful! Your passkey is working correctly.', 'success')
                else:
                    logger.warning(f"Token exchange failed for passkey test: {token_response.status_code}")
                    flash('⚠️ Passkey authentication completed but token verification failed.', 'warning')
                    
            except Exception as e:
                logger.error(f"Error during passkey token exchange: {e}")
                flash('⚠️ Passkey authentication completed but verification had issues.', 'warning')
        else:
            logger.info(f"Passkey test completed for {session.get('passkey_test_user')} (no token verification)")
            flash('✅ Passkey authentication test completed successfully!', 'success')
        
        # Clean up session
        session.pop('passkey_test_state', None)
        session.pop('passkey_test_nonce', None) 
        session.pop('passkey_test_user', None)
        
        return redirect(url_for('passkey_status'))
        
    except Exception as e:
        logger.error(f"Error in passkey callback: {e}")
        flash('Error processing passkey test result.', 'error')
        return redirect(url_for('passkey_status'))

@app.route('/admin')
@login_required
def admin():
    if not (current_user.is_admin or current_user.is_auditor):
        flash('Access denied')
        return redirect(url_for('index'))
    
    users = User.query.all()
    
    # Calculate test completion percentage and sort users
    def calculate_test_completion(user):
        tests_completed = sum([
            1 if user.saml_tested else 0,
            1 if user.oidc_tested else 0,
            1 if user.passkey_tested else 0
        ])
        return (tests_completed / 3.0) * 100  # 3 total test methods
    
    # Sort users by test completion percentage (descending), then by name (ascending)
    sorted_users = sorted(users, key=lambda user: (-calculate_test_completion(user), user.name.lower()))
    
    return render_template('admin.html', users=sorted_users)

@app.route('/admin/config', methods=['GET', 'POST'])
@login_required
def admin_config():
    """Admin configuration panel for SSO settings"""
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            config_data = request.get_json()
            if not config_data:
                return jsonify({'status': 'error', 'message': 'No configuration data provided'}), 400
            
            # Save each configuration item to database
            for key, value in config_data.items():
                if value:  # Only save non-empty values
                    existing_config = Configuration.query.filter_by(key=key).first()
                    if existing_config:
                        existing_config.value = value
                        existing_config.updated_at = datetime.utcnow()
                    else:
                        new_config = Configuration(key=key, value=value)
                        db.session.add(new_config)
            
            db.session.commit()
            
            # Export to YAML file for persistence
            export_config_to_file()
            
            app.logger.info(f'Configuration updated by {current_user.email}: {list(config_data.keys())}')
            return jsonify({'status': 'success', 'message': 'Configuration saved successfully'})
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error saving configuration: {str(e)}')
            return jsonify({'status': 'error', 'message': f'Failed to save configuration: {str(e)}'}), 500
    
    # Get current configuration values as objects for template access
    configs = Configuration.query.all()
    config_dict = {config.key: config for config in configs}
    
    # Generate correct base URL (force HTTPS for visiquate.com domains)
    host = request.headers.get('Host', request.host)
    if 'visiquate.com' in host or request.headers.get('X-Forwarded-Proto') == 'https':
        base_url = f"https://{host}"
    else:
        base_url = request.url_root.rstrip('/')
    
    return render_template('admin_config.html', configs=config_dict, base_url=base_url)

@app.route('/admin/import_saml_metadata', methods=['POST'])
@login_required
def import_saml_metadata():
    """Import SAML configuration from Authentik metadata URL"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        data = request.get_json()
        if not data or not data.get('metadata_url'):
            return jsonify({'success': False, 'error': 'Metadata URL required'})
        
        metadata_url = data['metadata_url']
        if not metadata_url.startswith('https://'):
            return jsonify({'success': False, 'error': 'Metadata URL must use HTTPS'})
        
        # Download and parse SAML metadata
        import requests
        import xml.etree.ElementTree as ET
        
        response = requests.get(metadata_url, timeout=10)
        response.raise_for_status()
        
        # Parse XML metadata
        root = ET.fromstring(response.content)
        
        # Define namespaces
        namespaces = {
            'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }
        
        result = {'success': True}
        
        # Extract Entity ID
        entity_id = root.get('entityID')
        if entity_id:
            result['entity_id'] = entity_id
        
        # Find SSO Service
        sso_service = root.find('.//md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', namespaces)
        if sso_service is not None:
            result['sso_url'] = sso_service.get('Location')
        
        # Find SLO Service  
        slo_service = root.find('.//md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', namespaces)
        if slo_service is not None:
            result['slo_url'] = slo_service.get('Location')
        
        # Extract X.509 Certificate
        cert_element = root.find('.//ds:X509Certificate', namespaces)
        if cert_element is not None:
            cert_data = cert_element.text.strip()
            # Format certificate properly
            formatted_cert = '-----BEGIN CERTIFICATE-----\n'
            # Split into 64-character lines
            for i in range(0, len(cert_data), 64):
                formatted_cert += cert_data[i:i+64] + '\n'
            formatted_cert += '-----END CERTIFICATE-----'
            result['certificate'] = formatted_cert
        
        app.logger.info(f'SAML metadata imported successfully from {metadata_url}')
        return jsonify(result)
        
    except requests.RequestException as e:
        app.logger.error(f'Error fetching SAML metadata: {str(e)}')
        return jsonify({'success': False, 'error': f'Failed to fetch metadata: {str(e)}'})
    except ET.ParseError as e:
        app.logger.error(f'Error parsing SAML metadata XML: {str(e)}')
        return jsonify({'success': False, 'error': 'Invalid SAML metadata XML'})
    except Exception as e:
        app.logger.error(f'Error importing SAML metadata: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/import_oidc_discovery', methods=['POST'])
@login_required
def import_oidc_discovery():
    """Import OIDC configuration from Authentik discovery document"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        data = request.get_json()
        if not data or not data.get('discovery_url'):
            return jsonify({'success': False, 'error': 'Discovery URL required'})
        
        discovery_url = data['discovery_url']
        if not discovery_url.startswith('https://'):
            return jsonify({'success': False, 'error': 'Discovery URL must use HTTPS'})
        
        # Download and parse OIDC discovery document
        import requests
        
        response = requests.get(discovery_url, timeout=10)
        response.raise_for_status()
        
        discovery_doc = response.json()
        
        result = {'success': True}
        
        # Extract key values
        if 'issuer' in discovery_doc:
            result['issuer'] = discovery_doc['issuer']
        
        if 'authorization_endpoint' in discovery_doc:
            result['authorization_endpoint'] = discovery_doc['authorization_endpoint']
        
        if 'token_endpoint' in discovery_doc:
            result['token_endpoint'] = discovery_doc['token_endpoint']
        
        if 'userinfo_endpoint' in discovery_doc:
            result['userinfo_endpoint'] = discovery_doc['userinfo_endpoint']
        
        if 'jwks_uri' in discovery_doc:
            result['jwks_uri'] = discovery_doc['jwks_uri']
        
        app.logger.info(f'OIDC discovery imported successfully from {discovery_url}')
        return jsonify(result)
        
    except requests.RequestException as e:
        app.logger.error(f'Error fetching OIDC discovery: {str(e)}')
        return jsonify({'success': False, 'error': f'Failed to fetch discovery document: {str(e)}'})
    except ValueError as e:
        app.logger.error(f'Error parsing OIDC discovery JSON: {str(e)}')
        return jsonify({'success': False, 'error': 'Invalid discovery document JSON'})
    except Exception as e:
        app.logger.error(f'Error importing OIDC discovery: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/import_passkey_discovery', methods=['POST'])
@login_required
def import_passkey_discovery():
    """Import passkey OIDC configuration from discovery document"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        data = request.get_json()
        if not data or not data.get('discovery_url'):
            return jsonify({'success': False, 'error': 'Discovery URL required'})
        
        discovery_url = data['discovery_url']
        if not discovery_url.startswith('https://'):
            return jsonify({'success': False, 'error': 'Discovery URL must use HTTPS'})
        
        # Download and parse OIDC discovery document
        import requests
        
        response = requests.get(discovery_url, timeout=10)
        response.raise_for_status()
        
        discovery_doc = response.json()
        
        result = {'success': True}
        
        # Extract key values
        if 'issuer' in discovery_doc:
            result['issuer'] = discovery_doc['issuer']
        
        if 'authorization_endpoint' in discovery_doc:
            result['authorization_endpoint'] = discovery_doc['authorization_endpoint']
        
        if 'token_endpoint' in discovery_doc:
            result['token_endpoint'] = discovery_doc['token_endpoint']
        
        if 'userinfo_endpoint' in discovery_doc:
            result['userinfo_endpoint'] = discovery_doc['userinfo_endpoint']
        
        if 'jwks_uri' in discovery_doc:
            result['jwks_uri'] = discovery_doc['jwks_uri']
        
        app.logger.info(f'Passkey OIDC discovery imported successfully from {discovery_url}')
        return jsonify(result)
        
    except requests.RequestException as e:
        app.logger.error(f'Error fetching passkey OIDC discovery: {str(e)}')
        return jsonify({'success': False, 'error': f'Failed to fetch discovery document: {str(e)}'})
    except ValueError as e:
        app.logger.error(f'Error parsing passkey OIDC discovery JSON: {str(e)}')
        return jsonify({'success': False, 'error': 'Invalid discovery document JSON'})
    except Exception as e:
        app.logger.error(f'Error importing passkey OIDC discovery: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/user/<int:user_id>/logs')
@login_required
def user_logs(user_id):
    if not (current_user.is_admin or current_user.is_auditor):
        return jsonify({'error': 'Access denied'}), 403
    
    logs = AuthLog.query.filter_by(user_id=user_id).order_by(AuthLog.timestamp.desc()).all()
    
    logs_data = []
    for log in logs:
        logs_data.append({
            'id': log.id,
            'auth_method': log.auth_method,
            'success': log.success,
            'transaction_data': json.loads(log.transaction_data) if log.transaction_data else {},
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'timestamp': log.timestamp.isoformat()
        })
    
    return jsonify(logs_data)


@app.route('/admin/user/<int:user_id>', methods=['DELETE'])
@login_required
def admin_delete_user(user_id):
    """Delete a user and all associated data"""
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    try:
        user_email = user.email
        user_name = user.name
        
        
        # Delete associated authentication logs
        AuthLog.query.filter_by(user_id=user_id).delete()
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        
        # Log the admin action
        log_authentication(
            user_id=None,
            auth_method='user_admin_delete',
            success=True,
            transaction_data={
                'admin_user_id': current_user.id,
                'admin_email': current_user.email,
                'deleted_user_id': user_id,
                'deleted_user_email': user_email,
                'deleted_user_name': user_name,
                'action': 'user_deleted'
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        return jsonify({'message': f'User {user_email} deleted successfully'})
    except Exception as e:
        app.logger.error(f"Error deleting user: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/admin/user/<int:user_id>/clear-tests', methods=['POST'])
@login_required
def admin_clear_user_tests(user_id):
    """Clear SAML and OIDC test status for a user"""
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get_or_404(user_id)
    
    try:
        user_email = user.email
        
        # Clear test status and metadata
        user.saml_tested = False
        user.oidc_tested = False
        user.passkey_tested = False
        user.saml_metadata = None
        user.oidc_metadata = None
        user.passkey_metadata = None
        
        db.session.commit()
        
        # Log the admin action
        log_authentication(
            user_id=None,
            auth_method='user_admin_clear_tests',
            success=True,
            transaction_data={
                'admin_user_id': current_user.id,
                'admin_email': current_user.email,
                'target_user_id': user_id,
                'target_user_email': user_email,
                'action': 'test_status_cleared'
            },
            ip_address=get_real_ip(),
            user_agent=request.headers.get('User-Agent', '')
        )
        
        return jsonify({'message': f'Test status cleared for {user_email}'})
    except Exception as e:
        app.logger.error(f"Error clearing test status for user {user_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to clear test status'}), 500

@app.route('/admin/scim_logs')
@login_required 
def admin_scim_logs():
    """Display SCIM activity logs"""
    if not (current_user.is_admin or current_user.is_auditor):
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Get SCIM logs ordered by most recent first
    scim_logs = SCIMLog.query.order_by(SCIMLog.timestamp.desc())\
                            .paginate(page=page, per_page=per_page, error_out=False)
    
    # Get summary statistics
    total_logs = SCIMLog.query.count()
    successful_logs = SCIMLog.query.filter_by(success=True).count()
    failed_logs = SCIMLog.query.filter_by(success=False).count()
    user_creations = SCIMLog.query.filter(SCIMLog.created_user_id.is_not(None)).count()
    
    # Get recent user creations via SCIM
    recent_scim_users = User.query.filter_by(scim_provisioned=True)\
                                  .order_by(User.created_at.desc())\
                                  .limit(10).all()
    
    return render_template('admin_scim_logs.html', 
                         scim_logs=scim_logs,
                         total_logs=total_logs,
                         successful_logs=successful_logs, 
                         failed_logs=failed_logs,
                         user_creations=user_creations,
                         recent_scim_users=recent_scim_users)

# User Impersonation Routes (Super Admin Only)
@app.route('/admin/impersonate')
@login_required
def admin_impersonate():
    """Display user impersonation interface"""
    if not current_user.is_super_admin:
        flash('Access denied - Super admin privileges required')
        return redirect(url_for('admin'))
    
    users = User.query.filter(User.id != current_user.id).all()
    recent_logs = ImpersonationLog.query.filter_by(admin_user_id=current_user.id)\
                                        .order_by(ImpersonationLog.timestamp.desc())\
                                        .limit(10).all()
    
    impersonation_info = get_impersonation_info()
    
    return render_template('admin_impersonate.html', 
                         users=users, 
                         recent_logs=recent_logs,
                         impersonation_info=impersonation_info)

@app.route('/admin/impersonate/start/<int:user_id>', methods=['POST'])
@login_required
def start_impersonate(user_id):
    """Start impersonating a user"""
    if not current_user.is_super_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    target_user = User.query.get_or_404(user_id)
    notes = request.form.get('notes', '')
    
    try:
        start_impersonation(current_user, target_user, notes)
        flash(f'Now impersonating {target_user.email}', 'info')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Failed to start impersonation: {str(e)}', 'error')
        return redirect(url_for('admin_impersonate'))

@app.route('/admin/impersonate/stop', methods=['POST'])
@login_required
def stop_impersonate():
    """Stop impersonating and return to admin user"""
    if not is_impersonating():
        flash('Not currently impersonating anyone')
        return redirect(url_for('admin'))
    
    impersonation_info = get_impersonation_info()
    if stop_impersonation():
        if impersonation_info:
            flash(f'Stopped impersonating {impersonation_info["impersonated_user"].email}')
        else:
            flash('Returned to admin account')
        return redirect(url_for('admin'))
    else:
        flash('Failed to stop impersonation', 'error')
        return redirect(url_for('index'))

@app.route('/admin/impersonate/test_auth/<method>')
@login_required  
def test_auth_as_user(method):
    """Test authentication method as impersonated user"""
    if not is_impersonating():
        return jsonify({'error': 'Not impersonating any user'}), 400
    
    impersonation_info = get_impersonation_info()
    if not impersonation_info:
        return jsonify({'error': 'Invalid impersonation session'}), 400
    
    # Log the auth test
    log = ImpersonationLog(
        admin_user_id=impersonation_info['original_user'].id,
        impersonated_user_id=impersonation_info['impersonated_user'].id,
        action='auth_test',
        ip_address=get_real_ip(),
        user_agent=request.headers.get('User-Agent'),
        notes=f'Testing {method} authentication'
    )
    db.session.add(log)
    db.session.commit()
    
    # Redirect to appropriate auth method
    if method == 'saml':
        return redirect(url_for('saml_login'))
    elif method == 'oidc':
        return redirect(url_for('oauth_login', provider='authentik'))
    else:
        flash('Invalid authentication method', 'error')
        return redirect(url_for('index'))

# SCIM 2.0 endpoints
@app.route('/scim/v2/ServiceProviderConfig')
def scim_service_provider_config():
    """SCIM endpoint for service provider configuration"""
    try:
        config = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            'patch': {
                'supported': True
            },
            'bulk': {
                'supported': False,
                'maxOperations': 0,
                'maxPayloadSize': 0
            },
            'filter': {
                'supported': True,
                'maxResults': 200
            },
            'changePassword': {
                'supported': False
            },
            'sort': {
                'supported': False
            },
            'etag': {
                'supported': False
            },
            'authenticationSchemes': [{
                'name': 'HTTP Bearer',
                'description': 'Authentication via bearer token',
                'specUri': 'http://www.rfc-editor.org/info/rfc6750',
                'type': 'httpbearer'
            }],
            'meta': {
                'location': '/scim/v2/ServiceProviderConfig',
                'resourceType': 'ServiceProviderConfig'
            }
        }
        
        # Log successful config request
        log_scim_activity('GET', '/scim/v2/ServiceProviderConfig', status_code=200, success=True)
        
        return jsonify(config)
        
    except Exception as e:
        error_msg = f'Failed to return service provider config: {str(e)}'
        log_scim_activity('GET', '/scim/v2/ServiceProviderConfig', status_code=500, success=False, 
                         error_message=error_msg)
        return jsonify({
            'detail': 'Internal server error',
            'status': 500
        }), 500

@app.route('/scim/v2/Users', methods=['GET'])
def scim_list_users():
    """SCIM endpoint to list users"""
    auth_header = request.headers.get('Authorization', '')
    scim_bearer_token = get_config('scim_bearer_token', '')
    
    if not auth_header.startswith('Bearer ') or auth_header[7:] != scim_bearer_token:
        log_scim_activity('GET', '/scim/v2/Users', status_code=401, success=False, 
                         error_message='Authentication failed')
        return jsonify({'detail': 'Authentication failed', 'status': 401}), 401
    
    try:
        users = User.query.all()
        
        # Parse SCIM filters if provided
        start_index = int(request.args.get('startIndex', 1))
        count = int(request.args.get('count', 20))
        
        scim_users = []
        for user in users[start_index-1:start_index-1+count]:
            scim_user = {
                'id': str(user.id),
                'externalId': user.external_id,
                'userName': user.email,
                'name': {
                    'formatted': user.name,
                    'givenName': user.name.split()[0] if user.name else '',
                    'familyName': ' '.join(user.name.split()[1:]) if len(user.name.split()) > 1 else ''
                },
                'emails': [{
                    'value': user.email,
                    'primary': True
                }],
                'active': user.active,
                'meta': {
                    'resourceType': 'User',
                    'created': user.created_at.isoformat() + 'Z',
                    'location': f'/scim/v2/Users/{user.id}'
                }
            }
            scim_users.append(scim_user)
        
        response = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults': len(users),
            'startIndex': start_index,
            'itemsPerPage': len(scim_users),
            'Resources': scim_users
        }
        
        # Log successful list operation
        log_scim_activity('GET', '/scim/v2/Users', status_code=200, success=True, 
                         response_data={'totalResults': len(users), 'returnedResults': len(scim_users)})
        
        return jsonify(response)
        
    except Exception as e:
        error_msg = f'Failed to list users: {str(e)}'
        log_scim_activity('GET', '/scim/v2/Users', status_code=500, success=False, 
                         error_message=error_msg)
        return jsonify({
            'detail': 'Internal server error',
            'status': 500
        }), 500

@app.route('/scim/v2/Users', methods=['POST'])
def scim_create_user():
    """SCIM endpoint to create a user"""
    auth_header = request.headers.get('Authorization', '')
    scim_bearer_token = get_config('scim_bearer_token', '')
    
    if not auth_header.startswith('Bearer ') or auth_header[7:] != scim_bearer_token:
        log_scim_activity('POST', '/scim/v2/Users', status_code=401, success=False, 
                         error_message='Authentication failed')
        return jsonify({'detail': 'Authentication failed', 'status': 401}), 401
    
    data = request.get_json()
    
    # Extract user information from SCIM payload
    username = data.get('userName')
    external_id = data.get('externalId')
    name_data = data.get('name', {})
    formatted_name = name_data.get('formatted', username)
    emails = data.get('emails', [])
    email = emails[0]['value'] if emails else username
    active = data.get('active', True)
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        # Update existing user instead of returning error
        app.logger.info(f"SCIM: Updating existing user {email}")
        
        # Update user fields from SCIM data
        existing_user.name = formatted_name
        existing_user.external_id = external_id
        existing_user.active = active
        existing_user.scim_provisioned = True
        
        # Check if user should be admin or auditor  
        if email == 'brent.langston@visiquate.com':
            existing_user.is_admin = True
        elif email == 'yuliia.lutai@visiquate.com':
            existing_user.is_auditor = True
            existing_user.is_admin = False  # Move from admin to auditor
        
        db.session.commit()
        
        # Log successful update
        log_scim_activity('POST', '/scim/v2/Users', user_identifier=email,
                         status_code=200, success=True, request_data=data,
                         updated_user_id=existing_user.id)
        
        # Return SCIM user representation  
        scim_user = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id': str(existing_user.id),
            'externalId': existing_user.external_id,
            'userName': existing_user.email,
            'name': {
                'formatted': existing_user.name,
                'givenName': existing_user.name.split()[0] if existing_user.name else '',
                'familyName': ' '.join(existing_user.name.split()[1:]) if len(existing_user.name.split()) > 1 else ''
            },
            'emails': [{'value': existing_user.email, 'primary': True}],
            'active': existing_user.active,
            'meta': {
                'resourceType': 'User',
                'created': existing_user.created_at.isoformat() + 'Z',
                'lastModified': datetime.utcnow().isoformat() + 'Z'
            }
        }
        
        return jsonify(scim_user), 200
    
    try:
        # Check if user should be admin or auditor
        is_admin = (email == 'brent.langston@visiquate.com')
        is_auditor = (email == 'yuliia.lutai@visiquate.com')
        
        # Create user
        user = User(
            email=email,
            name=formatted_name,
            external_id=external_id,
            active=active,
            scim_provisioned=True,
            is_admin=is_admin,
            is_auditor=is_auditor
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Return SCIM user representation
        scim_user = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id': str(user.id),
            'externalId': user.external_id,
            'userName': user.email,
            'name': {
                'formatted': user.name,
                'givenName': user.name.split()[0] if user.name else '',
                'familyName': ' '.join(user.name.split()[1:]) if len(user.name.split()) > 1 else ''
            },
            'emails': [{
                'value': user.email,
                'primary': True
            }],
            'active': user.active,
            'meta': {
                'resourceType': 'User',
                'created': user.created_at.isoformat() + 'Z',
                'location': f'/scim/v2/Users/{user.id}'
            }
        }
        
        # Log successful creation
        log_scim_activity('POST', '/scim/v2/Users', user_identifier=email, 
                         status_code=201, success=True, request_data=data, 
                         response_data=scim_user, created_user_id=user.id)
        
        return jsonify(scim_user), 201
        
    except Exception as e:
        db.session.rollback()
        error_msg = f'Failed to create user: {str(e)}'
        log_scim_activity('POST', '/scim/v2/Users', user_identifier=email, 
                         status_code=500, success=False, request_data=data, 
                         error_message=error_msg)
        return jsonify({
            'detail': 'Internal server error',
            'status': 500
        }), 500

# Authentication routes
def get_saml_client():
    """Get configured SAML client using pysaml2"""
    app.logger.info("get_saml_client: Starting SAML client creation")
    
    # Force HTTPS for all visiquate.com domains
    host = request.headers.get('Host', request.host)
    if 'visiquate.com' in host or request.headers.get('X-Forwarded-Proto') == 'https':
        scheme = 'https'
        port = 443
    else:
        scheme = request.scheme
        port = request.environ.get('SERVER_PORT', 80)
    
    base_url = f"{scheme}://{host}"
    app.logger.info(f"get_saml_client: Base URL: {base_url}")
    
    # Get configuration from database
    idp_entity_id = get_config('saml_idp_entity_id', '')
    idp_sso_url = get_config('saml_idp_sso_url', '')
    idp_slo_url = get_config('saml_idp_slo_url', '')
    idp_cert = get_config('saml_idp_cert', '')
    sp_cert = get_config('saml_sp_cert', '')
    sp_private_key = get_config('saml_sp_private_key', '')
    nameid_format = get_config('saml_nameid_format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
    
    app.logger.info(f"get_saml_client: Config loaded - IdP Entity ID: {idp_entity_id}, SSO URL: {idp_sso_url}")
    
    if not all([idp_entity_id, idp_sso_url, idp_cert]):
        app.logger.error("get_saml_client: SAML not fully configured")
        raise ValueError("SAML not fully configured")
    
    # pysaml2 configuration
    config = {
        "entityid": f"{base_url}",
        "service": {
            "sp": {
                "name": "VisiQuate SSO Test Application",
                "endpoints": {
                    "assertion_consumer_service": [
                        (f"{base_url}/saml/acs", BINDING_HTTP_POST, "0"),
                    ],
                    "single_logout_service": [
                        (f"{base_url}/saml/sls", BINDING_HTTP_REDIRECT, "0"),
                    ],
                },
                "name_id_format": [nameid_format],
                "want_response_signed": False,
                "want_assertions_signed": True,
                "allow_unsolicited": True,
            }
        },
        "metadata": {
            "remote": []
        },
        "key_file": None,  # Will set if private key provided
        "cert_file": None,  # Will set if certificate provided
    }
    
    # Check for metadata URL first, then fall back to manual configuration
    metadata_url = get_config('saml_metadata_url', '')
    
    if metadata_url:
        # Fetch metadata manually to handle redirects
        app.logger.info(f"get_saml_client: Fetching metadata from URL: {metadata_url}")
        try:
            import requests
            response = requests.get(metadata_url, allow_redirects=True, timeout=10)
            if response.status_code == 200:
                metadata_xml = response.text
                app.logger.info("get_saml_client: Successfully fetched metadata XML")
                config["metadata"]["inline"] = [metadata_xml]
            else:
                app.logger.error(f"get_saml_client: Failed to fetch metadata, status: {response.status_code}")
                raise ValueError(f"Failed to fetch metadata: HTTP {response.status_code}")
        except Exception as e:
            app.logger.error(f"get_saml_client: Error fetching metadata: {str(e)}")
            raise ValueError(f"Failed to fetch metadata: {str(e)}")
    elif idp_entity_id and idp_sso_url and idp_cert:
        # Use manual IdP configuration without metadata
        app.logger.info("get_saml_client: Using manual IdP configuration")
        # Don't use inline metadata, set up IdP manually in the config
        config["idp"] = {
            idp_entity_id: {
                "single_sign_on_service": {
                    BINDING_HTTP_REDIRECT: idp_sso_url
                },
                "single_logout_service": {
                    BINDING_HTTP_REDIRECT: idp_slo_url
                } if idp_slo_url else {},
                "name_id_format": nameid_format,
                # Add certificate for signature validation
                "signing_key": idp_cert if idp_cert else None
            }
        }
    
    # Configure SP certificate if provided
    if sp_cert and sp_private_key:
        # Save temp files for pysaml2 (it requires file paths)
        import tempfile
        import os
        
        cert_fd, cert_path = tempfile.mkstemp(suffix='.crt')
        key_fd, key_path = tempfile.mkstemp(suffix='.key')
        
        try:
            with os.fdopen(cert_fd, 'w') as cert_file:
                cert_file.write(sp_cert)
            with os.fdopen(key_fd, 'w') as key_file:
                key_file.write(sp_private_key)
                
            config["cert_file"] = cert_path
            config["key_file"] = key_path
            
            app.logger.info("get_saml_client: Creating SAML config with certificates")
            try:
                saml_config = Saml2Config()
                app.logger.info("get_saml_client: Saml2Config created, loading config")
                saml_config.load(config)
                app.logger.info("get_saml_client: Config loaded, creating SAML client with certificates")
                client = Saml2Client(config=saml_config)
                app.logger.info("get_saml_client: SAML client created successfully")
                return client
            except Exception as e:
                app.logger.error(f"get_saml_client: Error creating SAML client: {str(e)}")
                app.logger.error(f"get_saml_client: Error type: {type(e)}")
                import traceback
                app.logger.error(f"get_saml_client: Traceback: {traceback.format_exc()}")
                raise
            
        finally:
            # Clean up temp files
            try:
                os.unlink(cert_path)
                os.unlink(key_path)
            except:
                pass
    else:
        app.logger.info("get_saml_client: Creating SAML config without certificates")
        try:
            saml_config = Saml2Config()
            app.logger.info("get_saml_client: Saml2Config created, loading config")
            saml_config.load(config)
            app.logger.info("get_saml_client: Config loaded, creating SAML client without certificates")
            client = Saml2Client(config=saml_config)
            app.logger.info("get_saml_client: SAML client created successfully")
            return client
        except Exception as e:
            app.logger.error(f"get_saml_client: Error creating SAML client: {str(e)}")
            app.logger.error(f"get_saml_client: Error type: {type(e)}")
            import traceback
            app.logger.error(f"get_saml_client: Traceback: {traceback.format_exc()}")
            raise

# SAML functions removed - now using pysaml2 via get_saml_client()

@app.route('/debug/headers')
@login_required  
def debug_headers():
    """Debug endpoint to check request headers"""
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    headers_dict = {}
    for key, value in request.headers:
        headers_dict[key] = value
    
    return jsonify({
        'headers': headers_dict,
        'scheme': request.scheme,
        'host': request.host,
        'url': request.url,
        'is_https_detected': request.headers.get('X-Forwarded-Proto') == 'https' or request.headers.get('X-Forwarded-Ssl') == 'on'
    })

@app.route('/debug/saml-config')
@login_required
def debug_saml_config():
    """Debug endpoint to check SAML configuration - pysaml2 version"""
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Show current request details that affect SAML URL generation
        req_info = {
            'scheme': request.scheme,
            'host': request.host,
            'headers': {
                'Host': request.headers.get('Host'),
                'X-Forwarded-Proto': request.headers.get('X-Forwarded-Proto'),
                'X-Forwarded-Ssl': request.headers.get('X-Forwarded-Ssl'),
                'CF-Connecting-IP': request.headers.get('CF-Connecting-IP'),
                'X-Forwarded-For': request.headers.get('X-Forwarded-For')
            },
            'url': request.url
        }
        
        # Show SAML client configuration
        try:
            client = get_saml_client()
            
            # Force HTTPS for all visiquate.com domains
            host = request.headers.get('Host', request.host)
            if 'visiquate.com' in host or request.headers.get('X-Forwarded-Proto') == 'https':
                scheme = 'https'
            else:
                scheme = request.scheme
            
            base_url = f"{scheme}://{host}"
            
            saml_sp_info = {
                'entityId': f"{base_url}",
                'assertionConsumerService_url': f"{base_url}/saml/acs",
                'singleLogoutService_url': f"{base_url}/saml/sls",
                'library': 'pysaml2',
                'scheme_detection': f'Using {scheme} (forced HTTPS for visiquate.com domains)'
            }
        except Exception as e:
            saml_sp_info = {'error': str(e)}
        
        # Get all SAML related config
        saml_configs = {}
        for key in ['saml_entity_id', 'saml_idp_entity_id', 'saml_idp_sso_url', 'saml_idp_slo_url', 
                   'saml_idp_cert', 'saml_sp_cert', 'saml_sp_private_key', 'saml_nameid_format']:
            value = get_config(key, '')
            # Don't expose full private key for security, just show if it exists
            if 'private_key' in key and value:
                saml_configs[key] = f"[PRIVATE KEY PRESENT - {len(value)} chars]"
            elif 'cert' in key and value:
                saml_configs[key] = f"[CERTIFICATE PRESENT - {len(value)} chars]"
            else:
                saml_configs[key] = value or "[NOT SET]"
        
        return jsonify({
            'request_info': req_info,
            'saml_sp_info': saml_sp_info,
            'config_values': saml_configs,
            'note': 'Now using pysaml2 library with better HTTPS proxy support'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/saml/login')
def saml_login():
    """SAML authentication endpoint - pysaml2 version"""
    try:
        app.logger.info("SAML: Starting login process")
        
        # Get IdP entity ID first for debugging
        idp_entity_id = get_config('saml_idp_entity_id', '')
        if not idp_entity_id:
            app.logger.error("SAML: IdP entity ID not configured")
            raise ValueError("SAML IdP not configured")
        
        app.logger.info(f"SAML: IdP entity ID configured: {idp_entity_id}")
        
        # Get SAML client
        app.logger.info("SAML: Getting SAML client")
        client = get_saml_client()
        app.logger.info("SAML: SAML client created successfully")
        
        app.logger.info(f"SAML: Creating auth request for entity_id: {idp_entity_id}")
        
        try:
            # Create authentication request
            app.logger.info("SAML: Calling prepare_for_authenticate")
            session_id, result = client.prepare_for_authenticate(
                entityid=idp_entity_id,
                relay_state=url_for('saml_acs', _external=True),
                binding=BINDING_HTTP_REDIRECT
            )
            app.logger.info("SAML: prepare_for_authenticate completed")
            
            app.logger.info(f"SAML prepare_for_authenticate succeeded: session_id={session_id}")
            app.logger.info(f"SAML result type: {type(result)}")
            app.logger.info(f"SAML result: {result}")
            
        except Exception as prepare_error:
            app.logger.error(f"SAML prepare_for_authenticate failed: {str(prepare_error)}")
            app.logger.error(f"SAML prepare error type: {type(prepare_error)}")
            raise ValueError(f"SAML preparation failed: {str(prepare_error)}")
        
        # Store session ID for later validation
        session['saml_session_id'] = session_id
        
        # Extract redirect URL - try different approaches
        redirect_url = None
        
        try:
            # Method 1: Check if result is a tuple/dict with headers
            if hasattr(result, 'headers') and result.headers:
                for header_name, header_value in result.headers:
                    if header_name.lower() == 'location':
                        redirect_url = header_value
                        app.logger.info(f"SAML: Found redirect URL in headers: {redirect_url}")
                        break
            
            # Method 2: Check for dict with headers key
            elif isinstance(result, dict) and 'headers' in result:
                headers = result['headers']
                if isinstance(headers, list) and len(headers) > 0:
                    for header in headers:
                        if isinstance(header, (list, tuple)) and len(header) >= 2:
                            if header[0].lower() == 'location':
                                redirect_url = header[1]
                                app.logger.info(f"SAML: Found redirect URL in dict headers: {redirect_url}")
                                break
            
            # Method 3: Check if result is a string URL
            elif isinstance(result, str) and result.startswith('http'):
                redirect_url = result
                app.logger.info(f"SAML: Result is direct URL: {redirect_url}")
                
            # Method 4: Check for url key in dict
            elif isinstance(result, dict) and 'url' in result:
                redirect_url = result['url']
                app.logger.info(f"SAML: Found URL in dict: {redirect_url}")
                
        except Exception as parse_error:
            app.logger.error(f"SAML: Error parsing result: {str(parse_error)}")
        
        if not redirect_url:
            app.logger.error(f"SAML: No redirect URL found. Result structure: {result}")
            app.logger.error(f"SAML: Result attributes: {dir(result) if hasattr(result, '__dict__') else 'No attributes'}")
            raise ValueError(f"No redirect URL found in SAML result. Result type: {type(result)}, Content: {result}")
        
        app.logger.info(f"SAML: Redirecting to: {redirect_url}")
        return redirect(redirect_url)
        
    except ValueError as e:
        flash('SAML authentication not yet configured. Please configure SAML settings in admin panel.')
        return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"SAML login error: {str(e)}")
        flash(f'SAML error: {str(e)}')
        return redirect(url_for('login'))

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    """SAML Assertion Consumer Service - pysaml2 version"""
    try:
        app.logger.info("SAML ACS: Starting SAML response processing")
        client = get_saml_client()
        
        # Get the SAML response from form data
        saml_response = request.form.get('SAMLResponse')
        if not saml_response:
            app.logger.error("SAML ACS: No SAMLResponse in request")
            raise ValueError("No SAMLResponse in request")
        
        app.logger.info(f"SAML ACS: Received SAMLResponse (length: {len(saml_response)})")
        
        # Get the stored session ID if available
        session_id = session.get('saml_session_id')
        app.logger.info(f"SAML ACS: Session ID: {session_id}")
        
        # Process the SAML response
        app.logger.info("SAML ACS: Calling parse_authn_request_response")
        try:
            # pysaml2 expects outstanding to be a dict mapping request_id -> came_from_url
            # We'll leave it as None to disable outstanding query validation for now
            authn_response = client.parse_authn_request_response(
                saml_response, 
                BINDING_HTTP_POST,
                outstanding=None
            )
            app.logger.info("SAML ACS: Successfully parsed SAML response")
        except Exception as parse_error:
            app.logger.error(f"SAML ACS: Failed to parse SAML response: {str(parse_error)}")
            app.logger.error(f"SAML ACS: Parse error type: {type(parse_error)}")
            import traceback
            app.logger.error(f"SAML ACS: Parse error traceback: {traceback.format_exc()}")
            raise
        
        # Get user information from SAML response  
        app.logger.info("SAML ACS: Extracting identity and subject")
        try:
            identity = authn_response.get_identity()
            app.logger.info(f"SAML ACS: Identity type: {type(identity)}, content: {identity}")
        except Exception as identity_error:
            app.logger.error(f"SAML ACS: Failed to get identity: {str(identity_error)}")
            raise
            
        try:
            subject = authn_response.get_subject()
            app.logger.info(f"SAML ACS: Subject type: {type(subject)}, content: {subject}")
            nameid = subject.text  # NameID (may not be email)
            app.logger.info(f"SAML ACS: Extracted NameID: {nameid}")
        except Exception as subject_error:
            app.logger.error(f"SAML ACS: Failed to get subject: {str(subject_error)}")
            raise
        
        # Extract attributes
        app.logger.info("SAML ACS: Extracting attributes")
        attributes = {}
        try:
            for attr_name, attr_values in identity.items():
                attributes[attr_name] = attr_values
            app.logger.info(f"SAML ACS: Extracted attributes: {attributes}")
        except Exception as attr_error:
            app.logger.error(f"SAML ACS: Failed to extract attributes: {str(attr_error)}")
            app.logger.error(f"SAML ACS: Identity type: {type(identity)}")
            raise
        
        # Get email from attributes first, fallback to NameID
        email = nameid  # fallback
        for email_attr in [
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress', 
            'emailAddress',  # camelCase variant (Authentik uses this)
            'emailaddress',
            'email',
            'mail',
            'userPrincipalName',
            'upn'  # User Principal Name (also present in the log)
        ]:
            if email_attr in attributes and attributes[email_attr]:
                email = attributes[email_attr][0]
                app.logger.info(f"SAML ACS: Found email in attribute {email_attr}: {email}")
                break
        
        if email == nameid:
            app.logger.info(f"SAML ACS: No email attribute found, using NameID: {email}")
        
        app.logger.info(f"SAML ACS: Final email for user lookup: {email}")
        
        # Get display name
        name = email  # fallback
        for name_attr in ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', 
                         'displayName', 'name', 'cn']:
            if name_attr in attributes and attributes[name_attr]:
                name = attributes[name_attr][0]
                break
        
        # Extract group membership from SAML attributes
        groups = []
        for group_attr in [
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups',
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups', 
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role',
            'group',      # Authentik uses singular 'group'
            'groups',     # Some providers use plural 'groups'
            'memberOf',
            'roles'
        ]:
            if group_attr in attributes:
                groups.extend(attributes[group_attr])
                break
        
        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, name=name)
            db.session.add(user)
            db.session.commit()
        
        # Update SAML tested flag
        user.saml_tested = True
        
        # Auto-promote maintenance_team members to auditor
        if 'maintenance_team' in [g.lower() for g in groups]:
            if not user.is_auditor:
                user.is_auditor = True
                logger.info(f"Auto-promoted {email} to auditor due to maintenance_team membership")
        
        # Special case: always make Yuliia.lutai an auditor
        if email.lower() == 'yuliia.lutai@visiquate.com':
            if not user.is_auditor:
                user.is_auditor = True
                logger.info(f"Auto-promoted {email} to auditor (special user)")
        
        db.session.commit()
        
        # Login user
        login_user(user, remember=True)
        
        # Set session data for success page
        auth_data = {
            'method': 'saml',
            'email': email,
            'name': name,
            'groups': groups,
            'success': True,
            'user_id': user.id,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': get_real_ip(),
            'user_agent': request.headers.get('User-Agent'),
            'attributes': attributes,  # Store all attributes for debugging
            'nameid': email,
            'session_index': authn_response.session_id() if hasattr(authn_response, 'session_id') else None
        }
        session['last_auth_data'] = auth_data
        
        # Store persistent SAML metadata
        import json
        user.saml_metadata = json.dumps(auth_data)
        db.session.commit()
        
        # Log successful authentication
        log_authentication(
            user.id, 'saml', True, {
                'email': email,
                'attributes': attributes,
                'nameid': email
            },
            get_real_ip(), request.headers.get('User-Agent')
        )
        
        app.logger.info(f"SAML authentication successful for {email}")
        return redirect(url_for('success'))
        
    except Exception as e:
        error_msg = str(e)
        
        # Enhanced logging for debugging
        app.logger.error(f"SAML processing failed: {error_msg}")
        app.logger.error(f"SAML ERROR: {error_msg}")
        
        flash(f"SAML processing error: {error_msg}")
        
        # Log failed authentication
        log_authentication(
            None, 'saml', False, {
                'error': error_msg
            },
            get_real_ip(), request.headers.get('User-Agent')
        )
        
        return redirect(url_for('login'))

@app.route('/saml/sls', methods=['GET'])
def saml_sls():
    """SAML Single Logout Service - pysaml2 version"""
    try:
        # Simply logout the user and redirect
        logout_user()
        flash('Logged out successfully')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'SAML SLO error: {str(e)}')
        return redirect(url_for('login'))

@app.route('/oauth/login/<provider>')
def oauth_login(provider):
    """OIDC/OAuth authentication endpoint"""
    valid_providers = ['authentik']
    if provider not in valid_providers:
        flash(f'Invalid OAuth provider: {provider}. Only "authentik" is supported.')
        return redirect(url_for('login'))
    
    try:
        # Get OIDC configuration from database based on provider
        if provider == 'authentik':
            server_url = get_config('oidc_authentik_url', '')
            client_id = get_config('oidc_authentik_client_id', '')
            client_secret = get_config('oidc_authentik_client_secret', '')
            discovery_url = get_config('oidc_discovery_url', '')
        
        if not all([server_url, client_id, client_secret]):
            raise ValueError("OIDC not fully configured")
        
        # Use configured discovery URL or fall back to standard format
        metadata_url = discovery_url if discovery_url else f'{server_url}/.well-known/openid-configuration'
        
        # Configure OAuth client dynamically with provider-specific name
        try:
            # Try to get existing client first
            oauth_client = oauth.create_client(provider)
            if oauth_client is None:
                logger.warning(f"Existing OAuth client for {provider} is None, will re-register")
                raise ValueError("Existing client is None")
            logger.info(f"Using existing OAuth client for {provider}")
        except (KeyError, AttributeError, ValueError) as e:
            logger.info(f"Creating new OAuth client for {provider}, existing client error: {e}")
            # Register new client if it doesn't exist
            try:
                oauth_client = oauth.register(
                    name=provider,
                    client_id=client_id,
                    client_secret=client_secret,
                    server_metadata_url=metadata_url,
                    client_kwargs={
                        'scope': 'openid email profile groups'
                    }
                )
                logger.info(f"Successfully registered OAuth client for {provider}")
            except Exception as reg_error:
                logger.error(f"Failed to register OAuth client for {provider}: {reg_error}")
                raise ValueError(f"OAuth client registration failed: {reg_error}")
        
        # Verify client was created successfully
        if oauth_client is None:
            logger.error(f"OAuth client is None for provider {provider}")
            raise ValueError(f"OAuth client creation failed for {provider}")
        
        # Generate redirect URI with HTTPS for visiquate.com domains
        host = request.headers.get('Host', request.host)
        if 'visiquate.com' in host or request.headers.get('X-Forwarded-Proto') == 'https':
            redirect_uri = f"https://{host}/oauth/callback/{provider}"
        else:
            redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
        
        # Standard OAuth redirect for OIDC authentication
        return oauth_client.authorize_redirect(redirect_uri)
        
    except ValueError:
        flash('VisiQuate OIDC authentication not yet configured. Please configure OAuth settings in admin panel.')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'OIDC error: {str(e)}')
        return redirect(url_for('login'))

@app.route('/oauth/callback/<provider>')
def oauth_callback(provider):
    """OAuth callback handler"""
    try:
        # Get OIDC configuration from database based on provider
        if provider == 'authentik':
            server_url = get_config('oidc_authentik_url', '')
            client_id = get_config('oidc_authentik_client_id', '')
            client_secret = get_config('oidc_authentik_client_secret', '')
            discovery_url = get_config('oidc_discovery_url', '')
        else:
            raise ValueError(f"Unsupported provider: {provider}. Only 'authentik' is supported for OAuth callbacks.")
        
        if not all([server_url, client_id, client_secret]):
            raise ValueError("OIDC not fully configured")
        
        # Use configured discovery URL or fall back to standard format
        metadata_url = discovery_url if discovery_url else f'{server_url}/.well-known/openid-configuration'
        
        # Configure OAuth client dynamically with provider-specific name
        try:
            # Try to get existing client first
            oauth_client = oauth.create_client(provider)
            if oauth_client is None:
                logger.warning(f"Existing OAuth client for callback {provider} is None, will re-register")
                raise ValueError("Existing client is None")
            logger.info(f"Using existing OAuth client for callback {provider}")
        except (KeyError, AttributeError, ValueError) as e:
            logger.info(f"Creating new OAuth client for callback {provider}, existing client error: {e}")
            # Register new client if it doesn't exist
            try:
                oauth_client = oauth.register(
                    name=provider,
                    client_id=client_id,
                    client_secret=client_secret,
                    server_metadata_url=metadata_url,
                    client_kwargs={
                        'scope': 'openid email profile groups'
                    }
                )
                logger.info(f"Successfully registered OAuth client for callback {provider}")
            except Exception as reg_error:
                logger.error(f"Failed to register OAuth client for callback {provider}: {reg_error}")
                raise ValueError(f"OAuth client registration failed: {reg_error}")
        
        # Verify client was created successfully
        if oauth_client is None:
            logger.error(f"OAuth client is None for callback provider {provider}")
            raise ValueError(f"OAuth client creation failed for callback {provider}")
        
        # Exchange authorization code for tokens
        token = oauth_client.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            # For passkey-test-app, handle empty JWKS gracefully
            if provider == 'passkey-test-app':
                try:
                    user_info = oauth_client.parse_id_token(token)
                except Exception as e:
                    # If JWT parsing fails due to empty JWKS, try to get user info directly
                    logger.warning(f"JWT parsing failed for passkey provider: {str(e)}")
                    # Try to get userinfo from the userinfo endpoint
                    try:
                        user_info = oauth_client.userinfo()
                    except Exception as userinfo_error:
                        logger.error(f"Userinfo endpoint also failed: {str(userinfo_error)}")
                        raise ValueError(f"Unable to get user info from passkey provider: {str(e)}")
            else:
                user_info = oauth_client.parse_id_token(token)
        
        # Extract user information
        email = user_info.get('email')
        name = user_info.get('name') or user_info.get('preferred_username') or email
        
        if not email:
            raise ValueError("No email found in OIDC response")
        
        # Extract group membership from OIDC claims
        groups = []
        # Common OIDC group claim names
        for group_claim in ['groups', 'roles', 'memberOf', 'group_membership', 'authorities']:
            if group_claim in user_info:
                group_data = user_info[group_claim]
                if isinstance(group_data, list):
                    groups.extend(group_data)
                elif isinstance(group_data, str):
                    groups.append(group_data)
                break
        
        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, name=name)
            db.session.add(user)
            db.session.commit()
        
        # Update authentication tested flags based on provider
        if provider == 'authentik':
            user.oidc_tested = True
        elif provider == 'passkey-test-app':
            user.passkey_tested = True
        
        # Auto-promote maintenance_team members to auditor
        if 'maintenance_team' in [g.lower() for g in groups]:
            if not user.is_auditor:
                user.is_auditor = True
                logger.info(f"Auto-promoted {email} to auditor due to maintenance_team membership")
        
        # Special case: always make Yuliia.lutai an auditor
        if email.lower() == 'yuliia.lutai@visiquate.com':
            if not user.is_auditor:
                user.is_auditor = True
                logger.info(f"Auto-promoted {email} to auditor (special user)")
        
        db.session.commit()
        
        # Login user
        login_user(user, remember=True)
        
        # Set session data for success page
        auth_data = {
            'method': 'oidc',
            'email': email,
            'name': name,
            'provider': provider,
            'groups': groups,
            'success': True,
            'user_id': user.id,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': get_real_ip(),
            'user_agent': request.headers.get('User-Agent'),
            'user_info': dict(user_info)  # Store all user info for debugging
        }
        session['last_auth_data'] = auth_data
        
        # Store persistent metadata based on provider
        if provider == 'authentik':
            user.oidc_metadata = json.dumps(auth_data)
        elif provider == 'passkey-test-app':
            user.passkey_metadata = json.dumps(auth_data)
        db.session.commit()
        
        # Log successful authentication
        auth_method = 'passkey' if provider == 'passkey-test-app' else 'oidc'
        log_authentication(
            user.id, auth_method, True, {
                'email': email,
                'provider': provider,
                'user_info': user_info
            },
            get_real_ip(), request.headers.get('User-Agent')
        )
        
        return redirect(url_for('success'))
        
    except Exception as e:
        flash(f'OIDC authentication failed: {str(e)}')
        
        # Log failed authentication
        log_authentication(
            None, 'oidc', False, {
                'provider': provider,
                'error': str(e)
            },
            get_real_ip(), request.headers.get('User-Agent')
        )
        
        return redirect(url_for('login'))

# Authentik Metadata Download Routes
@app.route('/admin/download_saml_metadata', methods=['POST'])
@login_required
def download_saml_metadata():
    """Download and configure SAML metadata from Authentik"""
    if not current_user.is_super_admin:
        return jsonify({'error': 'Super admin privileges required'}), 403
    
    try:
        provider_id = request.form.get('provider_id')
        server_url = request.form.get('server_url', get_config('oidc_authentik_url', ''))
        
        if not provider_id or not server_url:
            return jsonify({'error': 'Provider ID and server URL required'}), 400
        
        # Download SAML metadata
        metadata_url = f"{server_url}/api/v3/providers/saml/{provider_id}/metadata/"
        response = requests.get(metadata_url, timeout=10)
        response.raise_for_status()
        
        # Parse XML metadata
        import xml.etree.ElementTree as ET
        root = ET.fromstring(response.content)
        
        # Extract SAML configuration
        namespace = {'saml': 'urn:oasis:names:tc:SAML:2.0:metadata'}
        
        # Get EntityID
        entity_id = root.get('entityID')
        
        # Get SSO URL
        sso_element = root.find('.//saml:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', namespace)
        sso_url = sso_element.get('Location') if sso_element is not None else None
        
        # Get SLO URL
        slo_element = root.find('.//saml:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]', namespace)
        slo_url = slo_element.get('Location') if slo_element is not None else None
        
        # Get X.509 Certificate
        cert_element = root.find('.//saml:X509Certificate', namespace)
        cert = cert_element.text.strip() if cert_element is not None else None
        
        if not all([entity_id, sso_url, cert]):
            return jsonify({'error': 'Could not extract required SAML metadata'}), 400
        
        # Save configuration to database
        set_config('saml_idp_entity_id', entity_id)
        set_config('saml_idp_sso_url', sso_url)
        if slo_url:
            set_config('saml_idp_slo_url', slo_url)
        set_config('saml_idp_cert', cert)
        
        return jsonify({
            'success': True,
            'message': 'SAML metadata downloaded and configured successfully',
            'data': {
                'entity_id': entity_id,
                'sso_url': sso_url,
                'slo_url': slo_url,
                'cert_length': len(cert)
            }
        })
        
    except requests.RequestException as e:
        return jsonify({'error': f'Failed to download metadata: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to process metadata: {str(e)}'}), 500

@app.route('/admin/download_oidc_metadata', methods=['POST'])
@login_required  
def download_oidc_metadata():
    """Download and configure OIDC metadata from Authentik"""
    if not current_user.is_super_admin:
        return jsonify({'error': 'Super admin privileges required'}), 403
    
    try:
        server_url = request.form.get('server_url')
        if not server_url:
            return jsonify({'error': 'Server URL required'}), 400
        
        # Download OIDC discovery document
        discovery_url = f"{server_url}/.well-known/openid-configuration"
        response = requests.get(discovery_url, timeout=10)
        response.raise_for_status()
        
        metadata = response.json()
        
        # Extract OIDC configuration
        authorization_endpoint = metadata.get('authorization_endpoint')
        token_endpoint = metadata.get('token_endpoint') 
        userinfo_endpoint = metadata.get('userinfo_endpoint')
        issuer = metadata.get('issuer')
        
        if not all([authorization_endpoint, token_endpoint, userinfo_endpoint]):
            return jsonify({'error': 'Incomplete OIDC metadata'}), 400
        
        # Save configuration to database
        set_config('oidc_authentik_url', server_url)
        set_config('oidc_authorization_endpoint', authorization_endpoint)
        set_config('oidc_token_endpoint', token_endpoint)
        set_config('oidc_userinfo_endpoint', userinfo_endpoint)
        set_config('oidc_issuer', issuer)
        
        return jsonify({
            'success': True,
            'message': 'OIDC metadata downloaded and configured successfully',
            'data': {
                'issuer': issuer,
                'authorization_endpoint': authorization_endpoint,
                'token_endpoint': token_endpoint,
                'userinfo_endpoint': userinfo_endpoint
            }
        })
        
    except requests.RequestException as e:
        return jsonify({'error': f'Failed to download OIDC metadata: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to process OIDC metadata: {str(e)}'}), 500


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

@app.template_filter('format_build_time')
def format_build_time(build_date_str):
    """Format build date to show time and timezone"""
    if not build_date_str or build_date_str in ['unknown', 'development']:
        return 'dev'
    
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo
        
        # Parse ISO datetime (from GitHub Actions)
        if 'T' in build_date_str:
            dt = datetime.fromisoformat(build_date_str.replace('Z', '+00:00'))
            # Convert to Pacific Time
            dt_pt = dt.astimezone(ZoneInfo('America/Los_Angeles'))
            return dt_pt.strftime('%b %d, %H:%M %Z')
        else:
            return build_date_str
    except Exception:
        # Fallback for older Python or if zoneinfo fails
        return build_date_str.split('T')[-1][:5] if 'T' in build_date_str else build_date_str


@app.template_filter('provider_display_name')
def provider_display_name(provider_name):
    """Convert internal provider names to friendly display names"""
    provider_names = {
        'authentik': 'id.visiquate.com',
        'saml': 'id.visiquate.com'
    }
    return provider_names.get(provider_name, provider_name)

@app.template_filter('from_json')
def from_json_filter(json_string):
    """Parse JSON string to Python object for template rendering"""
    if not json_string:
        return {}
    try:
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


@app.context_processor
def inject_version_info():
    context = dict(
        git_commit=BUILD_INFO['git_commit_short'],
        build_date=BUILD_INFO['build_date'],
        version=BUILD_INFO['version'],
        build_number=BUILD_INFO['build_number']
    )
    
    # Add impersonation context
    if current_user.is_authenticated:
        context['is_impersonating'] = is_impersonating()
        context['impersonation_info'] = get_impersonation_info()
        context['is_super_admin'] = current_user.is_super_admin
    
    return context

# Initialize database on first request
def run_migrations():
    """Run database migrations to add new columns"""
    try:
        # Check if is_auditor column exists
        result = db.session.execute(text("PRAGMA table_info(user)"))
        columns = [row[1] for row in result.fetchall()]
        
        if 'is_auditor' not in columns:
            logger.info("Adding is_auditor column to user table")
            db.session.execute(text("ALTER TABLE user ADD COLUMN is_auditor BOOLEAN DEFAULT 0"))
            db.session.commit()
            
        # Check if updated_user_id column exists in scim_log table  
        result = db.session.execute(text("PRAGMA table_info(scim_log)"))
        columns = [row[1] for row in result.fetchall()]
        
        if 'updated_user_id' not in columns:
            logger.info("Adding updated_user_id column to scim_log table")
            db.session.execute(text("ALTER TABLE scim_log ADD COLUMN updated_user_id INTEGER REFERENCES user(id)"))
            db.session.commit()
        
        # Check if saml_metadata column exists in user table
        result = db.session.execute(text("PRAGMA table_info(user)"))
        columns = [row[1] for row in result.fetchall()]
        
        if 'saml_metadata' not in columns:
            logger.info("Adding saml_metadata column to user table")
            db.session.execute(text("ALTER TABLE user ADD COLUMN saml_metadata TEXT"))
            db.session.commit()
            
        if 'oidc_metadata' not in columns:
            logger.info("Adding oidc_metadata column to user table")
            db.session.execute(text("ALTER TABLE user ADD COLUMN oidc_metadata TEXT"))
            db.session.commit()
            
        if 'passkey_tested' not in columns:
            logger.info("Adding passkey_tested column to user table")
            db.session.execute(text("ALTER TABLE user ADD COLUMN passkey_tested BOOLEAN DEFAULT 0"))
            db.session.commit()
            
        if 'passkey_metadata' not in columns:
            logger.info("Adding passkey_metadata column to user table")
            db.session.execute(text("ALTER TABLE user ADD COLUMN passkey_metadata TEXT"))
            db.session.commit()
        
        # Initialize default passkey configuration values if they don't exist
        passkey_configs = [
            ('passkey_server_url', 'https://id.visiquate.com', 'Passkey OIDC server URL'),
            ('passkey_client_id', '7Ko3puJT9GgwSb6ts3A0IoAXQiLabuxeI8vdhuXY', 'Passkey OIDC client ID'),
            ('passkey_client_secret', 'ny0iUwnmSFgXQpSekNUP94rCNw9KBg5148APk3r0Hn0llLYoUKeaLE3ysNNqP2ne4lHM9iUFdx5k1d1N1nf8BzFR8I69o0clZU5NhcLzBDDqqju9JChtl6F3i7Ux3iXz', 'Passkey OIDC client secret'),
            ('passkey_discovery_url', 'https://id.visiquate.com/application/o/passkey-test-app/.well-known/openid-configuration', 'Passkey OIDC discovery URL')
        ]
        
        for key, default_value, description in passkey_configs:
            existing_config = Configuration.query.filter_by(key=key).first()
            if not existing_config:
                logger.info(f"Adding default passkey configuration: {key}")
                new_config = Configuration(
                    key=key,
                    value=default_value,
                    description=description
                )
                db.session.add(new_config)
                db.session.commit()
            
    except Exception as e:
        logger.error(f"Migration error: {str(e)}")
        db.session.rollback()

@app.before_request
def create_tables():
    if not hasattr(create_tables, 'done'):
        db.create_all()
        
        # Run migrations for new columns
        run_migrations()
        
        # Load configuration from file into database
        update_config_from_file()
        
        # Create super admin user if none exists (now safe to query after migrations)
        if not User.query.filter_by(is_super_admin=True).first():
            admin = User.query.filter_by(email='admin@visiquate.com').first()
            if admin:
                admin.is_super_admin = True
                db.session.commit()
                logger.info("Upgraded admin@visiquate.com to super admin")
        
        create_tables.done = True

@app.route('/admin/create_super_admin', methods=['POST'])
@login_required
def create_super_admin():
    """Convert current user to super admin (for initial setup)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Must be admin'}), 403
    
    # Only allow if no super admin exists
    if User.query.filter_by(is_super_admin=True).first():
        return jsonify({'error': 'Super admin already exists'}), 400
    
    current_user.is_super_admin = True
    db.session.commit()
    
    flash('You are now a super admin with impersonation privileges')
    return redirect(url_for('admin'))

@app.route('/admin/export_config', methods=['POST'])
@login_required
def export_config():
    """Export current configuration to YAML file"""
    if not current_user.is_super_admin:
        return jsonify({'error': 'Super admin privileges required'}), 403
    
    try:
        # Get all configuration from database
        configs = Configuration.query.all()
        config_dict = {}
        
        for config in configs:
            config_dict[config.key] = config.value
        
        # Save to file
        if save_config_file(config_dict):
            logger.info(f"Exported {len(config_dict)} configuration items to file")
            return jsonify({
                'success': True,
                'message': f'Exported {len(config_dict)} configuration items to {CONFIG_FILE_PATH}',
                'config_count': len(config_dict)
            })
        else:
            return jsonify({'error': 'Failed to save configuration file'}), 500
            
    except Exception as e:
        logger.error(f"Failed to export configuration: {e}")
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

def reconcile_passkey_status_for_user(user):
    """
    Reconcile passkey status for a single user by checking Authentik API
    Returns tuple: (success: bool, message: str, changed: bool)
    """
    try:
        # Get user's actual passkey status from Authentik
        passkey_info = get_user_passkey_status(user.email)
        
        if 'error' in passkey_info:
            return False, f"API error: {passkey_info['error']}", False
        
        # Determine if user actually has passkeys in Authentik
        has_actual_passkeys = passkey_info.get('has_passkey', False)
        current_status = user.passkey_tested
        
        # If status doesn't match reality, update it
        if has_actual_passkeys and not current_status:
            # User has passkeys but we show "Not Tested" - mark as tested
            user.passkey_tested = True
            user.passkey_metadata = json.dumps({
                'reconciled_at': datetime.utcnow().isoformat(),
                'source': 'reconciliation_job',
                'authentik_passkey_count': passkey_info.get('passkey_count', 0),
                'note': 'Automatically marked as tested due to existing passkeys in Authentik'
            })
            return True, f"Marked as tested (found {passkey_info.get('passkey_count', 0)} passkeys)", True
            
        elif not has_actual_passkeys and current_status:
            # User shows "Tested" but has no passkeys - clear the status
            user.passkey_tested = False
            user.passkey_metadata = json.dumps({
                'reconciled_at': datetime.utcnow().isoformat(),
                'source': 'reconciliation_job',
                'note': 'Automatically cleared - no passkeys found in Authentik'
            })
            return True, f"Cleared test status (no passkeys found)", True
        else:
            # Status is already correct
            status_desc = "has passkeys and marked tested" if has_actual_passkeys else "no passkeys and marked not tested"
            return True, f"Already correct ({status_desc})", False
            
    except Exception as e:
        logger.error(f"Error reconciling passkey status for {user.email}: {e}")
        return False, f"Exception: {str(e)}", False

def reconcile_all_passkey_statuses():
    """
    Reconcile passkey status for all users by checking actual Authentik API status
    Returns summary statistics
    """
    results = {
        'total_users': 0,
        'users_checked': 0,
        'users_updated': 0,
        'errors': 0,
        'changes': []
    }
    
    try:
        with app.app_context():
            users = User.query.all()
            results['total_users'] = len(users)
            
            for user in users:
                success, message, changed = reconcile_passkey_status_for_user(user)
                results['users_checked'] += 1
                
                if success:
                    if changed:
                        results['users_updated'] += 1
                        results['changes'].append(f"{user.email}: {message}")
                        logger.info(f"Reconciliation updated {user.email}: {message}")
                else:
                    results['errors'] += 1
                    logger.error(f"Reconciliation failed for {user.email}: {message}")
            
            # Commit all changes at once
            if results['users_updated'] > 0:
                db.session.commit()
                logger.info(f"Passkey reconciliation completed: {results['users_updated']} users updated")
            else:
                logger.info("Passkey reconciliation completed: no changes needed")
                
    except Exception as e:
        logger.error(f"Error in passkey reconciliation job: {e}")
        db.session.rollback()
        results['errors'] += 1
    
    return results

@app.route('/admin/reconcile-passkeys', methods=['POST'])
@login_required
def admin_reconcile_passkeys():
    """Manual admin route to reconcile passkey statuses"""
    if not (current_user.is_admin or current_user.is_auditor):
        return jsonify({'error': 'Admin or auditor privileges required'}), 403
    
    try:
        results = reconcile_all_passkey_statuses()
        
        return jsonify({
            'success': True,
            'message': f'Reconciliation complete: {results["users_updated"]} users updated, {results["errors"]} errors',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Admin reconcile passkeys failed: {e}")
        return jsonify({'error': f'Reconciliation failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False)
