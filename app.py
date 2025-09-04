import os
import json
import base64
import secrets
import uuid
import time
import yaml
import logging
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

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

# OAuth Configuration - VisiQuate OIDC (Authentik)
app.config['AUTHENTIK_CLIENT_ID'] = os.getenv('AUTHENTIK_CLIENT_ID')
app.config['AUTHENTIK_CLIENT_SECRET'] = os.getenv('AUTHENTIK_CLIENT_SECRET')
app.config['AUTHENTIK_SERVER_URL'] = os.getenv('AUTHENTIK_SERVER_URL', 'https://auth.visiquate.com')

# WebAuthn Configuration
app.config['WEBAUTHN_RP_ID'] = os.getenv('WEBAUTHN_RP_ID', 'sso-app.visiquate.com')
app.config['WEBAUTHN_RP_NAME'] = os.getenv('WEBAUTHN_RP_NAME', 'SSO Test App')
app.config['WEBAUTHN_ORIGIN'] = os.getenv('WEBAUTHN_ORIGIN', 'https://sso-app.visiquate.com')

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
RP_NAME = os.getenv('RP_NAME', 'SSO Test App')
ORIGIN = os.getenv('ORIGIN', 'http://localhost:5000')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # SCIM fields
    external_id = db.Column(db.String(255))
    active = db.Column(db.Boolean, default=True)
    scim_provisioned = db.Column(db.Boolean, default=False)
    
    # Authentication status tracking
    saml_tested = db.Column(db.Boolean, default=False)
    oidc_tested = db.Column(db.Boolean, default=False)
    password_tested = db.Column(db.Boolean, default=False)
    passkey_tested = db.Column(db.Boolean, default=False)
    
    # Relationships
    auth_logs = db.relationship('AuthLog', backref='user', lazy=True)
    credentials = db.relationship('WebAuthnCredential', backref='user', lazy=True)

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

class WebAuthnCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.LargeBinary, nullable=False, unique=True)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ImpersonationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    impersonated_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 'start', 'stop', 'auth_test'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    notes = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def get_config(key, default=None):
    config = Configuration.query.filter_by(key=key).first()
    if config:
        return config.value
    return default

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
    
    return config

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
            elif auth_method == 'password':
                user.password_tested = True
            elif auth_method == 'passkey':
                user.passkey_tested = True
    
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
        ip_address=request.remote_addr,
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
            ip_address=request.remote_addr,
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
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        
        # Check if user should be admin
        is_admin = email in ['brent.langston@visiquate.com', 'yuliia.lutai@visiquate.com']
        
        user = User(
            email=email,
            name=name,
            password_hash=generate_password_hash(password),
            is_admin=is_admin
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/password_auth', methods=['POST'])
def password_auth():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    
    transaction_data = {
        'method': 'password',
        'email': email,
        'timestamp': datetime.utcnow().isoformat(),
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent')
    }
    
    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        transaction_data['success'] = True
        transaction_data['user_id'] = user.id
        
        log_authentication(
            user.id, 'password', True, transaction_data,
            request.remote_addr, request.headers.get('User-Agent')
        )
        
        session['last_auth_data'] = transaction_data
        flash('Password authentication successful!')
        return redirect(url_for('success'))
    else:
        transaction_data['success'] = False
        transaction_data['error'] = 'Invalid credentials'
        
        log_authentication(
            user.id if user else None, 'password', False, transaction_data,
            request.remote_addr, request.headers.get('User-Agent')
        )
        
        flash('Invalid email or password')
        return redirect(url_for('login'))

@app.route('/success')
@login_required
def success():
    auth_data = session.get('last_auth_data', {})
    return render_template('success.html', auth_data=auth_data)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin.html', users=users)

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
    
    return render_template('admin_config.html', configs=config_dict)

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

@app.route('/admin/user/<int:user_id>/logs')
@login_required
def user_logs(user_id):
    if not current_user.is_admin:
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
        ip_address=request.remote_addr,
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
    elif method == 'passkey':
        flash(f'Test passkey authentication for {current_user.email}', 'info')
        return redirect(url_for('login'))
    else:
        flash('Invalid authentication method', 'error')
        return redirect(url_for('index'))

# SCIM 2.0 endpoints
@app.route('/scim/v2/ServiceProviderConfig')
def scim_service_provider_config():
    """SCIM endpoint for service provider configuration"""
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
    
    return jsonify(config)

@app.route('/scim/v2/Users', methods=['GET'])
def scim_list_users():
    """SCIM endpoint to list users"""
    auth_header = request.headers.get('Authorization', '')
    scim_bearer_token = get_config('scim_bearer_token', '')
    
    if not auth_header.startswith('Bearer ') or auth_header[7:] != scim_bearer_token:
        return jsonify({'detail': 'Authentication failed', 'status': 401}), 401
    
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
    
    return jsonify(response)

@app.route('/scim/v2/Users', methods=['POST'])
def scim_create_user():
    """SCIM endpoint to create a user"""
    auth_header = request.headers.get('Authorization', '')
    scim_bearer_token = get_config('scim_bearer_token', '')
    
    if not auth_header.startswith('Bearer ') or auth_header[7:] != scim_bearer_token:
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
        return jsonify({
            'detail': 'User already exists',
            'status': 409
        }), 409
    
    # Check if user should be admin
    is_admin = email in ['brent.langston@visiquate.com', 'yuliia.lutai@visiquate.com']
    
    # Create user
    user = User(
        email=email,
        name=formatted_name,
        external_id=external_id,
        active=active,
        scim_provisioned=True,
        is_admin=is_admin
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
    
    return jsonify(scim_user), 201

# Authentication routes
def init_saml_auth(req):
    """Initialize SAML Auth object"""
    saml_settings = get_saml_settings()
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    return auth

def prepare_flask_request(request):
    """Prepare Flask request for SAML"""
    url_data = urlsplit(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.headers.get('Host', request.host),
        'server_port': url_data.port or (443 if request.scheme == 'https' else 80),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

def get_saml_settings():
    """Get SAML settings from database configuration"""
    entity_id = get_config('saml_entity_id', request.url_root.rstrip('/'))
    acs_url = f"{request.url_root.rstrip('/')}/saml/acs"
    sls_url = f"{request.url_root.rstrip('/')}/saml/sls" 
    
    idp_entity_id = get_config('saml_idp_entity_id', '')
    idp_sso_url = get_config('saml_idp_sso_url', '')
    idp_slo_url = get_config('saml_idp_slo_url', '')
    idp_cert = get_config('saml_idp_cert', '')
    nameid_format = get_config('saml_nameid_format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
    
    if not all([idp_entity_id, idp_sso_url, idp_cert]):
        raise ValueError("SAML not fully configured")
    
    return {
        "sp": {
            "entityId": entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": sls_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "NameIDFormat": nameid_format,
            "x509cert": "",
            "privateKey": ""
        },
        "idp": {
            "entityId": idp_entity_id,
            "singleSignOnService": {
                "url": idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "singleLogoutService": {
                "url": idp_slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            } if idp_slo_url else None,
            "x509cert": idp_cert
        }
    }

@app.route('/saml/login')
def saml_login():
    """SAML authentication endpoint"""
    try:
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        return redirect(auth.login())
    except ValueError as e:
        flash('SAML authentication not yet configured. Please configure SAML settings in admin panel.')
        return redirect(url_for('login'))
    except Exception as e:
        flash(f'SAML error: {str(e)}')
        return redirect(url_for('login'))

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    """SAML Assertion Consumer Service"""
    try:
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        auth.process_response()
        
        errors = auth.get_errors()
        if not errors:
            # Get user attributes from SAML response
            attributes = auth.get_attributes()
            email = auth.get_nameid()
            name = attributes.get('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', [email])[0]
            
            # Find or create user
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(email=email, name=name)
                db.session.add(user)
                db.session.commit()
            
            # Login user
            login_user(user, remember=True)
            
            # Log successful authentication
            log_authentication(
                user.id, 'saml', True, {
                    'email': email,
                    'attributes': attributes,
                    'nameid': auth.get_nameid()
                },
                request.remote_addr, request.headers.get('User-Agent')
            )
            
            return redirect(url_for('success'))
        else:
            error_msg = f"SAML Error: {', '.join(errors)}"
            flash(error_msg)
            
            # Log failed authentication
            log_authentication(
                None, 'saml', False, {
                    'errors': errors,
                    'last_error_reason': auth.get_last_error_reason()
                },
                request.remote_addr, request.headers.get('User-Agent')
            )
            
            return redirect(url_for('login'))
            
    except Exception as e:
        flash(f'SAML processing error: {str(e)}')
        return redirect(url_for('login'))

@app.route('/saml/sls', methods=['GET'])
def saml_sls():
    """SAML Single Logout Service"""
    try:
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        url = auth.process_slo(delete_session_cb=lambda: logout_user())
        errors = auth.get_errors()
        
        if not errors:
            if url:
                return redirect(url)
            else:
                return redirect(url_for('login'))
        else:
            flash(f'SAML SLO Error: {", ".join(errors)}')
            return redirect(url_for('login'))
            
    except Exception as e:
        flash(f'SAML SLO error: {str(e)}')
        return redirect(url_for('login'))

@app.route('/oauth/login/<provider>')
def oauth_login(provider):
    """OIDC/OAuth authentication endpoint"""
    valid_providers = ['authentik']
    if provider not in valid_providers:
        flash('Invalid OAuth provider')
        return redirect(url_for('login'))
    
    try:
        # Get OIDC configuration from database
        server_url = get_config('oidc_authentik_url', '')
        client_id = get_config('oidc_authentik_client_id', '')
        client_secret = get_config('oidc_authentik_client_secret', '')
        
        if not all([server_url, client_id, client_secret]):
            raise ValueError("OIDC not fully configured")
        
        # Configure OAuth client dynamically
        authentik = oauth.register(
            name='authentik',
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url=f'{server_url}/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
        
        redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
        return authentik.authorize_redirect(redirect_uri)
        
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
        # Get OIDC configuration from database
        server_url = get_config('oidc_authentik_url', '')
        client_id = get_config('oidc_authentik_client_id', '')
        client_secret = get_config('oidc_authentik_client_secret', '')
        
        if not all([server_url, client_id, client_secret]):
            raise ValueError("OIDC not fully configured")
        
        # Configure OAuth client dynamically (same as above)
        authentik = oauth.register(
            name='authentik',
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url=f'{server_url}/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
        
        # Exchange authorization code for tokens
        token = authentik.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            user_info = authentik.parse_id_token(token)
        
        # Extract user information
        email = user_info.get('email')
        name = user_info.get('name') or user_info.get('preferred_username') or email
        
        if not email:
            raise ValueError("No email found in OIDC response")
        
        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, name=name)
            db.session.add(user)
            db.session.commit()
        
        # Login user
        login_user(user, remember=True)
        
        # Log successful authentication
        log_authentication(
            user.id, 'oidc', True, {
                'email': email,
                'provider': provider,
                'user_info': user_info
            },
            request.remote_addr, request.headers.get('User-Agent')
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
            request.remote_addr, request.headers.get('User-Agent')
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

# WebAuthn Routes
@app.route('/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    """Begin WebAuthn registration process"""
    try:
        user_id = str(current_user.id).encode('utf-8')
        user_name = current_user.email
        user_display_name = current_user.email
        
        # Generate registration options
        options = generate_registration_options(
            rp_id=app.config['WEBAUTHN_RP_ID'],
            rp_name=app.config['WEBAUTHN_RP_NAME'],
            user_id=user_id,
            user_name=user_name,
            user_display_name=user_display_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED
            )
        )
        
        # Store challenge in session
        session['webauthn_challenge'] = base64.urlsafe_b64encode(options.challenge).decode('utf-8')
        
        # Convert options to JSON-serializable format
        options_json = {
            "challenge": base64.urlsafe_b64encode(options.challenge).decode('utf-8'),
            "rp": {
                "name": options.rp.name,
                "id": options.rp.id
            },
            "user": {
                "id": base64.urlsafe_b64encode(options.user.id).decode('utf-8'),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [{"alg": param.alg, "type": param.type} for param in options.pub_key_cred_params],
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "timeout": options.timeout,
            "attestation": options.attestation.value
        }
        
        return jsonify({"options": options_json})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    """Complete WebAuthn registration process"""
    try:
        credential_json = request.get_json()
        
        if not credential_json or 'webauthn_challenge' not in session:
            return jsonify({"error": "Invalid request"}), 400
            
        challenge = base64.urlsafe_b64decode(session['webauthn_challenge'].encode('utf-8'))
        
        # Create RegistrationCredential object
        credential = RegistrationCredential.parse_raw(json.dumps(credential_json))
        
        # Verify the registration
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=app.config['WEBAUTHN_ORIGIN'],
            expected_rp_id=app.config['WEBAUTHN_RP_ID']
        )
        
        if verification.verified:
            # Save credential to database
            new_credential = WebAuthnCredential(
                user_id=current_user.id,
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count
            )
            db.session.add(new_credential)
            db.session.commit()
            
            # Clear challenge from session
            session.pop('webauthn_challenge', None)
            
            return jsonify({"verified": True})
        else:
            return jsonify({"error": "Registration verification failed"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/webauthn/authenticate/begin', methods=['POST'])
def webauthn_authenticate_begin():
    """Begin WebAuthn authentication process"""
    try:
        data = request.get_json()
        email = data.get('email') if data else None
        
        if not email:
            return jsonify({"error": "Email required"}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Get user's credentials
        credentials = WebAuthnCredential.query.filter_by(user_id=user.id).all()
        if not credentials:
            return jsonify({"error": "No credentials found"}), 404
            
        # Generate authentication options
        credential_descriptors = [{
            "id": base64.urlsafe_b64encode(cred.credential_id).decode('utf-8'),
            "type": "public-key"
        } for cred in credentials]
        
        options = generate_authentication_options(
            rp_id=app.config['WEBAUTHN_RP_ID'],
            allow_credentials=credential_descriptors,
            user_verification=UserVerificationRequirement.PREFERRED
        )
        
        # Store challenge and user ID in session
        session['webauthn_challenge'] = base64.urlsafe_b64encode(options.challenge).decode('utf-8')
        session['webauthn_user_id'] = user.id
        
        # Convert options to JSON-serializable format
        options_json = {
            "challenge": base64.urlsafe_b64encode(options.challenge).decode('utf-8'),
            "allowCredentials": [
                {
                    "id": base64.urlsafe_b64encode(cred.credential_id).decode('utf-8'),
                    "type": "public-key"
                } for cred in credentials
            ],
            "timeout": options.timeout,
            "rpId": options.rp_id,
            "userVerification": options.user_verification.value
        }
        
        return jsonify({"options": options_json})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/webauthn/authenticate/complete', methods=['POST'])
def webauthn_authenticate_complete():
    """Complete WebAuthn authentication process"""
    try:
        credential_json = request.get_json()
        
        if not credential_json or 'webauthn_challenge' not in session or 'webauthn_user_id' not in session:
            return jsonify({"error": "Invalid request"}), 400
            
        user_id = session['webauthn_user_id']
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        challenge = base64.urlsafe_b64decode(session['webauthn_challenge'].encode('utf-8'))
        
        # Find the credential
        credential_id = base64.urlsafe_b64decode(credential_json['id'].encode('utf-8'))
        db_credential = WebAuthnCredential.query.filter_by(
            user_id=user_id,
            credential_id=credential_id
        ).first()
        
        if not db_credential:
            return jsonify({"error": "Credential not found"}), 404
            
        # Create AuthenticationCredential object
        credential = AuthenticationCredential.parse_raw(json.dumps(credential_json))
        
        # Verify the authentication
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=app.config['WEBAUTHN_ORIGIN'],
            expected_rp_id=app.config['WEBAUTHN_RP_ID'],
            credential_public_key=db_credential.public_key,
            credential_current_sign_count=db_credential.sign_count
        )
        
        if verification.verified:
            # Update sign count
            db_credential.sign_count = verification.new_sign_count
            db.session.commit()
            
            # Log the user in
            login_user(user, remember=True)
            
            # Log successful authentication
            auth_log = AuthLog(
                user_id=user.id,
                email=user.email,
                method='passkey',
                success=True,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(auth_log)
            db.session.commit()
            
            # Clear session data
            session.pop('webauthn_challenge', None)
            session.pop('webauthn_user_id', None)
            
            return jsonify({
                "verified": True,
                "redirect": url_for('success')
            })
        else:
            return jsonify({"error": "Authentication verification failed"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

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
@app.before_request
def create_tables():
    if not hasattr(create_tables, 'done'):
        db.create_all()
        
        # Load configuration from file into database
        update_config_from_file()
        
        # Create super admin user if none exists
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

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False)
