import os
import json
import base64
import secrets
import uuid
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from authlib.integrations.flask_client import OAuth
from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
)
import webauthn
from dotenv import load_dotenv
from scim2_filter_parser.lexer import SCIMFilterLexer
from scim2_filter_parser.parser import SCIMFilterParser

load_dotenv()

app = Flask(__name__)
START_TIME = time.time()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///sso_test.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['MICROSOFT_CLIENT_ID'] = os.getenv('MICROSOFT_CLIENT_ID')
app.config['MICROSOFT_CLIENT_SECRET'] = os.getenv('MICROSOFT_CLIENT_SECRET')

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth setup
oauth = OAuth(app)

# Google OAuth
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Microsoft OAuth
microsoft = oauth.register(
    name='microsoft',
    client_id=app.config['MICROSOFT_CLIENT_ID'],
    client_secret=app.config['MICROSOFT_CLIENT_SECRET'],
    client_kwargs={
        'scope': 'openid email profile',
    },
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    jwks_uri='https://login.microsoftonline.com/common/discovery/v2.0/keys',
)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # SCIM fields
    external_id = db.Column(db.String(255))  # Authentik user ID
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    auth_method = db.Column(db.String(20), nullable=False)  # saml, oidc, password, passkey
    success = db.Column(db.Boolean, nullable=False)
    transaction_data = db.Column(db.Text)  # JSON string of auth details
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_config(key, default=None):
    """Get configuration value"""
    config = Configuration.query.filter_by(key=key).first()
    if config:
        return config.value
    return default

def set_config(key, value, description=None, user_id=None):
    """Set configuration value"""
    config = Configuration.query.filter_by(key=key).first()
    if not config:
        config = Configuration(key=key, description=description)
    
    config.value = value
    config.updated_by = user_id
    config.updated_at = datetime.utcnow()
    
    db.session.add(config)
    db.session.commit()
    return config

def init_saml_auth(req):
    """Initialize SAML authentication"""
    # Get SAML configuration from database
    origin = get_config('saml_origin', ORIGIN)
    
    settings = {
        "strict": True,
        "debug": get_config('saml_debug', 'true').lower() == 'true',
        "sp": {
            "entityId": f"{origin}/saml/metadata",
            "assertionConsumerService": {
                "url": f"{origin}/saml/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": f"{origin}/saml/sls", 
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "NameIDFormat": get_config('saml_nameid_format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
            "x509cert": get_config('saml_sp_cert', ''),
            "privateKey": get_config('saml_sp_private_key', '')
        },
        "idp": {
            "entityId": get_config('saml_idp_entity_id', ''),
            "singleSignOnService": {
                "url": get_config('saml_idp_sso_url', ''),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "singleLogoutService": {
                "url": get_config('saml_idp_slo_url', ''),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": get_config('saml_idp_cert', '')
        }
    }
    
    auth = OneLogin_Saml2_Auth(req, settings)
    return auth

def init_request(request):
    """Initialize SAML request object"""
    url_data = request.urlsplit
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.environ['HTTP_HOST'],
        'server_port': request.environ['SERVER_PORT'],
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

def log_authentication(user_id, auth_method, success, transaction_data, ip_address, user_agent):
    """Log authentication attempt"""
    auth_log = AuthLog(
        user_id=user_id,
        auth_method=auth_method,
        success=success,
        transaction_data=json.dumps(transaction_data),
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.session.add(auth_log)
    
    # Update user's test status
    if success and user_id:
        user = User.query.get(user_id)
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

@app.route('/health')
def health():
    """Standardized health check endpoint."""
    health_status = {
        'status': 'healthy',
        'service': os.getenv('SERVICE_NAME', 'sso-authentication-test'),
        'version': os.getenv('VERSION', '1.0.0'),
        'commit': os.getenv('GIT_COMMIT', 'unknown')[:7],
        'build_date': os.getenv('BUILD_DATE', 'unknown'),
        'uptime': int(time.time() - START_TIME),
        'environment': os.getenv('ENVIRONMENT', 'production'),
        'checks': {}
    }
    
    # Add service-specific health checks
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        health_status['checks']['database'] = 'healthy'
    except Exception as e:
        health_status['checks']['database'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    # Check if basic configuration exists
    try:
        # Test basic configuration access
        test_config = get_config('app_origin', 'not_set')
        health_status['checks']['configuration'] = 'healthy'
    except Exception as e:
        health_status['checks']['configuration'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    # Return pretty-printed JSON
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

@app.route('/saml/login')
def saml_login():
    req = init_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = init_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    
    errors = auth.get_errors()
    
    transaction_data = {
        'method': 'saml',
        'timestamp': datetime.utcnow().isoformat(),
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'saml_response': request.form.get('SAMLResponse', ''),
        'relay_state': request.form.get('RelayState', ''),
        'errors': errors,
        'attributes': auth.get_attributes() if not errors else {},
        'nameid': auth.get_nameid() if not errors else None,
        'session_index': auth.get_session_index() if not errors else None
    }
    
    if len(errors) == 0:
        email = auth.get_nameid()
        attributes = auth.get_attributes()
        
        # Get or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            # Extract name from attributes
            name = email
            if 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name' in attributes:
                name = attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'][0]
            elif 'displayName' in attributes:
                name = attributes['displayName'][0]
            
            is_admin = email in ['brent.langston@visiquate.com', 'yuliia.lutai@visiquate.com']
            
            user = User(email=email, name=name, is_admin=is_admin)
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        transaction_data['success'] = True
        transaction_data['user_id'] = user.id
        
        log_authentication(
            user.id, 'saml', True, transaction_data,
            request.remote_addr, request.headers.get('User-Agent')
        )
        
        session['last_auth_data'] = transaction_data
        flash('SAML authentication successful!')
        return redirect(url_for('success'))
    else:
        transaction_data['success'] = False
        
        log_authentication(
            None, 'saml', False, transaction_data,
            request.remote_addr, request.headers.get('User-Agent')
        )
        
        flash(f'SAML authentication failed: {", ".join(errors)}')
        return redirect(url_for('login'))

@app.route('/saml/metadata')
def saml_metadata():
    req = init_request(request)
    settings = OneLogin_Saml2_Settings(req)
    metadata = settings.get_sp_metadata()
    resp = make_response(metadata, 200)
    resp.headers['Content-Type'] = 'text/xml'
    return resp

@app.route('/oauth/<provider>')
def oauth_login(provider):
    if provider == 'google':
        client = google
    elif provider == 'microsoft':
        client = microsoft
    else:
        flash('Invalid OAuth provider')
        return redirect(url_for('login'))
    
    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
    return client.authorize_redirect(redirect_uri)

@app.route('/oauth/<provider>/callback')
def oauth_callback(provider):
    if provider == 'google':
        client = google
    elif provider == 'microsoft':
        client = microsoft
    else:
        flash('Invalid OAuth provider')
        return redirect(url_for('login'))
    
    try:
        token = client.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            user_info = client.parse_id_token(token)
        
        transaction_data = {
            'method': 'oidc',
            'provider': provider,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'token_response': {
                'access_token': token.get('access_token', '')[:20] + '...' if token.get('access_token') else '',
                'id_token': token.get('id_token', '')[:20] + '...' if token.get('id_token') else '',
                'token_type': token.get('token_type'),
                'expires_in': token.get('expires_in'),
                'scope': token.get('scope')
            },
            'user_info': user_info
        }
        
        email = user_info.get('email')
        name = user_info.get('name', email)
        
        # Get or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            is_admin = email in ['brent.langston@visiquate.com', 'yuliia.lutai@visiquate.com']
            user = User(email=email, name=name, is_admin=is_admin)
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        transaction_data['success'] = True
        transaction_data['user_id'] = user.id
        
        log_authentication(
            user.id, 'oidc', True, transaction_data,
            request.remote_addr, request.headers.get('User-Agent')
        )
        
        session['last_auth_data'] = transaction_data
        flash(f'{provider.title()} OIDC authentication successful!')
        return redirect(url_for('success'))
        
    except Exception as e:
        transaction_data = {
            'method': 'oidc',
            'provider': provider,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'success': False,
            'error': str(e)
        }
        
        log_authentication(
            None, 'oidc', False, transaction_data,
            request.remote_addr, request.headers.get('User-Agent')
        )
        
        flash(f'{provider.title()} OIDC authentication failed: {str(e)}')
        return redirect(url_for('login'))

@app.route('/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    user_id = str(current_user.id).encode('utf-8')
    
    # Check if user already has credentials
    existing_creds = WebAuthnCredential.query.filter_by(user_id=current_user.id).all()
    exclude_credentials = []
    
    for cred in existing_creds:
        exclude_credentials.append(
            PublicKeyCredentialDescriptor(id=cred.credential_id)
        )
    
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=current_user.email,
        user_display_name=current_user.name,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        ),
    )
    
    session['webauthn_challenge'] = options.challenge
    session['webauthn_user_id'] = user_id
    
    return jsonify({
        'options': {
            'challenge': base64.urlsafe_b64encode(options.challenge).decode(),
            'rp': {'name': options.rp.name, 'id': options.rp.id},
            'user': {
                'id': base64.urlsafe_b64encode(options.user.id).decode(),
                'name': options.user.name,
                'displayName': options.user.display_name
            },
            'pubKeyCredParams': [{'alg': param.alg, 'type': param.type} for param in options.pub_key_cred_params],
            'timeout': options.timeout,
            'excludeCredentials': [{'id': base64.urlsafe_b64encode(cred.id).decode(), 'type': cred.type} for cred in options.exclude_credentials] if options.exclude_credentials else [],
            'authenticatorSelection': {
                'userVerification': options.authenticator_selection.user_verification.value if options.authenticator_selection else 'required'
            }
        }
    })

@app.route('/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    credential_data = request.get_json()
    
    transaction_data = {
        'method': 'passkey_registration',
        'timestamp': datetime.utcnow().isoformat(),
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'credential_data': credential_data
    }
    
    try:
        expected_challenge = session.get('webauthn_challenge')
        expected_origin = ORIGIN
        expected_rp_id = RP_ID
        
        credential = RegistrationCredential.parse_raw(json.dumps(credential_data))
        
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=expected_origin,
            expected_rp_id=expected_rp_id,
        )
        
        if verification.verified:
            # Store credential
            new_credential = WebAuthnCredential(
                user_id=current_user.id,
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count
            )
            db.session.add(new_credential)
            db.session.commit()
            
            transaction_data['success'] = True
            transaction_data['credential_id'] = base64.urlsafe_b64encode(verification.credential_id).decode()
            
            log_authentication(
                current_user.id, 'passkey', True, transaction_data,
                request.remote_addr, request.headers.get('User-Agent')
            )
            
            return jsonify({'verified': True})
        else:
            transaction_data['success'] = False
            transaction_data['error'] = 'Verification failed'
            
            log_authentication(
                current_user.id, 'passkey', False, transaction_data,
                request.remote_addr, request.headers.get('User-Agent')
            )
            
            return jsonify({'verified': False, 'error': 'Registration verification failed'})
            
    except Exception as e:
        transaction_data['success'] = False
        transaction_data['error'] = str(e)
        
        log_authentication(
            current_user.id, 'passkey', False, transaction_data,
            request.remote_addr, request.headers.get('User-Agent')
        )
        
        return jsonify({'verified': False, 'error': str(e)})

@app.route('/webauthn/authenticate/begin', methods=['POST'])
def webauthn_auth_begin():
    email = request.get_json().get('email')
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    credentials = WebAuthnCredential.query.filter_by(user_id=user.id).all()
    
    if not credentials:
        return jsonify({'error': 'No credentials found'}), 404
    
    allow_credentials = []
    for cred in credentials:
        allow_credentials.append(
            PublicKeyCredentialDescriptor(id=cred.credential_id)
        )
    
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    
    session['webauthn_challenge'] = options.challenge
    session['webauthn_user_email'] = email
    
    return jsonify({
        'options': {
            'challenge': base64.urlsafe_b64encode(options.challenge).decode(),
            'rpId': options.rp_id,
            'allowCredentials': [{'id': base64.urlsafe_b64encode(cred.id).decode(), 'type': cred.type} for cred in options.allow_credentials],
            'userVerification': options.user_verification.value,
            'timeout': options.timeout
        }
    })

@app.route('/webauthn/authenticate/complete', methods=['POST'])
def webauthn_auth_complete():
    credential_data = request.get_json()
    email = session.get('webauthn_user_email')
    
    transaction_data = {
        'method': 'passkey',
        'timestamp': datetime.utcnow().isoformat(),
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'email': email,
        'credential_data': credential_data
    }
    
    try:
        user = User.query.filter_by(email=email).first()
        if not user:
            transaction_data['success'] = False
            transaction_data['error'] = 'User not found'
            
            log_authentication(
                None, 'passkey', False, transaction_data,
                request.remote_addr, request.headers.get('User-Agent')
            )
            
            return jsonify({'verified': False, 'error': 'User not found'})
        
        credential_id = base64.urlsafe_b64decode(credential_data['id'])
        stored_credential = WebAuthnCredential.query.filter_by(
            user_id=user.id,
            credential_id=credential_id
        ).first()
        
        if not stored_credential:
            transaction_data['success'] = False
            transaction_data['error'] = 'Credential not found'
            
            log_authentication(
                user.id, 'passkey', False, transaction_data,
                request.remote_addr, request.headers.get('User-Agent')
            )
            
            return jsonify({'verified': False, 'error': 'Credential not found'})
        
        expected_challenge = session.get('webauthn_challenge')
        expected_origin = ORIGIN
        expected_rp_id = RP_ID
        
        credential = AuthenticationCredential.parse_raw(json.dumps(credential_data))
        
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=expected_origin,
            expected_rp_id=expected_rp_id,
            credential_public_key=stored_credential.public_key,
            credential_current_sign_count=stored_credential.sign_count,
        )
        
        if verification.verified:
            # Update sign count
            stored_credential.sign_count = verification.new_sign_count
            db.session.commit()
            
            login_user(user)
            transaction_data['success'] = True
            transaction_data['user_id'] = user.id
            transaction_data['new_sign_count'] = verification.new_sign_count
            
            log_authentication(
                user.id, 'passkey', True, transaction_data,
                request.remote_addr, request.headers.get('User-Agent')
            )
            
            session['last_auth_data'] = transaction_data
            return jsonify({'verified': True, 'redirect': url_for('success')})
        else:
            transaction_data['success'] = False
            transaction_data['error'] = 'Authentication verification failed'
            
            log_authentication(
                user.id, 'passkey', False, transaction_data,
                request.remote_addr, request.headers.get('User-Agent')
            )
            
            return jsonify({'verified': False, 'error': 'Authentication verification failed'})
            
    except Exception as e:
        transaction_data['success'] = False
        transaction_data['error'] = str(e)
        
        log_authentication(
            user.id if 'user' in locals() else None, 'passkey', False, transaction_data,
            request.remote_addr, request.headers.get('User-Agent')
        )
        
        return jsonify({'verified': False, 'error': str(e)})

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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

# SCIM Endpoints
@app.route('/scim/v2/Users', methods=['GET'])
def scim_list_users():
    """SCIM endpoint to list users"""
    # Basic authentication check (you might want to add proper SCIM authentication)
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
        'itemsPerPage': count,
        'Resources': scim_users
    }
    
    return jsonify(response)

@app.route('/scim/v2/Users/<user_id>', methods=['GET'])
def scim_get_user(user_id):
    """SCIM endpoint to get a specific user"""
    auth_header = request.headers.get('Authorization', '')
    scim_bearer_token = get_config('scim_bearer_token', '')
    
    if not auth_header.startswith('Bearer ') or auth_header[7:] != scim_bearer_token:
        return jsonify({'detail': 'Authentication failed', 'status': 401}), 401
    
    user = User.query.get_or_404(user_id)
    
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
    
    return jsonify(scim_user)

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

@app.route('/scim/v2/Users/<user_id>', methods=['PUT', 'PATCH'])
def scim_update_user(user_id):
    """SCIM endpoint to update a user"""
    auth_header = request.headers.get('Authorization', '')
    scim_bearer_token = get_config('scim_bearer_token', '')
    
    if not auth_header.startswith('Bearer ') or auth_header[7:] != scim_bearer_token:
        return jsonify({'detail': 'Authentication failed', 'status': 401}), 401
    
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    # Update user fields
    if 'userName' in data:
        user.email = data['userName']
    
    if 'externalId' in data:
        user.external_id = data['externalId']
    
    if 'name' in data:
        name_data = data['name']
        if 'formatted' in name_data:
            user.name = name_data['formatted']
    
    if 'emails' in data and data['emails']:
        user.email = data['emails'][0]['value']
    
    if 'active' in data:
        user.active = data['active']
    
    db.session.commit()
    
    # Return updated user
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
    
    return jsonify(scim_user)

@app.route('/scim/v2/Users/<user_id>', methods=['DELETE'])
def scim_delete_user(user_id):
    """SCIM endpoint to delete a user"""
    auth_header = request.headers.get('Authorization', '')
    scim_bearer_token = get_config('scim_bearer_token', '')
    
    if not auth_header.startswith('Bearer ') or auth_header[7:] != scim_bearer_token:
        return jsonify({'detail': 'Authentication failed', 'status': 401}), 401
    
    user = User.query.get_or_404(user_id)
    
    # Instead of hard delete, mark as inactive
    user.active = False
    db.session.commit()
    
    return '', 204

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

# Admin configuration routes
@app.route('/admin/config')
@login_required
def admin_config():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    # Get all configuration values
    configs = Configuration.query.all()
    config_dict = {config.key: config for config in configs}
    
    return render_template('admin_config.html', configs=config_dict)

@app.route('/admin/config', methods=['POST'])
@login_required
def admin_config_save():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    # Save configuration values
    config_updates = request.get_json()
    
    for key, value in config_updates.items():
        if key.startswith('_'):  # Skip metadata fields
            continue
            
        set_config(key, value, user_id=current_user.id)
    
    return jsonify({'success': True})

@app.context_processor
def inject_version_info():
    """Inject version information into all templates"""
    return dict(
        git_commit=os.getenv('GIT_COMMIT', ''),
        build_date=os.getenv('BUILD_DATE', ''),
        version=os.getenv('VERSION', '1.0.0')
    )

@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)