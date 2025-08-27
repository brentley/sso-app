import os
import json
import base64
import secrets
import uuid
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
START_TIME = time.time()

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    return config

def log_authentication(user_id, auth_method, success, transaction_data, ip_address, user_agent):
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
@app.route('/saml/login')
def saml_login():
    """SAML authentication endpoint"""
    # For now, redirect back to login with a message
    flash('SAML authentication not yet configured. Please configure SAML settings in admin panel.')
    return redirect(url_for('login'))

@app.route('/oauth/login/<provider>')
def oauth_login(provider):
    """OIDC/OAuth authentication endpoint"""
    # For now, redirect back to login with a message
    valid_providers = ['google', 'microsoft', 'authentik']
    if provider not in valid_providers:
        flash('Invalid OAuth provider')
        return redirect(url_for('login'))
    
    flash(f'{provider.title()} OAuth authentication not yet configured. Please configure OAuth settings in admin panel.')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

@app.context_processor
def inject_version_info():
    return dict(
        git_commit=BUILD_INFO['git_commit_short'],
        build_date=BUILD_INFO['build_date'],
        version=BUILD_INFO['version'],
        build_number=BUILD_INFO['build_number']
    )

# Initialize database on first request
@app.before_request
def create_tables():
    if not hasattr(create_tables, 'done'):
        db.create_all()
        create_tables.done = True

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False)
