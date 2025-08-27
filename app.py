import os
import json
import base64
import secrets
import uuid
import time
from datetime import datetime, timedelta
from flask import Flask
from sqlalchemy import text
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

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
    auth_method = db.Column(db.String(20), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    transaction_data = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
        'version': os.getenv('VERSION', '1.0.0'),
        'commit': os.getenv('GIT_COMMIT', 'unknown')[:7],
        'build_date': os.getenv('BUILD_DATE', 'unknown'),
        'uptime': int(time.time() - START_TIME),
        'environment': os.getenv('ENVIRONMENT', 'production'),
        'checks': {}
    }
    
    try:
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

@app.context_processor
def inject_version_info():
    return dict(
        git_commit=os.getenv('GIT_COMMIT', ''),
        build_date=os.getenv('BUILD_DATE', ''),
        version=os.getenv('VERSION', '1.0.0')
    )

# Database initialization will happen automatically

if __name__ == '__main__':
    app.run(debug=True)

# Initialize database on first request
@app.before_request
def create_tables():
    if not hasattr(create_tables, 'done'):
        db.create_all()
        create_tables.done = True
app.run(host="0.0.0.0", port=5000, debug=False)
