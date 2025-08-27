import json
import pytest
from app import app, User, Configuration, set_config, get_config


def test_health_endpoint(client):
    """Test the health endpoint returns correct status"""
    response = client.get('/health')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'status' in data
    assert 'service' in data
    assert 'version' in data
    assert 'checks' in data
    assert data['service'] == 'sso-authentication-test'


def test_index_page(client):
    """Test the index page loads"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'SSO Authentication Testing' in response.data


def test_login_page(client):
    """Test the login page loads"""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Authentication Testing' in response.data
    assert b'SAML Authentication' in response.data
    assert b'OIDC Authentication' in response.data
    assert b'Password Authentication' in response.data
    assert b'Passkey Authentication' in response.data


def test_register_page(client):
    """Test the register page loads"""
    response = client.get('/register')
    assert response.status_code == 200
    assert b'Register New Account' in response.data


def test_user_registration(client):
    """Test user registration functionality"""
    response = client.post('/register', data={
        'name': 'Test User',
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code == 302  # Redirect after successful registration
    
    # Check user was created
    with app.app_context():
        user = User.query.filter_by(email='test@example.com').first()
        assert user is not None
        assert user.name == 'Test User'
        assert not user.is_admin


def test_admin_user_registration(client):
    """Test admin user gets admin privileges automatically"""
    response = client.post('/register', data={
        'name': 'Brent Langston',
        'email': 'brent.langston@visiquate.com',
        'password': 'password123'
    })
    assert response.status_code == 302
    
    # Check user has admin privileges
    with app.app_context():
        user = User.query.filter_by(email='brent.langston@visiquate.com').first()
        assert user is not None
        assert user.is_admin


def test_password_authentication(client):
    """Test password authentication"""
    # First register a user
    client.post('/register', data={
        'name': 'Test User',
        'email': 'test@example.com',
        'password': 'password123'
    })
    
    # Test successful login
    response = client.post('/password_auth', data={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code == 302  # Redirect to success page
    
    # Test failed login
    response = client.post('/password_auth', data={
        'email': 'test@example.com',
        'password': 'wrongpassword'
    })
    assert response.status_code == 302  # Redirect back to login


def test_configuration_management(client):
    """Test configuration get/set functionality"""
    with app.app_context():
        # Test setting configuration
        set_config('test_key', 'test_value', 'Test configuration')
        
        # Test getting configuration
        value = get_config('test_key')
        assert value == 'test_value'
        
        # Test default value
        default_value = get_config('nonexistent_key', 'default')
        assert default_value == 'default'


def test_admin_access_control(client, admin_user, regular_user):
    """Test admin access control"""
    # Test regular user cannot access admin pages
    with client.session_transaction() as sess:
        sess['user_id'] = str(regular_user.user_id)
    
    response = client.get('/admin')
    assert response.status_code == 302  # Redirect due to no admin access
    
    # Test admin user can access admin pages
    with client.session_transaction() as sess:
        sess['user_id'] = str(admin_user.admin_id)
    
    response = client.get('/admin')
    assert response.status_code == 200
    assert b'Admin Dashboard' in response.data


def test_scim_authentication(client):
    """Test SCIM endpoint authentication"""
    # Test without token
    response = client.get('/scim/v2/Users')
    assert response.status_code == 401
    
    # Set up SCIM token
    with app.app_context():
        set_config('scim_bearer_token', 'test-token')
    
    # Test with wrong token
    response = client.get('/scim/v2/Users', headers={
        'Authorization': 'Bearer wrong-token'
    })
    assert response.status_code == 401
    
    # Test with correct token
    response = client.get('/scim/v2/Users', headers={
        'Authorization': 'Bearer test-token'
    })
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'schemas' in data
    assert 'Resources' in data


def test_scim_service_provider_config(client):
    """Test SCIM service provider configuration endpoint"""
    response = client.get('/scim/v2/ServiceProviderConfig')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'schemas' in data
    assert 'authenticationSchemes' in data


def test_scim_user_creation(client):
    """Test SCIM user creation"""
    with app.app_context():
        set_config('scim_bearer_token', 'test-token')
    
    scim_user_data = {
        'userName': 'scim.user@example.com',
        'externalId': 'ext-123',
        'name': {
            'formatted': 'SCIM User'
        },
        'emails': [{
            'value': 'scim.user@example.com',
            'primary': True
        }],
        'active': True
    }
    
    response = client.post('/scim/v2/Users',
                          headers={'Authorization': 'Bearer test-token'},
                          data=json.dumps(scim_user_data),
                          content_type='application/json')
    
    assert response.status_code == 201
    
    data = json.loads(response.data)
    assert data['userName'] == 'scim.user@example.com'
    assert data['externalId'] == 'ext-123'
    
    # Verify user was created in database
    with app.app_context():
        user = User.query.filter_by(email='scim.user@example.com').first()
        assert user is not None
        assert user.scim_provisioned is True


def test_user_auth_status_tracking(client):
    """Test that authentication status is tracked properly"""
    # Register user
    client.post('/register', data={
        'name': 'Test User',
        'email': 'test@example.com',
        'password': 'password123'
    })
    
    # Login with password
    client.post('/password_auth', data={
        'email': 'test@example.com',
        'password': 'password123'
    })
    
    # Check that password_tested is marked as True
    with app.app_context():
        user = User.query.filter_by(email='test@example.com').first()
        assert user.password_tested is True
        assert user.saml_tested is False
        assert user.oidc_tested is False
        assert user.passkey_tested is False