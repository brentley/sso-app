import json
import pytest
from app import app, db, User, Configuration, set_config, get_config


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
    """Test the index page redirects logged-out users to login"""
    response = client.get('/')
    assert response.status_code == 302
    assert response.location.endswith('/login')


def test_login_page(client):
    """Test the login page loads"""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'VisiQuate SSO Testing Guide' in response.data
    assert b'Login Method #1' in response.data
    assert b'Login Method #2' in response.data


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


def test_passkey_oauth_provider_configuration(client):
    """Test that passkey OAuth provider is properly configured"""
    # Test accessing passkey OAuth login route
    response = client.get('/oauth/login/passkey-test-app')
    
    # Should redirect to OAuth provider (or return 302 for redirect)
    assert response.status_code == 302
    
    # The redirect location should contain the passkey test app URL
    assert 'id.visiquate.com' in response.location


def test_user_auth_status_tracking(client):
    """Test that authentication status is tracked properly"""
    # Register user (no password needed now)
    client.post('/register', data={
        'name': 'Test User',
        'email': 'test@example.com'
    })
    
    # Check initial state - no authentication methods tested yet
    with app.app_context():
        user = User.query.filter_by(email='test@example.com').first()
        assert user.saml_tested is False
        assert user.oidc_tested is False
        assert user.passkey_tested is False


def test_user_passkey_metadata_methods(client):
    """Test user passkey metadata getter methods"""
    with app.app_context():
        # Create user with passkey metadata
        user = User(
            email='passkey@example.com',
            name='Passkey User',
            passkey_tested=True,
            passkey_metadata='{"groups": ["admin", "users"], "provider": "passkey-test-app", "timestamp": "2024-01-01T12:00:00Z"}'
        )
        db.session.add(user)
        db.session.commit()
        
        # Test passkey metadata parsing
        passkey_metadata = user.get_passkey_metadata_dict()
        assert passkey_metadata is not None
        assert 'groups' in passkey_metadata
        assert 'admin' in passkey_metadata['groups']
        assert passkey_metadata['provider'] == 'passkey-test-app'
        
        # Test with empty metadata
        user.passkey_metadata = None
        passkey_metadata = user.get_passkey_metadata_dict()
        assert passkey_metadata == {}
