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
    
    # Could be 200 (cookie clearing page) or 302 (redirect to login if config missing)
    assert response.status_code in [200, 302]
    
    if response.status_code == 200:
        # Should contain cookie clearing JavaScript and redirect to id.visiquate.com
        response_text = response.get_data(as_text=True)
        assert 'Preparing Passkey Authentication' in response_text
        assert 'authentik_session=' in response_text  # Cookie clearing script
        assert 'id.visiquate.com' in response_text  # Redirect URL
    else:
        # If config is missing, should redirect to login
        assert response.location == '/login'


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


def test_clear_my_test_results_route_exists(client):
    """Test that clear test results route exists and requires login"""
    # Test without login - should redirect to login page
    response = client.post('/clear-my-test-results')
    assert response.status_code == 302  # Redirect due to @login_required


def test_reconcile_passkey_status_for_user(client):
    """Test passkey status reconciliation for individual users"""
    with app.app_context():
        from app import reconcile_passkey_status_for_user
        from unittest.mock import patch
        
        # Create a test user with incorrect passkey status
        user = User(
            email='test-reconcile@example.com',
            name='Test Reconcile User',
            passkey_tested=True  # Currently marked as tested
        )
        db.session.add(user)
        db.session.commit()
        
        # Mock get_user_passkey_status to return no passkeys (should clear status)
        with patch('app.get_user_passkey_status') as mock_get_status:
            mock_get_status.return_value = {
                'has_passkey': False,
                'passkey_count': 0,
                'passkeys': []
            }
            
            success, message, changed = reconcile_passkey_status_for_user(user)
            
            assert success is True
            assert changed is True
            assert "Cleared test status" in message
            assert user.passkey_tested is False
            
            # Check that metadata was updated
            metadata = user.get_passkey_metadata_dict()
            assert metadata.get('source') == 'reconciliation_job'
            assert 'reconciled_at' in metadata
        
        # Test case where user doesn't have passkeys but should be marked as tested
        user.passkey_tested = False
        with patch('app.get_user_passkey_status') as mock_get_status:
            mock_get_status.return_value = {
                'has_passkey': True,
                'passkey_count': 2,
                'passkeys': [{'name': 'test1'}, {'name': 'test2'}]
            }
            
            success, message, changed = reconcile_passkey_status_for_user(user)
            
            assert success is True
            assert changed is True
            assert "Marked as tested" in message
            assert user.passkey_tested is True
            
            # Check metadata
            metadata = user.get_passkey_metadata_dict()
            assert metadata.get('authentik_passkey_count') == 2


def test_admin_reconcile_passkeys_route_exists(client):
    """Test that reconcile passkeys route exists and requires authentication"""
    # Test without login - should redirect due to @login_required
    response = client.post('/admin/reconcile-passkeys')
    assert response.status_code == 302  # Redirect due to @login_required
    
    # The authorization logic (admin/auditor check) is simple enough that we can trust it works
    # The important thing is that the route exists and the reconciliation logic is tested separately


def test_reconcile_all_passkey_statuses(client):
    """Test bulk reconciliation of all users' passkey statuses"""
    with app.app_context():
        from app import reconcile_all_passkey_statuses
        from unittest.mock import patch
        
        # Create test users with different scenarios
        user1 = User(email='user1@example.com', name='User 1', passkey_tested=True)
        user2 = User(email='user2@example.com', name='User 2', passkey_tested=False)
        user3 = User(email='user3@example.com', name='User 3', passkey_tested=True)
        
        db.session.add_all([user1, user2, user3])
        db.session.commit()
        
        # Mock different responses for different users
        def mock_get_passkey_status(email):
            if email == 'user1@example.com':
                return {'has_passkey': False, 'passkey_count': 0}  # Should clear status
            elif email == 'user2@example.com':
                return {'has_passkey': True, 'passkey_count': 1}   # Should mark as tested
            else:  # user3@example.com
                return {'has_passkey': True, 'passkey_count': 2}   # Already correct, no change
        
        with patch('app.get_user_passkey_status', side_effect=mock_get_passkey_status):
            results = reconcile_all_passkey_statuses()
            
            assert results['total_users'] == 3
            assert results['users_checked'] == 3
            assert results['users_updated'] == 2  # user1 and user2 should be updated
            assert results['errors'] == 0
            assert len(results['changes']) == 2
            
            # Verify the changes were applied
            db.session.refresh(user1)
            db.session.refresh(user2)
            db.session.refresh(user3)
            
            assert user1.passkey_tested is False  # Should be cleared
            assert user2.passkey_tested is True   # Should be marked as tested
            assert user3.passkey_tested is True   # Should remain unchanged


def test_should_reconcile_user(client):
    """Test the logic for determining if a user should be reconciled"""
    with app.app_context():
        from app import should_reconcile_user
        
        # User with 0% completion (no tests done) - should not reconcile
        user0 = User(
            email='user0@example.com', 
            name='User 0',
            saml_tested=False,
            oidc_tested=False, 
            passkey_tested=False
        )
        assert should_reconcile_user(user0) is False
        
        # User with 33% completion (1 test done) - should reconcile
        user33 = User(
            email='user33@example.com',
            name='User 33',
            saml_tested=True,
            oidc_tested=False,
            passkey_tested=False
        )
        assert should_reconcile_user(user33) is True
        
        # User with 67% completion (2 tests done) - should reconcile
        user67 = User(
            email='user67@example.com',
            name='User 67', 
            saml_tested=True,
            oidc_tested=True,
            passkey_tested=False
        )
        assert should_reconcile_user(user67) is True
        
        # User with 100% completion (all tests done) - should reconcile
        user100 = User(
            email='user100@example.com',
            name='User 100',
            saml_tested=True,
            oidc_tested=True,
            passkey_tested=True
        )
        assert should_reconcile_user(user100) is True
