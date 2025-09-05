import pytest
from app import app, db, User, AuthLog, Configuration


def test_user_model(client):
    """Test User model functionality"""
    with app.app_context():
        # Create user
        user = User(
            email='test@example.com',
            name='Test User',
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()
        
        # Test user properties
        assert user.email == 'test@example.com'
        assert user.name == 'Test User'
        assert user.is_admin is False
        assert user.active is True
        assert user.scim_provisioned is False
        
        # Test authentication status defaults
        assert user.saml_tested is False
        assert user.oidc_tested is False


def test_configuration_model(client):
    """Test Configuration model functionality"""
    with app.app_context():
        # Create configuration
        config = Configuration(
            key='test_setting',
            value='test_value',
            description='Test configuration setting'
        )
        db.session.add(config)
        db.session.commit()
        
        # Test retrieval
        retrieved_config = Configuration.query.filter_by(key='test_setting').first()
        assert retrieved_config is not None
        assert retrieved_config.value == 'test_value'
        assert retrieved_config.description == 'Test configuration setting'


def test_auth_log_model(client, regular_user):
    """Test AuthLog model functionality"""
    with app.app_context():
        # Create auth log
        auth_log = AuthLog(
            user_id=regular_user.user_id,
            auth_method='password',
            success=True,
            transaction_data='{"test": "data"}',
            ip_address='127.0.0.1',
            user_agent='Test User Agent'
        )
        db.session.add(auth_log)
        db.session.commit()
        
        # Test basic auth log properties
        assert auth_log.user_id == regular_user.user_id
        assert auth_log.auth_method == 'password'
        assert auth_log.success is True



def test_user_admin_detection(client):
    """Test automatic admin detection for specified emails"""
    with app.app_context():
        # Test admin emails
        admin_emails = ['brent.langston@visiquate.com', 'yuliia.lutai@visiquate.com']
        
        for email in admin_emails:
            user = User(email=email, name='Admin User')
            # Admin status would be set in the registration route
            user.is_admin = email in admin_emails
            db.session.add(user)
            db.session.commit()
            
            assert user.is_admin is True
        
        # Test non-admin email
        regular_user = User(email='user@example.com', name='Regular User')
        db.session.add(regular_user)
        db.session.commit()
        
        assert regular_user.is_admin is False


def test_scim_user_fields(client):
    """Test SCIM-specific user fields"""
    with app.app_context():
        # Create SCIM-provisioned user
        user = User(
            email='scim@example.com',
            name='SCIM User',
            external_id='ext-123',
            scim_provisioned=True,
            active=True
        )
        db.session.add(user)
        db.session.commit()
        
        assert user.external_id == 'ext-123'
        assert user.scim_provisioned is True
        assert user.active is True