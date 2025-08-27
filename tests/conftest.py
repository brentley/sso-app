import pytest
import os
import tempfile
import time
from app import app, db


@pytest.fixture
def client():
    # Create a temporary database file
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{app.config['DATABASE']}"
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        # Clean up database session after each test
        with app.app_context():
            db.session.remove()
            db.drop_all()

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


@pytest.fixture
def admin_user(client):
    """Create an admin user for testing"""
    from app import User
    
    with app.app_context():
        # Use unique email with timestamp to avoid conflicts
        unique_email = f'admin-{int(time.time() * 1000)}@test.com'
        
        admin = User(
            email=unique_email,
            name='Test Admin',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        
        # Access the id while still in session to avoid DetachedInstanceError
        admin_id = admin.id
        admin.admin_id = admin_id  # Store id as attribute
        return admin


@pytest.fixture
def regular_user(client):
    """Create a regular user for testing"""
    from app import User
    
    with app.app_context():
        # Use unique email with timestamp to avoid conflicts
        unique_email = f'user-{int(time.time() * 1000)}@test.com'
        
        user = User(
            email=unique_email,
            name='Test User',
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()
        
        # Access the id while still in session to avoid DetachedInstanceError
        user_id = user.id
        user.user_id = user_id  # Store id as attribute
        return user