import pytest
import os
import tempfile
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

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


@pytest.fixture
def admin_user(client):
    """Create an admin user for testing"""
    from app import User
    
    with app.app_context():
        # Check if user already exists
        existing_admin = User.query.filter_by(email='brent.langston@visiquate.com').first()
        if existing_admin:
            # Refresh the object to make sure it's attached to current session
            db.session.refresh(existing_admin)
            return existing_admin
            
        admin = User(
            email='brent.langston@visiquate.com',
            name='Brent Langston',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        # Refresh to ensure it's properly attached
        db.session.refresh(admin)
        return admin


@pytest.fixture
def regular_user(client):
    """Create a regular user for testing"""
    from app import User
    
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter_by(email='user@example.com').first()
        if existing_user:
            # Refresh the object to make sure it's attached to current session
            db.session.refresh(existing_user)
            return existing_user
            
        user = User(
            email='user@example.com',
            name='Test User',
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()
        # Refresh to ensure it's properly attached
        db.session.refresh(user)
        return user