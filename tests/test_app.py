import sys, os
# ensure project root is on sys.path for pytest/CI
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from models import db
import pytest

@pytest.fixture
def client():
    # Create app with testing config
    test_config = {
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'
    }
    app = create_app(test_config=test_config)
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_index(client):
    rv = client.get('/')
    assert rv.status_code == 200
    assert b'Welcome to Task Manager' in rv.data

def test_register_page_loads(client):
    rv = client.get('/register')
    assert rv.status_code == 200
    assert b'Register' in rv.data

def test_login_page_loads(client):
    rv = client.get('/login')
    assert rv.status_code == 200
    assert b'Login' in rv.data
