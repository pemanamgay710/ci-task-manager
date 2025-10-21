import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
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