import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'python_app'))

from app import app  # ✅ Works now

def test_home():
    client = app.test_client()
    response = client.get('/')
    assert response.status_code == 200
    assert b"Policy as Code" in response.data
