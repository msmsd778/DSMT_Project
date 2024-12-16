import requests
import pytest

BASE_URL = "http://localhost:5000"

@pytest.fixture
def test_user():
    return {"username": "testuser", "password": "testpassword"}

def test_register_user(test_user):
    # Attempt to register a new user
    response = requests.post(f"{BASE_URL}/register", json=test_user)
    assert response.status_code == 201 or response.status_code == 400
    # If user already exists, status will be 400
    
def test_login_user(test_user):
    # Attempt to login with the correct password
    response = requests.post(f"{BASE_URL}/login", json=test_user)
    assert response.status_code == 200, "Expected successful login"
    data = response.json()
    assert data.get("message") == "Login successful."

    # Attempt to login with an incorrect password
    wrong_credentials = {"username": test_user["username"], "password": "wrongpass"}
    response = requests.post(f"{BASE_URL}/login", json=wrong_credentials)
    assert response.status_code == 401, "Expected invalid credentials error"
    data = response.json()
    assert data.get("error") == "Invalid credentials."
