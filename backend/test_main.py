import pytest
from fastapi.testclient import TestClient
import json
from main import app
from activity_logger import init_activity_log_table, log_activity, get_activities
import os
import tempfile
import sqlite3

# Setup test client
client = TestClient(app)

# Create a temporary database for testing
@pytest.fixture(scope="module")
def temp_db():
    # Create a temporary file for the test database
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["TEST_DB_PATH"] = db_path
    
    # Setup test database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create necessary tables for testing
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        activity_type TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        hashed_password TEXT NOT NULL,
        full_name TEXT,
        disabled BOOLEAN DEFAULT 0,
        role TEXT DEFAULT 'user'
    )''')
    
    # Insert a test admin user
    cursor.execute(
        "INSERT INTO users (username, email, hashed_password, full_name, role) VALUES (?, ?, ?, ?, ?)",
        ("testadmin", "admin@test.com", "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW", "Test Admin", "admin")
    )
    
    # Insert a test regular user
    cursor.execute(
        "INSERT INTO users (username, email, hashed_password, full_name, role) VALUES (?, ?, ?, ?, ?)",
        ("testuser", "user@test.com", "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW", "Test User", "user")
    )
    
    conn.commit()
    conn.close()
    
    yield db_path
    
    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)

# Test authentication endpoints
def test_login_success(temp_db):
    response = client.post(
        "/token",
        data={"username": "testadmin", "password": "password"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_failed(temp_db):
    response = client.post(
        "/token",
        data={"username": "testadmin", "password": "wrong_password"}
    )
    assert response.status_code == 401

# Test activity logging functionality
def test_log_activity(temp_db):
    # Use the direct function to log an activity
    log_id = log_activity(
        user_id="testuser",
        activity_type="test_activity",
        details={"test": "data", "value": 123},
        ip_address="127.0.0.1"
    )
    
    # Verify the activity was logged
    assert log_id is not None and log_id > 0
    
    # Retrieve the logged activity
    activities = get_activities(user_id="testuser", activity_type="test_activity")
    
    # Verify the activity data
    assert len(activities) > 0
    assert activities[0]["user_id"] == "testuser"
    assert activities[0]["activity_type"] == "test_activity"
    assert activities[0]["ip_address"] == "127.0.0.1"
    assert activities[0]["details"]["test"] == "data"
    assert activities[0]["details"]["value"] == 123

# Test API endpoint for activity logging
def test_record_activity_api():
    # First login to get a token
    login_response = client.post(
        "/token",
        data={"username": "testadmin", "password": "password"}
    )
    token = login_response.json()["access_token"]
    
    # Use the API to log an activity
    activity_data = {
        "user_id": "system",  # This will be overridden by the API
        "activity_type": "api_test",
        "details": {"source": "test"}
    }
    
    response = client.post(
        "/api/activity-log",
        json=activity_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Verify the response
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["status"] == "recorded"

# Test retrieving activity logs
def test_get_activity_logs():
    # First login as admin to get a token
    login_response = client.post(
        "/token",
        data={"username": "testadmin", "password": "password"}
    )
    token = login_response.json()["access_token"]
    
    # Query for activity logs
    response = client.get(
        "/api/activity-logs",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Verify response
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data
    assert "total" in data
    
    # Test filtering
    response = client.get(
        "/api/activity-logs?user_id=testuser&activity_type=test_activity",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Verify filtered response
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data
    
    # If there are logs, verify they match our filters
    if data["total"] > 0:
        for log in data["logs"]:
            assert log["user_id"] == "testuser"
            assert log["activity_type"] == "test_activity"

# Test unauthorized access attempts
def test_unauthorized_access():
    # Try to access activity logs without authentication
    response = client.get("/api/activity-logs")
    assert response.status_code in [401, 403]  # Either unauthorized or forbidden
    
    # Try with a regular user (not admin)
    login_response = client.post(
        "/token",
        data={"username": "testuser", "password": "password"}
    )
    
    if login_response.status_code == 200:
        token = login_response.json()["access_token"]
        response = client.get(
            "/api/activity-logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        # Should be forbidden for non-admin users
        assert response.status_code in [401, 403]

# Test edge cases
def test_missing_fields():
    """Test logging activity with missing required fields"""
    # First login to get a token
    login_response = client.post(
        "/token",
        data={"username": "testadmin", "password": "password"}
    )
    token = login_response.json()["access_token"]
    
    # Test missing activity_type
    activity_data = {
        "details": {"source": "test"}
    }
    
    response = client.post(
        "/api/activity-log",
        json=activity_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Should fail validation
    assert response.status_code == 422

def test_malformed_filters():
    """Test activity log retrieval with malformed filters"""
    # First login as admin to get a token
    login_response = client.post(
        "/token",
        data={"username": "testadmin", "password": "password"}
    )
    token = login_response.json()["access_token"]
    
    # Test with invalid limit (negative)
    response = client.get(
        "/api/activity-logs?limit=-10",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Should fail validation
    assert response.status_code in [400, 422]
    
def test_token_expiry():
    """Test behavior with expired or malformed tokens"""
    # Test with malformed token
    response = client.get(
        "/api/activity-logs",
        headers={"Authorization": "Bearer invalid.token.format"}
    )
    
    # Should be unauthorized
    assert response.status_code == 401
    
    # Test with expired token would require mocking JWT time validation
    # This is a placeholder for that test

def test_schema_versioning():
    """Test compatibility with schema versioning"""
    # Log activity with a version field
    log_id = log_activity(
        user_id="testuser",
        activity_type="test_versioned_activity",
        details={"_schema_version": "1.0", "data": "test"}, 
        ip_address="127.0.0.1"
    )
    
    # Verify the activity was logged with schema version
    assert log_id is not None and log_id > 0
    
    # Retrieve the logged activity
    activities = get_activities(activity_type="test_versioned_activity")
    
    # Verify the schema version was preserved
    assert len(activities) > 0
    assert activities[0]["details"]["_schema_version"] == "1.0"
    
# Concurrent logging test
def test_concurrent_logging():
    """Simple simulation of concurrent logging"""
    import threading
    
    # Function to log activities in a thread
    def log_thread_activity(thread_id):
        log_activity(
            user_id=f"thread_{thread_id}",
            activity_type="concurrent_test",
            details={"thread": thread_id},
            ip_address="127.0.0.1"
        )
    
    # Create and start multiple threads
    threads = []
    for i in range(5):  # Test with 5 concurrent logs
        t = threading.Thread(target=log_thread_activity, args=(i,))
        threads.append(t)
        t.start()
    
    # Wait for all threads to finish
    for t in threads:
        t.join()
    
    # Verify all activities were logged
    activities = get_activities(activity_type="concurrent_test")
    assert len(activities) == 5
