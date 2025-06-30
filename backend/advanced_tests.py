"""Advanced Edge Case Tests for Cooperativa Activity Logging System

These tests cover extreme edge cases for input validation, security, concurrency, 
time-based scenarios, permissions, and search functionality.
"""

import pytest
import json
import time
import sqlite3
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from main import app
from activity_logger import init_activity_log_table, log_activity, get_activities

# Setup test client
client = TestClient(app)

# Test fixtures from test_main.py would be imported/shared in a real setup

#############################################
# Input Validation & Payload Oddity Testing #
#############################################

@pytest.mark.parametrize("payload", [
    # Empty values
    {"activity_type": "", "details": {}},
    # Wrong data types
    {"activity_type": 123, "details": "not_an_object"},
    # Oversized payload
    {"activity_type": "big_payload", "details": {"large_field": "x" * 10000}},
    # Unicode and special characters
    {"activity_type": "unicode_test", "details": {"text": "😀🌍👨‍👩‍👧‍👦こんにちは世界العربية"}},
    # Injection patterns
    {"activity_type": "injection_test", "details": {"field": "' OR '1'='1"}},
    # Nested structures
    {"activity_type": "nested", "details": {"level1": {"level2": {"level3": {"deep": "value"}}}}},
])
def test_input_validation(payload, temp_db):
    """Test various input validation scenarios"""
    # Login first
    login_response = client.post(
        "/token",
        data={"username": "testadmin", "password": "password"}
    )
    token = login_response.json()["access_token"]
    
    # Try the payload
    response = client.post(
        "/api/activity-log",
        json=payload,
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # We expect either a successful log or a validation error
    # Not a server crash (500) or other unexpected behavior
    assert response.status_code in [201, 400, 422]
    
    # If it was successful, verify the log was stored correctly
    if response.status_code == 201:
        # Try to retrieve the log
        logs_response = client.get(
            "/api/activity-logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert logs_response.status_code == 200
        
        # We should find our log
        data = logs_response.json()
        if "activity_type" in payload and isinstance(payload["activity_type"], str) and payload["activity_type"]:
            found = False
            for log in data["logs"]:
                if log["activity_type"] == payload["activity_type"]:
                    found = True
                    break
            assert found, "Log with the given activity type was not found"

###############################
# Security & Access Edge Cases #
###############################

def test_invalid_token_structure():
    """Test behavior with structurally invalid tokens"""
    invalid_tokens = [
        "not.a.token",
        "invalid.token.format.with.too.many.segments",
        "" # Empty token
    ]
    
    for invalid_token in invalid_tokens:
        response = client.get(
            "/api/activity-logs",
            headers={"Authorization": f"Bearer {invalid_token}"}
        )
        # Should be unauthorized
        assert response.status_code == 401

def test_tampered_token():
    """Simulate token tampering by modifying parts of a valid token"""
    # Get a valid token first
    login_response = client.post(
        "/token",
        data={"username": "testadmin", "password": "password"}
    )
    valid_token = login_response.json()["access_token"]
    
    # Tamper with the token - change middle segment (payload)
    # This is a simplistic simulation - in a real JWT the signature would invalidate it
    token_parts = valid_token.split('.')
    if len(token_parts) >= 2:
        token_parts[1] = "tampered_payload_segment"
        tampered_token = '.'.join(token_parts)
        
        response = client.get(
            "/api/activity-logs",
            headers={"Authorization": f"Bearer {tampered_token}"}
        )
        # Should be unauthorized due to invalid signature
        assert response.status_code == 401

def test_role_escalation_attempt():
    """Test that regular users cannot access admin endpoints"""
    # Login as a regular user
    login_response = client.post(
        "/token",
        data={"username": "testuser", "password": "password"}
    )
    
    if login_response.status_code == 200:
        token = login_response.json()["access_token"]
        
        # Try to access admin-only logs endpoint
        response = client.get(
            "/api/activity-logs",
            headers={"Authorization": f"Bearer {token}"}
        )
        # Should be forbidden
        assert response.status_code in [401, 403]
        
        # Try to impersonate another user in activity log
        activity_data = {
            "user_id": "admin",  # Attempting to log as someone else
            "activity_type": "impersonation_attempt",
            "details": {}
        }
        
        response = client.post(
            "/api/activity-log",
            json=activity_data,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Should succeed but override the user_id to match the token
        if response.status_code == 201:
            # Admin logs in to check
            admin_login = client.post(
                "/token",
                data={"username": "testadmin", "password": "password"}
            )
            admin_token = admin_login.json()["access_token"]
            
            logs_response = client.get(
                "/api/activity-logs?activity_type=impersonation_attempt",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            logs = logs_response.json()["logs"]
            
            # The user_id should be testuser, not admin
            for log in logs:
                if log["activity_type"] == "impersonation_attempt":
                    assert log["user_id"] == "testuser", "User impersonation should not be possible"

#################################
# Time-Based Scenario Testing    #
#################################

def test_timestamp_manipulation():
    """Test behavior with manipulated timestamps"""
    with patch('activity_logger.log_activity') as mock_log:
        # Mock the function to test custom timestamps
        mock_log.return_value = 999  # Fake ID
        
        # Test future timestamp
        future_time = (datetime.now() + timedelta(days=30)).isoformat()
        log_activity(
            user_id="testuser",
            activity_type="future_timestamp",
            details={"event_time": future_time},
            ip_address="127.0.0.1"
        )
        
        # Verify the call happened with our data
        mock_log.assert_called_with(
            user_id="testuser",
            activity_type="future_timestamp", 
            details={"event_time": future_time},
            ip_address="127.0.0.1"
        )
        
        # Test past timestamp
        past_time = (datetime.now() - timedelta(days=365)).isoformat()
        log_activity(
            user_id="testuser",
            activity_type="past_timestamp",
            details={"event_time": past_time},
            ip_address="127.0.0.1"
        )
        
        # Verify the call happened with our data
        mock_log.assert_called_with(
            user_id="testuser",
            activity_type="past_timestamp", 
            details={"event_time": past_time},
            ip_address="127.0.0.1"
        )

#####################################
# Search & Filtering Oddities       #
#####################################

@pytest.mark.parametrize("query_params", [
    # Edge cases for pagination
    "?limit=0", 
    "?limit=9999999",
    "?offset=-1",
    # Non-existent filters
    "?user_id=no_such_user", 
    "?activity_type=no_such_activity",
    # Case sensitivity checks
    "?user_id=TESTUSER",  # capitals vs lowercase
    "?user_id=testuser&activity_type=TEST_ACTIVITY",
    # Multiple filters
    "?user_id=testuser&activity_type=test_activity&limit=5&offset=10"
])
def test_search_filtering_edge_cases(query_params, temp_db):
    """Test search and filtering with edge cases"""
    # Login as admin
    login_response = client.post(
        "/token",
        data={"username": "testadmin", "password": "password"}
    )
    token = login_response.json()["access_token"]
    
    # Try querying with the edge case params
    response = client.get(
        f"/api/activity-logs{query_params}",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # We expect either a successful response or validation error
    # Not a server crash or 500
    assert response.status_code in [200, 400, 422]
    
    if response.status_code == 200:
        # Check that we got a valid response structure
        data = response.json()
        assert "logs" in data
        assert "total" in data
        assert isinstance(data["logs"], list)
        assert isinstance(data["total"], int)

#####################################
# Concurrent User Activity Testing  #
#####################################

def test_concurrent_user_activity():
    """Test concurrent activity logging from different users"""
    # This would be more intense with a higher number
    # but we keep it small for test runtime
    num_concurrent = 3
    
    def run_user_session(user_index):
        # Login
        if user_index == 0:
            username = "testadmin"
        else:
            username = f"testuser{user_index}"
            
        # For simplicity, all users have same password in test
        login_response = client.post(
            "/token",
            data={"username": username, "password": "password"}
        )
        
        # If login worked (might not for some user indexes)
        if login_response.status_code == 200:
            token = login_response.json()["access_token"]
            
            # Log multiple activities in sequence
            for i in range(3):  # 3 activities per user
                activity_data = {
                    "activity_type": f"concurrent_user_test",
                    "details": {
                        "user_index": user_index,
                        "activity_index": i,
                        "timestamp": datetime.now().isoformat()
                    }
                }
                
                response = client.post(
                    "/api/activity-log",
                    json=activity_data,
                    headers={"Authorization": f"Bearer {token}"}
                )
                
            return username, login_response.status_code
        
        return username, login_response.status_code
    
    # Run concurrent user sessions
    with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
        results = list(executor.map(run_user_session, range(num_concurrent)))
    
    # Check results - for users that could log in, we should see their activities
    successful_users = [username for username, status in results if status == 200]
    
    if successful_users:
        # Login as admin to check logs
        admin_login = client.post(
            "/token",
            data={"username": "testadmin", "password": "password"}
        )
        admin_token = admin_login.json()["access_token"]
        
        response = client.get(
            "/api/activity-logs?activity_type=concurrent_user_test",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        if response.status_code == 200:
            logs = response.json()["logs"]
            
            # There should be 3 activities per successful user
            expected_count = len(successful_users) * 3
            assert len(logs) >= expected_count, f"Expected at least {expected_count} logs from concurrent users"

# Run this file with pytest for advanced testing scenarios
if __name__ == "__main__":
    pytest.main(['-xvs', __file__])
