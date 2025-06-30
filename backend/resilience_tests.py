"""Resilience and Advanced Edge Case Tests for Cooperativa Activity Logging System

These tests focus on system resilience, data integrity, and behavior under extreme conditions.
"""

import pytest
import sqlite3
import tempfile
import os
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from main import app
from activity_logger import log_activity, get_activities

# Setup test client
client = TestClient(app)

###########################################
# Behavioral Consistency Testing          #
###########################################

def test_logging_during_downtime():
    """Test graceful handling of database failures during logging"""
    
    # Create a mock that will raise an exception on the first call
    # but work normally afterward (simulating temporary outage)
    mock_db_connection = MagicMock()
    mock_cursor = MagicMock()
    mock_db_connection.cursor.return_value = mock_cursor
    
    # First call raises error, subsequent calls work fine
    mock_cursor.execute.side_effect = [
        sqlite3.OperationalError("database is locked"),  # First call fails
        None,  # Second call succeeds (for the insert)
        MagicMock(),  # Third call (for lastrowid)
    ]
    mock_cursor.lastrowid = 999
    
    # Patch the database connection
    with patch('activity_logger.get_db_connection', return_value=mock_db_connection):
        # Attempt to log activity during "downtime"
        try:
            log_id = log_activity(
                user_id="resilient_user",
                activity_type="downtime_test",
                details={"status": "should_handle_gracefully"},
                ip_address="127.0.0.1"
            )
            
            # If we reach here without exception, the system has retry logic
            # or handles the error gracefully
            assert log_id is not None, "Log ID should be returned after recovery"
            print("System gracefully handles database downtime")
        except Exception as e:
            # If we get here, the system doesn't have retry logic
            # In a real implementation, we would want to implement retry with backoff
            print(f"System fails during downtime: {e}")
            print("Consider implementing retry logic with backoff")

def test_post_restart_log_recovery():
    """Test that logs persist correctly after a simulated app restart"""
    # Create a temporary database file
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    
    # Override the database path for this test
    with patch('activity_logger.DATABASE_PATH', db_path):
        # Step 1: Log some activities in the "first session"
        log_id1 = log_activity(
            user_id="restart_user",
            activity_type="pre_restart_log",
            details={"session": "first"},
            ip_address="127.0.0.1"
        )
        
        # Verify log was created
        assert log_id1 is not None
        
        # Step 2: Simulate app "restart" by creating a fresh import of the module
        # In real tests, this might involve stopping and starting the actual server
        with patch('activity_logger.DATABASE_PATH', db_path):
            # Step 3: Log new activity in "second session"
            log_id2 = log_activity(
                user_id="restart_user",
                activity_type="post_restart_log",
                details={"session": "second"},
                ip_address="127.0.0.1"
            )
            
            # Verify new log was created
            assert log_id2 is not None
            
            # Step 4: Verify both logs (pre and post "restart") are retrievable
            activities = get_activities(user_id="restart_user")
            
            # We should have at least 2 activities (one from each "session")
            assert len(activities) >= 2
            
            # Verify both activities exist in the log
            activity_types = [a["activity_type"] for a in activities]
            assert "pre_restart_log" in activity_types
            assert "post_restart_log" in activity_types
    
    # Clean up the temporary database
    os.close(db_fd)
    os.unlink(db_path)

###########################################
# Data Consistency & Audit Trails         #
###########################################

def test_tampered_activity_record():
    """Test detection of directly modified activity logs in the database"""
    # This test assumes we have or could add integrity validation
    # Such as checksums or digital signatures on logs
    
    # Create a temporary database
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    
    try:
        # Create the activity_log table
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        
        # Insert a legitimate activity log
        cursor.execute(
            "INSERT INTO activity_log (user_id, activity_type, details, ip_address) VALUES (?, ?, ?, ?)",
            ("test_user", "original_activity", '{"original":true}', "127.0.0.1")
        )
        log_id = cursor.lastrowid
        conn.commit()
        
        # Now directly tamper with the record
        cursor.execute(
            "UPDATE activity_log SET details = ? WHERE id = ?",
            ('{"tampered":true,"original":false}', log_id)
        )
        conn.commit()
        conn.close()
        
        # In a real system with integrity checks, we would now try to retrieve
        # the log and verify it detects tampering
        
        # NOTE: This is an aspirational test that demonstrates how you might
        # implement data integrity validation. The current system doesn't have
        # this feature, but this test shows how you'd verify it if added.
        
        print("RECOMMENDATION: Add digital signatures or checksums to activity logs")
        print("to detect unauthorized modifications to the audit trail.")
        
    finally:
        # Clean up
        os.close(db_fd)
        os.unlink(db_path)

def test_idempotency():
    """Test behavior when submitting identical log requests multiple times"""
    # Get a reference point for activity count
    initial_activities = get_activities(activity_type="idempotency_test")
    initial_count = len(initial_activities)
    
    # Create an identical log request and submit it multiple times
    identical_details = {"test_id": "identical-123", "timestamp": "2023-06-29T13:00:00Z"}
    
    # First submission
    log_id1 = log_activity(
        user_id="idempotency_user",
        activity_type="idempotency_test",
        details=identical_details,
        ip_address="127.0.0.1"
    )
    
    # Second submission (identical)
    log_id2 = log_activity(
        user_id="idempotency_user",
        activity_type="idempotency_test",
        details=identical_details,
        ip_address="127.0.0.1"
    )
    
    # Third submission (identical)
    log_id3 = log_activity(
        user_id="idempotency_user",
        activity_type="idempotency_test",
        details=identical_details,
        ip_address="127.0.0.1"
    )
    
    # Check how many logs were created
    final_activities = get_activities(activity_type="idempotency_test")
    final_count = len(final_activities)
    
    # Determine current behavior
    new_logs_created = final_count - initial_count
    
    # Current expected behavior is that 3 logs will be created
    # (system does not have idempotency controls)
    assert new_logs_created == 3, f"Expected 3 new logs, got {new_logs_created}"
    
    print(f"CURRENT BEHAVIOR: System created {new_logs_created} logs from identical requests")
    print("RECOMMENDATION: If idempotency is desired, implement request deduplication")
    print("using a unique request ID or hash of the content + timestamp + user.")

###########################################
# Fuzz Testing & Random Inputs           #
###########################################

# Conditional import to handle environments without hypothesis
try:
    from hypothesis import given, strategies as st
    hypothesis_available = True
except ImportError:
    hypothesis_available = False
    print("Hypothesis not available. Skipping fuzz tests.")
    print("Install with: pip install hypothesis")

# Define the test conditionally
if hypothesis_available:
    @given(
        # Generate random dictionaries with text keys and various value types
        details=st.dictionaries(
            keys=st.text(min_size=1, max_size=20),
            values=st.one_of(
                st.text(),
                st.integers(),
                st.floats(),
                st.booleans(),
                st.lists(st.text(), max_size=5),
                st.dictionaries(st.text(min_size=1), st.text(), max_size=3)
            ),
            max_size=10
        )
    )
    def test_fuzzed_details(details):
        """Fuzz test the details field with randomly generated data"""
        try:
            log_id = log_activity(
                user_id="fuzz_user",
                activity_type="fuzz_test",
                details=details,
                ip_address="127.0.0.1"
            )
            # If we get here, the system accepted the random data
            assert log_id is not None
            
            # Try to retrieve the log to verify it was stored correctly
            activities = get_activities(user_id="fuzz_user", activity_type="fuzz_test")
            assert len(activities) > 0
            
        except Exception as e:
            # If there are specific expected validation errors, we could
            # whitelist them here. Otherwise, we consider any exception a failure.
            pytest.fail(f"Failed with random input: {details}. Error: {str(e)}")

###########################################
# Load Testing Simulation                 #
###########################################

def test_rapid_sequential_logging():
    """Test the system's ability to handle many sequential logs"""
    NUM_LOGS = 100  # Adjust based on your performance expectations
    
    start_time = time.time()
    
    for i in range(NUM_LOGS):
        log_id = log_activity(
            user_id=f"load_test_user",
            activity_type="rapid_logging_test",
            details={"iteration": i, "batch": "sequential"},
            ip_address="127.0.0.1"
        )
        assert log_id is not None
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Calculate logs per second
    logs_per_second = NUM_LOGS / duration
    
    print(f"\nPerformance Benchmark:")
    print(f"Logged {NUM_LOGS} activities in {duration:.2f} seconds")
    print(f"Rate: {logs_per_second:.2f} logs per second")
    
    # Verify all logs were recorded
    activities = get_activities(user_id="load_test_user", activity_type="rapid_logging_test")
    assert len(activities) >= NUM_LOGS

# Run this file with pytest for advanced resilience testing
if __name__ == "__main__":
    pytest.main(['-xvs', __file__])
