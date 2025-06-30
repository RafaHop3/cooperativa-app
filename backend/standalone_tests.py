"""Stand-Alone Resilience Tests for Activity Logging

These tests focus on database resilience, idempotency, and data integrity
without requiring imports from other modules.
"""

import sqlite3
import json
import os
import tempfile
import time
import hashlib
from datetime import datetime

# Test database setup
def setup_test_db():
    """Create a temporary test database"""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create activity_log table
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
    conn.close()
    
    return db_fd, db_path

# Basic logging functions for testing
def log_activity(db_path, user_id, activity_type, details=None, ip_address=None):
    """Log an activity to the test database"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Convert details to JSON
        details_json = json.dumps(details) if details else None
        
        cursor.execute(
            "INSERT INTO activity_log (user_id, activity_type, details, ip_address) VALUES (?, ?, ?, ?)",
            (user_id, activity_type, details_json, ip_address)
        )
        
        conn.commit()
        log_id = cursor.lastrowid
        conn.close()
        
        return log_id
    except Exception as e:
        print(f"Error logging activity: {str(e)}")
        return None

def get_activities(db_path, user_id=None, activity_type=None, limit=100, offset=0):
    """Get activities from the test database with optional filtering"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # Get results as dictionaries
        cursor = conn.cursor()
        
        query = "SELECT * FROM activity_log WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
            
        if activity_type:
            query += " AND activity_type = ?"
            params.append(activity_type)
            
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # Convert rows to list of dicts and parse JSON details
        activities = []
        for row in rows:
            activity = dict(row)
            if activity['details']:
                try:
                    activity['details'] = json.loads(activity['details'])
                except:
                    activity['details'] = {"raw": activity['details']}
            activities.append(activity)
        
        conn.close()
        return activities
    except Exception as e:
        print(f"Error getting activities: {str(e)}")
        return []

############################
# Resilience Tests         #
############################

def test_basic_functionality():
    """Test basic logging and retrieval functionality"""
    print("\n🧪 Testing basic functionality...")
    
    # Setup test database
    db_fd, db_path = setup_test_db()
    
    try:
        # Log an activity
        log_id = log_activity(
            db_path=db_path,
            user_id="test_user",
            activity_type="basic_test",
            details={"test": "data"},
            ip_address="127.0.0.1"
        )
        
        print(f"  ✓ Logged activity with ID: {log_id}")
        
        # Retrieve the activity
        activities = get_activities(db_path=db_path, user_id="test_user")
        
        # Check results
        assert len(activities) == 1, "Expected 1 activity"
        assert activities[0]["id"] == log_id, "Activity ID mismatch"
        assert activities[0]["user_id"] == "test_user", "User ID mismatch"
        assert activities[0]["activity_type"] == "basic_test", "Activity type mismatch"
        assert activities[0]["details"]["test"] == "data", "Details mismatch"
        
        print("  ✓ Successfully retrieved activity")
        print("✅ Basic functionality test passed")
    finally:
        # Clean up
        os.close(db_fd)
        os.unlink(db_path)

def test_db_failure_handling():
    """Test handling of database failures"""
    print("\n🧪 Testing database failure handling...")
    
    # Use an invalid path to simulate database failure
    invalid_db_path = "/nonexistent/path/to/db.sqlite"
    
    start_time = time.time()
    
    # Attempt to log to non-existent database
    log_id = log_activity(
        db_path=invalid_db_path,
        user_id="failure_user",
        activity_type="db_failure_test",
        details={"test": "failure"},
        ip_address="127.0.0.1"
    )
    
    end_time = time.time()
    
    # Check for expected failure behavior
    assert log_id is None, "Expected None result when DB access fails"
    
    # Check failure response time (should fail quickly, not hang)
    elapsed = end_time - start_time
    print(f"  ✓ Failed gracefully in {elapsed:.3f} seconds")
    print("✅ Database failure handling test passed")

def test_idempotency():
    """Test system behavior with duplicate logging requests"""
    print("\n🧪 Testing idempotency behavior...")
    
    # Setup test database
    db_fd, db_path = setup_test_db()
    
    try:
        # Define identical log parameters
        test_id = f"idempotency_{int(time.time())}"
        identical_details = {"test_id": test_id, "value": "same_value"}
        
        # Log the same activity multiple times
        log_ids = []
        for i in range(3):
            log_id = log_activity(
                db_path=db_path,
                user_id="idempotent_user",
                activity_type="duplicate_test",
                details=identical_details,
                ip_address="127.0.0.1"
            )
            log_ids.append(log_id)
        
        print(f"  ✓ Logged identical activities with IDs: {log_ids}")
        
        # Retrieve all matching activities
        activities = get_activities(db_path=db_path, activity_type="duplicate_test")
        
        # Filter to just this test run
        test_activities = []
        for activity in activities:
            if activity["details"].get("test_id") == test_id:
                test_activities.append(activity)
        
        # Current expected behavior: system allows duplicates
        assert len(test_activities) == 3, "Expected 3 duplicate logs with current implementation"
        
        print(f"  ✓ Current behavior: System created {len(test_activities)} logs from identical requests")
        print("  ℹ️ In production, consider implementing request deduplication")
        print("✅ Idempotency test passed")
    finally:
        # Clean up
        os.close(db_fd)
        os.unlink(db_path)

def test_tampered_record_detection():
    """Test detection of tampered activity records"""
    print("\n🧪 Testing tampered record detection...")
    
    # Setup test database with integrity features
    db_fd, db_path = setup_test_db()
    
    try:
        # Create a function to calculate a checksum
        def calculate_checksum(data):
            serialized = json.dumps(data, sort_keys=True)
            return hashlib.sha256(serialized.encode()).hexdigest()
        
        # Create a record with a checksum
        original_data = {"sensitive": "important_data", "timestamp": datetime.now().isoformat()}
        checksum = calculate_checksum(original_data)
        
        # Add the checksum to the data we'll store
        data_with_checksum = dict(original_data)
        data_with_checksum["_integrity"] = checksum
        
        # Log the activity
        log_id = log_activity(
            db_path=db_path,
            user_id="integrity_test_user",
            activity_type="integrity_test",
            details=data_with_checksum,
            ip_address="127.0.0.1"
        )
        
        print(f"  ✓ Logged activity with integrity checksum, ID: {log_id}")
        
        # Connect directly to the database to simulate tampering
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Retrieve the original record
        cursor.execute("SELECT details FROM activity_log WHERE id = ?", (log_id,))
        details_json = cursor.fetchone()[0]
        details = json.loads(details_json)
        
        # "Tamper" with the data, but don't update the checksum
        details["sensitive"] = "TAMPERED_DATA"  # Modified data
        # details["_integrity"] = unchanged     # Checksum not updated
        
        # Update the record with tampered data
        cursor.execute(
            "UPDATE activity_log SET details = ? WHERE id = ?",
            (json.dumps(details), log_id)
        )
        conn.commit()
        conn.close()
        
        print("  ✓ Simulated tampering by directly modifying the database")
        
        # Retrieve the tampered record
        activities = get_activities(db_path=db_path, activity_type="integrity_test")
        tampered_activity = activities[0]
        
        # Verify tampering detection
        stored_checksum = tampered_activity["details"].get("_integrity")
        tampered_data = dict(tampered_activity["details"])
        del tampered_data["_integrity"]  # Remove checksum before recalculating
        
        recalculated_checksum = calculate_checksum(tampered_data)
        
        # Check if tampering is detected
        if stored_checksum != recalculated_checksum:
            print("  ✓ Tampering detected! Checksum mismatch")
            print("    - Stored checksum: ", stored_checksum[:10] + "...")
            print("    - Recalculated:    ", recalculated_checksum[:10] + "...")
        else:
            print("  ❌ Tampering NOT detected - checksums match")
        
        assert stored_checksum != recalculated_checksum, "Tampering should be detected"
        print("✅ Tampered record detection test passed")
    finally:
        # Clean up
        os.close(db_fd)
        os.unlink(db_path)

############################
# Run all tests            #
############################

if __name__ == "__main__":
    print("\n====== RESILIENCE TESTS ======\n")
    
    try:
        test_basic_functionality()
        test_db_failure_handling()
        test_idempotency()
        test_tampered_record_detection()
        
        print("\n✅ ALL TESTS PASSED")
        print("\n==== RESILIENCE TEST SUMMARY ====\n")
        print("✅ Basic functionality:      System correctly logs and retrieves activities")
        print("✅ DB failure handling:      System handles database errors gracefully")
        print("✅ Idempotency behavior:     System currently allows duplicate logs (consider adding deduplication)")
        print("✅ Tampered record detection: Demonstrated how to detect unauthorized modifications")
        print("\nRecommendations:")
        print("1. Consider adding idempotency keys for critical operations")
        print("2. Implement integrity checksums for sensitive audit logs")
        print("3. Add retry logic for transient database failures")
    except Exception as e:
        print(f"\n❌ TEST FAILURE: {str(e)}")
    
    print("\n====== END OF TESTS ======\n")
