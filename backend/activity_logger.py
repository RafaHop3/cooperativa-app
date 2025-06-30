from fastapi import Depends, HTTPException, status
import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
import json
import hashlib
import time
import functools
import random
from pydantic import BaseModel, Field
from auth import User, get_current_active_user
import os

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'cooperativa.db')

class ActivityLog(BaseModel):
    """Model for activity logs"""
    id: Optional[int] = None
    user_id: str
    activity_type: str
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    timestamp: Optional[datetime] = None
    request_id: Optional[str] = Field(None, description="Unique request ID for idempotency")
    checksum: Optional[str] = Field(None, description="Integrity checksum of the log data")

# Create secure database connection
def get_db_connection():
    """Create a database connection with proper error handling"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        return conn
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection error: {str(e)}")

# Retry decorator for database operations
def retry_db_operation(max_attempts=3, initial_backoff=0.1):
    """Decorator to retry database operations with exponential backoff"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            last_exception = None
            
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    # Only retry on specific operational errors like database locked
                    if "database is locked" in str(e) or "busy" in str(e):
                        attempt += 1
                        last_exception = e
                        
                        if attempt < max_attempts:
                            # Calculate backoff with jitter to prevent thundering herd
                            backoff = initial_backoff * (2 ** (attempt - 1)) * (0.5 + random.random())
                            time.sleep(backoff)
                        else:
                            raise
                    else:
                        # Don't retry on other operational errors
                        raise
                except Exception as e:
                    # Don't retry on non-operational errors
                    raise
            
            # If we get here, all attempts failed
            raise last_exception
        return wrapper
    return decorator

# Helper function to calculate integrity checksum
def calculate_checksum(data: Dict[str, Any]) -> str:
    """Calculate integrity checksum for log data"""
    # Make a copy of the data to avoid modifying the original
    checkable_data = dict(data) if data else {}
    
    # Remove any existing checksum field if present
    if "_checksum" in checkable_data:
        del checkable_data["_checksum"]
    
    # Sort keys for consistent serialization
    serialized = json.dumps(checkable_data, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()

@retry_db_operation(max_attempts=3)
def init_activity_log_table():
    """Initialize the activity_log table if it doesn't exist with enhanced schema"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create activity_log table with additional columns for resilience
        cursor.execute('''CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            request_id TEXT UNIQUE,
            checksum TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Create index on request_id for efficient idempotency checks
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_request_id ON activity_log (request_id)')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initialize activity_log table: {str(e)}")

@retry_db_operation(max_attempts=3)
def log_activity(user_id: str, activity_type: str, details: Dict[str, Any] = None, 
               ip_address: str = None, request_id: str = None):
    """Log user activity to the database with idempotency and integrity protection"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Handle idempotency if a request_id is provided
        if request_id:
            # Check if this request_id already exists
            cursor.execute("SELECT id FROM activity_log WHERE request_id = ?", (request_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Request already processed, return existing ID
                conn.close()
                return existing[0]
        
        # Prepare details with integrity protection
        log_details = dict(details) if details else {}
        
        # Calculate checksum for the log data
        checksum = calculate_checksum({
            "user_id": user_id,
            "activity_type": activity_type,
            "details": log_details,
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat()
        })
        
        # Store checksum in details for validation
        log_details["_checksum"] = checksum
        
        # Convert enriched details dict to JSON string
        details_json = json.dumps(log_details)
        
        # Insert with request_id and checksum
        cursor.execute(
            "INSERT INTO activity_log (user_id, activity_type, details, ip_address, request_id, checksum) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, activity_type, details_json, ip_address, request_id, checksum)
        )
        
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        
        return last_id
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log activity: {str(e)}")

@retry_db_operation(max_attempts=3)
def get_activities(limit: int = 100, offset: int = 0, user_id: str = None, 
                   activity_type: str = None, verify_integrity: bool = True):
    """Get activity logs with optional filtering and integrity verification"""
    try:
        conn = get_db_connection()
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
        conn.close()
        
        # Convert rows to list of dicts and parse JSON details
        activities = []
        for row in rows:
            activity = dict(row)
            integrity_status = True
            
            if activity['details']:
                try:
                    activity['details'] = json.loads(activity['details'])
                    
                    # Verify integrity if requested
                    if verify_integrity and '_checksum' in activity['details']:
                        stored_checksum = activity['details']['_checksum']
                        verify_data = {
                            "user_id": activity["user_id"],
                            "activity_type": activity["activity_type"],
                            "details": {k: v for k, v in activity["details"].items() if k != "_checksum"},
                            "ip_address": activity["ip_address"],
                            "timestamp": activity.get("timestamp")
                        }
                        recalculated_checksum = calculate_checksum(verify_data)
                        
                        # Add integrity verification result
                        integrity_status = (stored_checksum == recalculated_checksum)
                        activity['integrity_verified'] = integrity_status
                        
                        if not integrity_status:
                            activity['warning'] = "Possible data tampering detected"
                except Exception as e:
                    activity['details'] = {"raw": activity['details'], "parse_error": str(e)}
            
            activities.append(activity)
            
        return activities
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve activity logs: {str(e)}")

# Add function to verify a single activity's integrity
def verify_activity_integrity(activity_id: int) -> Dict[str, Union[bool, str, Dict]]:
    """Verify the integrity of a specific activity log"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get the activity
        cursor.execute("SELECT * FROM activity_log WHERE id = ?", (activity_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return {"verified": False, "error": "Activity not found"}
        
        activity = dict(row)
        if not activity['details']:
            return {"verified": False, "error": "No details to verify"}
        
        # Parse details
        try:
            details = json.loads(activity['details'])
        except:
            return {"verified": False, "error": "Invalid JSON in details"}
        
        # Check for checksum
        if '_checksum' not in details:
            return {"verified": False, "error": "No checksum found in activity"}
        
        # Extract checksum
        stored_checksum = details['_checksum']
        
        # Prepare data for verification
        verify_data = {
            "user_id": activity["user_id"],
            "activity_type": activity["activity_type"],
            "details": {k: v for k, v in details.items() if k != "_checksum"},
            "ip_address": activity["ip_address"],
            "timestamp": activity.get("timestamp")
        }
        
        # Recalculate checksum
        recalculated_checksum = calculate_checksum(verify_data)
        
        # Verify
        if stored_checksum == recalculated_checksum:
            return {
                "verified": True, 
                "activity_id": activity_id,
                "message": "Activity log integrity verified"
            }
        else:
            return {
                "verified": False, 
                "activity_id": activity_id,
                "message": "Data integrity violation detected",
                "stored_checksum": stored_checksum,
                "recalculated_checksum": recalculated_checksum
            }
    
    except Exception as e:
        return {"verified": False, "error": str(e)}

# Initialize the table when the module is loaded
init_activity_log_table()
