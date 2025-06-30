"""Enhanced Activity Logging System with Digital Signatures

This module extends the original activity logger with digital signatures
and other advanced security features.
"""

from fastapi import Depends, HTTPException, status
import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any, Union, Set
import json
import hashlib
import time
import functools
import random
import uuid
from pydantic import BaseModel, Field
from auth import User, get_current_active_user
import os
import logging

# Import the digital signature module
from security.log_signing import generate_keypair, load_private_key, load_public_key, sign_activity_log, verify_activity_log, verify_signature

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'cooperativa.db')

# Configuration
ENABLE_SIGNATURES = os.environ.get('ENABLE_LOG_SIGNATURES', 'true').lower() == 'true'
ENABLE_METALOGS = os.environ.get('ENABLE_METALOGS', 'true').lower() == 'true'
SENSITIVE_LOG_TYPES = set(os.environ.get('SENSITIVE_LOG_TYPES', 
                                       'login,password_change,admin_action,data_export,user_creation').split(','))


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
    digital_signature: Optional[str] = Field(None, description="Cryptographic signature for sensitive logs")
    locked: Optional[bool] = Field(False, description="Whether this log is locked for modifications")


class MetaLog(BaseModel):
    """Model for meta-logs (audit trail of log access)"""
    id: Optional[int] = None
    user_id: str
    action: str  # view, export, search
    target_log_id: Optional[int] = None  # If a specific log was targeted
    query_params: Optional[Dict[str, Any]] = None
    query_hash: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: Optional[datetime] = None


# Create secure database connection
def get_db_connection():
    """Get a connection to the SQLite database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
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
def init_db_tables():
    """Initialize database tables for activity logging
    
    Create the enhanced activity_log table with digital signature support
    and the meta_log table for recording log access
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create enhanced activity_log table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            details TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            request_id TEXT UNIQUE,
            digital_signature TEXT,
            locked INTEGER DEFAULT 0,
            lock_id INTEGER
        )
        ''')
        
        # Add indexes for common query patterns
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_user_id ON activity_log(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_activity_type ON activity_log(activity_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_timestamp ON activity_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_request_id ON activity_log(request_id)')
        
        # Create meta_log table for recording log access
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS meta_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target_log_id INTEGER,
            query_params TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT
        )
        ''')
        
        # Add indexes for meta_log
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_meta_log_user_id ON meta_log(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_meta_log_action ON meta_log(action)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_meta_log_timestamp ON meta_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_meta_log_target_log_id ON meta_log(target_log_id)')
        
        # Create log_locks table for post-audit read-only mode
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_locks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            reason TEXT,
            locked_by TEXT NOT NULL,
            locked_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Add indexes for log_locks
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_locks_period_start ON log_locks(period_start)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_locks_period_end ON log_locks(period_end)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_locks_locked_by ON log_locks(locked_by)')
        
        conn.commit()
        conn.close()
        logger.info("Activity log tables initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize activity log tables: {str(e)}")
        raise
        logger.error(f"Failed to initialize database tables: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to initialize database tables: {str(e)}")


@retry_db_operation(max_attempts=3)
def log_meta_activity(user_id: str, action: str, target_log_id: Optional[int] = None,
                   query_params: Optional[Dict[str, Any]] = None, ip_address: Optional[str] = None):
    """Log meta-activity (who accessed which logs)
    
    This provides a reversible audit trail of all log access and operations
    
    Args:
        user_id: ID of the user who accessed the logs
        action: Type of access (view, export, search, etc.)
        target_log_id: Optional ID of a specific log that was accessed
        query_params: Optional parameters used to query/filter logs
        ip_address: IP address of the user
        
    Returns:
        int: ID of the inserted meta-log or None if disabled
    """
    if not ENABLE_METALOGS:
        return None
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Convert query_params dict to JSON string
        params_json = json.dumps(query_params) if query_params else None
        
        # Calculate query hash for verification
        query_hash = None
        if query_params:
            query_hash = hashlib.sha256(params_json.encode()).hexdigest()
        
        # Insert meta-log
        cursor.execute(
            "INSERT INTO meta_logs (user_id, action, target_log_id, query_params, query_hash, ip_address) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, action, target_log_id, params_json, query_hash, ip_address)
        )
        
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        
        return last_id
    
    except Exception as e:
        logger.error(f"Failed to log meta-activity: {str(e)}")
        # Don't raise exception for meta-log failures to avoid disrupting core functionality
        return None


@retry_db_operation(max_attempts=3)
def log_activity(user_id: str, activity_type: str, details: Dict[str, Any] = None,
               ip_address: str = None, request_id: str = None,
               current_user: Optional[User] = None):
    """Log user activity with enhanced security features
    
    Args:
        user_id: ID of the user performing the action
        activity_type: Type of activity being logged
        details: Additional details about the activity
        ip_address: IP address of the requester
        request_id: Optional unique request ID for idempotency
        current_user: Optional current user object for meta-logging
    
    Returns:
        int: ID of the logged activity
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Generate request ID if not provided
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Handle idempotency if a request_id is provided
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
        
        # Check if this is a sensitive log type that needs digital signature
        needs_signature = activity_type in SENSITIVE_LOG_TYPES and ENABLE_SIGNATURES
        
        # Generate digital signature for sensitive logs
        digital_signature = None
        if needs_signature:
            # Create data to sign
            sign_data = {
                "user_id": user_id,
                "activity_type": activity_type,
                "details": log_details,
                "ip_address": ip_address,
                "request_id": request_id,
                "checksum": checksum,
                "timestamp": datetime.now().isoformat()
            }
            
            # Sign the data
            signed_data, digital_signature = sign_activity_log(sign_data)
            
            # Update details with signature metadata
            if "signature_metadata" in signed_data:
                log_details["_signature_metadata"] = signed_data["signature_metadata"]
        
        # Convert enriched details dict to JSON string
        details_json = json.dumps(log_details)
        
        # Insert with request_id, checksum, and signature
        cursor.execute(
            "INSERT INTO activity_log "
            "(user_id, activity_type, details, ip_address, request_id, checksum, digital_signature) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, activity_type, details_json, ip_address, request_id, checksum, digital_signature)
        )
        
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        
        # Create meta-log entry if applicable
        if current_user and current_user.user_id != user_id:
            log_meta_activity(
                user_id=current_user.user_id,
                action="create_log",
                target_log_id=last_id,
                query_params={"activity_type": activity_type},
                ip_address=ip_address
            )
        
        return last_id
    
    except Exception as e:
        logger.error(f"Failed to log activity: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to log activity: {str(e)}")


@retry_db_operation(max_attempts=3)
def get_activities(limit: int = 100, offset: int = 0, user_id: str = None,
                activity_type: str = None, verify_integrity: bool = True,
                verify_signatures: bool = True, current_user: Optional[User] = None,
                ip_address: str = None):
    """Get activity logs with enhanced security checks
    
    Args:
        limit: Maximum number of logs to return
        offset: Number of logs to skip (for pagination)
        user_id: Filter logs by user ID
        activity_type: Filter logs by activity type
        verify_integrity: Whether to verify checksums
        verify_signatures: Whether to verify digital signatures
        current_user: Current user object for meta-logging
        ip_address: IP address of the requester
    
    Returns:
        List[Dict]: List of activity logs with verification results
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build the query
        query = "SELECT * FROM activity_log WHERE 1=1"
        params = []
        
        # Track query parameters for meta-logging
        query_params = {"limit": limit, "offset": offset}
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
            query_params["user_id"] = user_id
            
        if activity_type:
            query += " AND activity_type = ?"
            params.append(activity_type)
            query_params["activity_type"] = activity_type
            
        # Don't show locked logs to non-admin users
        if current_user and not current_user.is_admin:
            query += " AND (locked = 0 OR user_id = ?)"
            params.append(current_user.user_id)  # Users can see their own locked logs
            
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert rows to list of dicts and parse JSON details
        activities = []
        for row in rows:
            activity = dict(row)
            signature_status = None
            
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
                    
                    # Verify digital signature if present and requested
                    if verify_signatures and activity.get("digital_signature") and ENABLE_SIGNATURES:
                        # Prepare data for signature verification
                        verify_data = {
                            "user_id": activity["user_id"],
                            "activity_type": activity["activity_type"],
                            "details": activity["details"],
                            "ip_address": activity["ip_address"],
                            "request_id": activity.get("request_id"),
                            "checksum": activity.get("checksum"),
                            "signature_metadata": activity["details"].get("_signature_metadata")
                        }
                        
                        # Verify the signature
                        signature_status = verify_activity_log({
                            **verify_data,
                            "signature": activity["digital_signature"]
                        })
                        
                        activity['signature_verified'] = signature_status.get("verified", False)
                        
                        if not signature_status.get("verified", False):
                            activity['warning'] = activity.get('warning', "") + " Signature verification failed."
                            
                except Exception as e:
                    activity['details'] = {"raw": activity['details'], "parse_error": str(e)}
            
            activities.append(activity)
        
        # Log this access in meta-logs if applicable
        if current_user and ENABLE_METALOGS:
            log_meta_activity(
                user_id=current_user.user_id,
                action="view_logs",
                query_params=query_params,
                ip_address=ip_address
            )
            
        return activities
    
    except Exception as e:
        logger.error(f"Failed to retrieve activity logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve activity logs: {str(e)}")


@retry_db_operation(max_attempts=3)
def verify_activity_integrity(activity_id: int, current_user: Optional[User] = None,
                           ip_address: str = None) -> Dict[str, Union[bool, str, Dict]]:
    """Verify the integrity of a specific activity log
    
    This performs both checksum and digital signature verification
    
    Args:
        activity_id: ID of the activity log to verify
        current_user: Current user object for meta-logging
        ip_address: IP address of the requester
        
    Returns:
        Dict: Verification results
    """
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
        
        # Log this verification in meta-logs if applicable
        if current_user and ENABLE_METALOGS:
            log_meta_activity(
                user_id=current_user.user_id,
                action="verify_integrity",
                target_log_id=activity_id,
                ip_address=ip_address
            )
        
        # Check for basic data
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
        
        # Verify integrity
        integrity_verified = (stored_checksum == recalculated_checksum)
        
        # Verify signature if present
        signature_verified = None
        if activity.get("digital_signature") and ENABLE_SIGNATURES:
            sign_verify_data = {
                "user_id": activity["user_id"],
                "activity_type": activity["activity_type"],
                "details": details,
                "ip_address": activity["ip_address"],
                "request_id": activity.get("request_id"),
                "checksum": activity.get("checksum"),
                "signature": activity["digital_signature"],
                "signature_metadata": details.get("_signature_metadata")
            }
            
            signature_verified = verify_activity_log(sign_verify_data)
        
        # Compile results
        result = {
            "activity_id": activity_id,
            "integrity_verified": integrity_verified,
            "signature_verified": signature_verified.get("verified", None) if signature_verified else None,
            "locked": bool(activity.get("locked", False))
        }
        
        if not integrity_verified:
            result["integrity_error"] = {
                "stored_checksum": stored_checksum,
                "recalculated_checksum": recalculated_checksum
            }
            
        if signature_verified and not signature_verified.get("verified", False):
            result["signature_error"] = signature_verified.get("reason")
            
        return result
    
    except Exception as e:
        logger.error(f"Error verifying activity integrity: {str(e)}")
        return {"verified": False, "error": str(e)}


@retry_db_operation(max_attempts=3)
def create_lock_period(start_date: datetime, end_date: datetime, reason: str,
                    locked_by: str, ip_address: Optional[str] = None,
                    current_user: Optional[User] = None) -> int:
    """Create a lock period for logs, preventing modification
    
    This implements the post-audit read-only mode, locking logs for a specific time period
    
    Args:
        start_date: Beginning of period to lock logs
        end_date: End of period to lock logs
        reason: Reason for locking (e.g. "Monthly Audit", "Legal Hold")
        locked_by: User ID of the person creating the lock
        ip_address: IP address of the requester
        current_user: Optional current user object for meta-logging
        
    Returns:
        int: ID of the created lock period
    """
    try:
        # Only admins should be able to create locks
        if current_user and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can create log lock periods"
            )
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert the lock period
        cursor.execute(
            "INSERT INTO log_locks (period_start, period_end, reason, locked_by) VALUES (?, ?, ?, ?)",
            (start_date.isoformat(), end_date.isoformat(), reason, locked_by)
        )
        
        lock_id = cursor.lastrowid
        
        # Apply the lock to all logs within the period
        cursor.execute(
            "UPDATE activity_log SET locked = 1, lock_id = ? WHERE "
            "timestamp >= ? AND timestamp <= ?",
            (lock_id, start_date.isoformat(), end_date.isoformat())
        )
        
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()
        
        # Log this action in meta-logs
        if current_user and ENABLE_METALOGS:
            log_meta_activity(
                user_id=current_user.user_id,
                action="create_lock_period",
                query_params={
                    "lock_id": lock_id,
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "affected_logs": affected_rows
                },
                ip_address=ip_address
            )
        
        return lock_id
    
    except Exception as e:
        logger.error(f"Failed to create lock period: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create lock period: {str(e)}")


@retry_db_operation(max_attempts=3)
def get_lock_periods(limit: int = 100, offset: int = 0, current_user: Optional[User] = None,
                 ip_address: Optional[str] = None) -> List[Dict]:
    """Get list of log lock periods
    
    Args:
        limit: Maximum number of locks to return
        offset: Number of locks to skip (for pagination)
        current_user: Current user object for meta-logging
        ip_address: IP address of the requester
        
    Returns:
        List[Dict]: List of lock periods with affected log counts
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get lock periods
        cursor.execute(
            "SELECT * FROM log_locks ORDER BY locked_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        rows = cursor.fetchall()
        
        # Convert to list of dicts
        lock_periods = []
        for row in rows:
            lock = dict(row)
            
            # Count affected logs for each lock
            cursor.execute(
                "SELECT COUNT(*) as affected_count FROM activity_log WHERE lock_id = ?",
                (lock['id'],)
            )
            count_row = cursor.fetchone()
            lock['affected_logs_count'] = count_row['affected_count'] if count_row else 0
            
            lock_periods.append(lock)
            
        conn.close()
        
        # Log this access in meta-logs
        if current_user and ENABLE_METALOGS:
            log_meta_activity(
                user_id=current_user.user_id,
                action="view_lock_periods",
                query_params={"limit": limit, "offset": offset},
                ip_address=ip_address
            )
            
        return lock_periods
    
    except Exception as e:
        logger.error(f"Failed to retrieve lock periods: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve lock periods: {str(e)}")


@retry_db_operation(max_attempts=3)
def secure_export_activities(filters: Dict[str, Any], export_format: str = "json",
                         current_user: Optional[User] = None, ip_address: Optional[str] = None) -> Dict:
    """Securely export activity logs with verification hash
    
    This function creates a tamper-evident export of logs that can be verified later
    
    Args:
        filters: Dictionary of filters to apply (user_id, activity_type, date_range, etc.)
        export_format: Format to export (json, csv, pdf)
        current_user: Current user object for meta-logging
        ip_address: IP address of the requester
        
    Returns:
        Dict: Export metadata and either file path or content
    """
    try:
        # Build query based on filters
        query = "SELECT * FROM activity_log WHERE 1=1"
        params = []
        
        if "user_id" in filters and filters["user_id"]:
            query += " AND user_id = ?"
            params.append(filters["user_id"])
            
        if "activity_type" in filters and filters["activity_type"]:
            query += " AND activity_type = ?"
            params.append(filters["activity_type"])
            
        if "start_date" in filters and filters["start_date"]:
            query += " AND timestamp >= ?"
            params.append(filters["start_date"])
            
        if "end_date" in filters and filters["end_date"]:
            query += " AND timestamp <= ?"
            params.append(filters["end_date"])
            
        # Don't export locked logs if not admin
        if current_user and not current_user.is_admin:
            query += " AND (locked = 0 OR user_id = ?)"
            params.append(current_user.user_id)  # Users can export their own locked logs
            
        query += " ORDER BY timestamp DESC"
        
        # Execute query
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert rows to list of dicts
        activities = []
        for row in rows:
            activity = dict(row)
            
            # Parse JSON details
            if activity['details']:
                try:
                    activity['details'] = json.loads(activity['details'])
                except:
                    activity['details'] = {"parse_error": "Invalid JSON"}
                    
            activities.append(activity)
        
        # Create export metadata
        export_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        export_data = {
            "export_id": export_id,
            "timestamp": timestamp,
            "exported_by": current_user.user_id if current_user else "system",
            "filters": filters,
            "record_count": len(activities),
            "records": activities
        }
        
        # Generate export file
        export_path = os.path.join(os.path.dirname(__file__), 'exports')
        os.makedirs(export_path, exist_ok=True)
        
        file_path = os.path.join(export_path, f"activity_export_{export_id}.{export_format}")
        
        # Generate content based on format
        if export_format == "json":
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
                
        elif export_format == "csv":
            import csv
            with open(file_path, 'w', newline='') as f:
                # Flatten the structure for CSV
                fieldnames = ["id", "user_id", "activity_type", "ip_address", "timestamp", 
                             "request_id", "digital_signature", "locked", "details"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for activity in activities:
                    # Convert details back to string for CSV
                    if "details" in activity and activity["details"]:
                        activity["details"] = json.dumps(activity["details"])
                    writer.writerow(activity)
                    
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
        
        # Generate verification hash for the entire export
        with open(file_path, 'rb') as f:
            file_content = f.read()
            verification_hash = hashlib.sha256(file_content).hexdigest()
            
        # Add verification metadata file
        metadata_path = file_path + ".meta"
        verification_data = {
            "export_id": export_id,
            "timestamp": timestamp,
            "exported_by": current_user.user_id if current_user else "system",
            "record_count": len(activities),
            "file_hash": verification_hash,
            "hash_algorithm": "sha256"
        }
        
        # Sign the verification metadata if enabled
        if ENABLE_SIGNATURES:
            signed_data, signature = sign_activity_log(verification_data)
            verification_data["signature"] = signature
            verification_data["signature_metadata"] = signed_data.get("signature_metadata")
            
        with open(metadata_path, 'w') as f:
            json.dump(verification_data, f, indent=2, default=str)
            
        # Log this export in meta-logs
        if current_user and ENABLE_METALOGS:
            log_meta_activity(
                user_id=current_user.user_id,
                action="export_logs",
                query_params={
                    "filters": filters,
                    "export_id": export_id,
                    "record_count": len(activities),
                    "format": export_format
                },
                ip_address=ip_address
            )
            
        # Return export metadata
        return {
            "export_id": export_id,
            "timestamp": timestamp,
            "record_count": len(activities),
            "format": export_format,
            "file_path": file_path,
            "verification_hash": verification_hash,
            "verification_file": metadata_path
        }
        
    except Exception as e:
        logger.error(f"Failed to export activities: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to export activities: {str(e)}")


@retry_db_operation(max_attempts=3)
def verify_export(export_file_path: str, verification_file_path: Optional[str] = None) -> Dict[str, Any]:
    """Verify an exported log file against its verification metadata
    
    Args:
        export_file_path: Path to the exported log file
        verification_file_path: Path to the verification metadata file (defaults to export_file_path + ".meta")
        
    Returns:
        Dict: Verification results
    """
    try:
        # Default verification file path
        if not verification_file_path:
            verification_file_path = export_file_path + ".meta"
            
        # Check if files exist
        if not os.path.exists(export_file_path):
            return {"verified": False, "error": "Export file not found"}
            
        if not os.path.exists(verification_file_path):
            return {"verified": False, "error": "Verification file not found"}
            
        # Load verification metadata
        with open(verification_file_path, 'r') as f:
            verification_data = json.load(f)
            
        # Calculate hash of export file
        with open(export_file_path, 'rb') as f:
            file_content = f.read()
            calculated_hash = hashlib.sha256(file_content).hexdigest()
            
        # Compare hashes
        hash_verified = (calculated_hash == verification_data.get("file_hash"))
        
        # Verify signature if present
        signature_verified = None
        if "signature" in verification_data and ENABLE_SIGNATURES:
            # Prepare data for verification
            sign_verify_data = {
                "export_id": verification_data.get("export_id"),
                "timestamp": verification_data.get("timestamp"),
                "exported_by": verification_data.get("exported_by"),
                "record_count": verification_data.get("record_count"),
                "file_hash": verification_data.get("file_hash"),
                "hash_algorithm": verification_data.get("hash_algorithm")
            }
            
            # Use verify_activity_log function from the log_signing module
            verification_result = verify_activity_log({
                "data": sign_verify_data,
                "signature": verification_data.get("signature"),
                "signature_metadata": verification_data.get("signature_metadata")
            })
            
            signature_verified = verification_result.get("verified", False)
            
        # Compile results
        result = {
            "file_verified": hash_verified,
            "signature_verified": signature_verified,
            "export_id": verification_data.get("export_id"),
            "timestamp": verification_data.get("timestamp"),
            "exported_by": verification_data.get("exported_by"),
            "record_count": verification_data.get("record_count")
        }
        
        if not hash_verified:
            result["hash_error"] = {
                "stored_hash": verification_data.get("file_hash"),
                "calculated_hash": calculated_hash
            }
            
        return result
    
    except Exception as e:
        logger.error(f"Failed to verify export: {str(e)}")
        return {"verified": False, "error": str(e)}


# Initialize database tables on module import
init_db_tables()
