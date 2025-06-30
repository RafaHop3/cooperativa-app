from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from pydantic import BaseModel, validator
from typing import Optional, List, Dict
import os
import sqlite3
import secrets
import re
import time
from loguru import logger

# Import security policies
from security_policies import (
    password_meets_requirements, is_common_password, record_login_attempt,
    is_account_locked, reset_lockout, password_expired, is_password_reused
)

# Setup logging
logger.add("security.log", rotation="10 MB", retention="1 week", level="INFO")

# Security configurations
# Generate a secure secret key
SECRET_KEY = secrets.token_hex(32)  # In production, use environment variables
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'cooperativa.db')

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def password_must_meet_policy(cls, v):
        is_valid, reason = password_meets_requirements(v)
        if not is_valid:
            raise ValueError(reason)
        if is_common_password(v):
            raise ValueError("Password is too common or easily guessable")
        return v

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = False
    role: str = "user"
    locked_until: Optional[datetime] = None
    failed_login_attempts: int = 0
    last_password_change: Optional[datetime] = None

class UserInDB(User):
    hashed_password: str
    password_history: List[str] = []

# Function to initialize user table
def init_user_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create or update users table with enhanced security fields
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        email TEXT,
        full_name TEXT,
        hashed_password TEXT NOT NULL,
        disabled BOOLEAN DEFAULT 0,
        role TEXT DEFAULT 'user',
        locked_until TIMESTAMP,
        failed_login_attempts INTEGER DEFAULT 0,
        last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        password_reset_token TEXT,
        password_reset_expires TIMESTAMP
    )''')
    
    # Create table for password history
    cursor.execute('''CREATE TABLE IF NOT EXISTS password_history (
        username TEXT,
        hashed_password TEXT NOT NULL,
        change_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (username, hashed_password),
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )''')
    
    # Create table for login attempts audit
    cursor.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT,
        success BOOLEAN,
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE SET NULL
    )''')
    
    # Add triggers for user deletion to clean up related tables
    cursor.execute('''CREATE TRIGGER IF NOT EXISTS delete_user_cleanup
        AFTER DELETE ON users
        FOR EACH ROW
        BEGIN
            DELETE FROM password_history WHERE username = OLD.username;
        END;
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Security-enhanced user tables initialized")

# Initialize user table
init_user_table()

# Add an admin user if no users exist
def create_admin_if_needed():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count == 0:
        admin_password = secrets.token_urlsafe(12)  # Generate a random password
        hashed_password = pwd_context.hash(admin_password)
        cursor.execute(
            "INSERT INTO users (username, email, full_name, hashed_password, role) VALUES (?, ?, ?, ?, ?)",
            ('admin', 'admin@cooperativa.local', 'Administrator', hashed_password, 'admin')
        )
        conn.commit()
        logger.info(f"Initial admin user created. Username: admin, Password: {admin_password}")
        print(f"Initial admin user created. Username: admin, Password: {admin_password}")
    conn.close()

create_admin_if_needed()

# Password functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# User functions
def get_user(username: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, full_name, hashed_password, disabled, role FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return UserInDB(
            username=user_data[0],
            email=user_data[1],
            full_name=user_data[2],
            hashed_password=user_data[3],
            disabled=bool(user_data[4]),
            role=user_data[5]
        )
    return None

def authenticate_user(username: str, password: str, request: Optional[Request] = None):
    # Check if the account is locked
    is_locked, seconds_left = is_account_locked(username)
    if is_locked:
        minutes_left = int(seconds_left / 60) if seconds_left else 0
        logger.warning(f"Login attempt for locked account: {username}. Minutes remaining: {minutes_left}")
        return False
    
    # Get the user
    user = get_user(username)
    
    # Record IP and user agent if request is provided
    ip_address = None
    user_agent = None
    if request:
        ip_address = request.client.host if hasattr(request.client, 'host') else None
        user_agent = request.headers.get("user-agent")
    
    # Check if user exists
    if not user:
        # Record the failed attempt (even if user doesn't exist)
        record_login_attempt(username, False)
        
        # Log failed attempt
        logger.warning(f"Authentication attempt with invalid username: {username}")
        
        # Record in database
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO login_attempts (username, ip_address, user_agent, success) VALUES (?, ?, ?, ?)",
                (username, ip_address, user_agent, 0)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error recording failed login attempt: {str(e)}")
        
        return False
    
    # Check if user is disabled
    if user.disabled:
        logger.warning(f"Authentication attempt for disabled account: {username}")
        return False
    
    # Verify password
    if not verify_password(password, user.hashed_password):
        # Record failed attempt
        record_login_attempt(username, False)
        logger.warning(f"Failed password authentication for user: {username}")
        
        # Update the failed attempts counter in DB
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Record in login_attempts table
            cursor.execute(
                "INSERT INTO login_attempts (username, ip_address, user_agent, success) VALUES (?, ?, ?, ?)",
                (username, ip_address, user_agent, 0)
            )
            
            # Update user's failed login counter
            cursor.execute(
                "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?",
                (username,)
            )
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error updating failed login attempts: {str(e)}")
            
        return False
    
    # Authentication successful
    record_login_attempt(username, True)
    
    # Reset failed login attempts on success
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Record successful login
        cursor.execute(
            "INSERT INTO login_attempts (username, ip_address, user_agent, success) VALUES (?, ?, ?, ?)",
            (username, ip_address, user_agent, 1)
        )
        
        # Reset failed attempts counter
        cursor.execute(
            "UPDATE users SET failed_login_attempts = 0 WHERE username = ?",
            (username,)
        )
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error recording successful login: {str(e)}")
    
    # Check if password has expired
    if user.last_password_change and password_expired(user.last_password_change):
        logger.info(f"Password expired for user: {username}")
        # We still return the user but will force a password change in the application
    
    logger.info(f"User authenticated successfully: {username}")
    return user

# JWT functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Token verification
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.warning("Token validation failed: missing username")
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError as e:
        logger.warning(f"Token validation error: {str(e)}")
        raise credentials_exception
    
    user = get_user(username=token_data.username)
    if user is None:
        logger.warning(f"User from token not found: {token_data.username}")
        raise credentials_exception
    return user

# Active user verification
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        logger.warning(f"Disabled user attempted access: {current_user.username}")
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Admin user verification
async def get_admin_user(current_user: User = Depends(get_current_active_user)):
    if current_user.role != "admin":
        logger.warning(f"Non-admin user attempted admin access: {current_user.username}")
        raise HTTPException(status_code=403, detail="Not enough privileges")
    return current_user
