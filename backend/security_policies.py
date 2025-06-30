"""
Security policies module for the cooperativa-app
Contains password validation, account lockout mechanisms, and other security utilities
"""

import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from loguru import logger
from pydantic import BaseModel, validator

# Password policy configuration
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGITS = True
PASSWORD_REQUIRE_SPECIAL = True
PASSWORD_MAX_AGE_DAYS = 90
PASSWORD_HISTORY_COUNT = 5  # Remember last 5 passwords

# Account lockout configuration
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME_MINUTES = 15
ATTEMPT_WINDOW_MINUTES = 30  # Reset attempt counter after this time

# Rate limiting
DEFAULT_RATE_LIMIT = "30/minute"
SENSITIVE_RATE_LIMIT = "5/minute"  # For login, registration, etc.

# Login attempt tracking: {username: [(timestamp, success), ...]}
login_attempts: Dict[str, List[Tuple[float, bool]]] = {}
# Account lockouts: {username: lockout_until_timestamp}
account_lockouts: Dict[str, float] = {}


class PasswordPolicy(BaseModel):
    """Password policy model for validation and information"""
    min_length: int = PASSWORD_MIN_LENGTH
    require_uppercase: bool = PASSWORD_REQUIRE_UPPERCASE
    require_lowercase: bool = PASSWORD_REQUIRE_LOWERCASE
    require_digits: bool = PASSWORD_REQUIRE_DIGITS
    require_special: bool = PASSWORD_REQUIRE_SPECIAL
    max_age_days: int = PASSWORD_MAX_AGE_DAYS

    @validator('min_length')
    def min_length_must_be_reasonable(cls, v):
        if v < 8:
            raise ValueError('Minimum password length must be at least 8')
        return v


def get_current_policy() -> PasswordPolicy:
    """Get the current password policy"""
    return PasswordPolicy()


def password_meets_requirements(password: str) -> Tuple[bool, str]:
    """
    Check if a password meets all requirements
    Returns (is_valid, reason)
    """
    policy = get_current_policy()
    
    if len(password) < policy.min_length:
        return False, f"Password must be at least {policy.min_length} characters long"
        
    if policy.require_uppercase and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
        
    if policy.require_lowercase and not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
        
    if policy.require_digits and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
        
    if policy.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
        
    return True, "Password meets requirements"


def is_common_password(password: str) -> bool:
    """
    Check if a password is too common or easily guessable
    Uses a simple list of very common passwords
    """
    common_passwords = {
        "password", "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
        "qwerty", "abc123", "admin", "welcome", "password1", "admin1", "administrator",
        "cooperativa", "sistema"
    }
    
    return password.lower() in common_passwords


def record_login_attempt(username: str, success: bool) -> None:
    """
    Record a login attempt for a user
    """
    if username not in login_attempts:
        login_attempts[username] = []
        
    # Add the current attempt
    current_time = time.time()
    login_attempts[username].append((current_time, success))
    
    # Log the attempt
    if success:
        logger.info(f"Successful login for user: {username}")
    else:
        logger.warning(f"Failed login attempt for user: {username}")
    
    # Clean up old attempts
    clean_old_attempts(username)
    
    # Check if we need to lock the account
    if not success:
        check_and_lock_account(username)


def clean_old_attempts(username: str) -> None:
    """
    Clean old login attempts outside the window period
    """
    if username not in login_attempts:
        return
        
    current_time = time.time()
    window_start = current_time - (ATTEMPT_WINDOW_MINUTES * 60)
    
    # Keep only attempts within the window
    login_attempts[username] = [(t, s) for t, s in login_attempts[username] if t >= window_start]


def check_and_lock_account(username: str) -> None:
    """
    Check if an account should be locked based on failed attempts
    """
    if username not in login_attempts:
        return
    
    # Count failed attempts within window
    current_time = time.time()
    window_start = current_time - (ATTEMPT_WINDOW_MINUTES * 60)
    failed_attempts = sum(1 for t, s in login_attempts[username] 
                         if t >= window_start and not s)
    
    if failed_attempts >= MAX_LOGIN_ATTEMPTS:
        # Lock the account
        lockout_until = current_time + (LOCKOUT_TIME_MINUTES * 60)
        account_lockouts[username] = lockout_until
        
        logger.warning(f"Account locked for user: {username}. Too many failed attempts.")


def is_account_locked(username: str) -> Tuple[bool, Optional[float]]:
    """
    Check if an account is currently locked out
    Returns (is_locked, seconds_remaining)
    """
    if username not in account_lockouts:
        return False, None
        
    current_time = time.time()
    lockout_until = account_lockouts[username]
    
    if current_time < lockout_until:
        # Account is still locked
        seconds_remaining = lockout_until - current_time
        return True, seconds_remaining
    else:
        # Lockout has expired
        del account_lockouts[username]
        return False, None


def reset_lockout(username: str) -> None:
    """
    Reset a lockout for a specific user (admin function)
    """
    if username in account_lockouts:
        del account_lockouts[username]
        logger.info(f"Lockout manually reset for user: {username}")


def password_expired(last_changed: datetime) -> bool:
    """
    Check if a password has expired based on the maximum age
    """
    if not last_changed:
        return False
        
    policy = get_current_policy()
    max_age = timedelta(days=policy.max_age_days)
    
    return datetime.now() - last_changed > max_age


def is_password_reused(username: str, new_password_hash: str, password_history: List[str]) -> bool:
    """
    Check if a password was recently used by comparing hashes
    """
    if not password_history:
        return False
        
    for old_hash in password_history:
        if old_hash == new_password_hash:
            return True
            
    return False


def generate_secure_url(base_url: str, path: str, params: Dict[str, str] = None) -> str:
    """Generate a secure URL with proper encoding"""
    from urllib.parse import urlencode, quote
    
    # Ensure path starts with /
    if not path.startswith('/'):
        path = '/' + path
        
    # Remove trailing slash from base_url if exists
    if base_url.endswith('/'):
        base_url = base_url[:-1]
        
    # URL-encode the path
    encoded_path = quote(path)
    
    # Build the URL
    url = f"{base_url}{encoded_path}"
    
    # Add query parameters if provided
    if params:
        url += '?' + urlencode(params)
        
    return url
