"""Digital Signature System for Cooperativa App Activity Logs

This module provides cryptographic signing and verification for activity logs,
ensuring tamper-evident audit trails for sensitive operations.
"""

import os
import json
import base64
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Union, Optional, Tuple

# For cryptography - using a widely trusted library
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

# Set up logging
logging = logging.getLogger(__name__)

# Configuration
KEY_DIRECTORY = os.environ.get(
    "COOPERATIVA_KEY_DIR",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "secure_keys")
)

# Ensure key directory exists
Path(KEY_DIRECTORY).mkdir(parents=True, exist_ok=True)

# Default key locations
DEFAULT_PRIVATE_KEY_PATH = os.path.join(KEY_DIRECTORY, "log_signing_private.pem")
DEFAULT_PUBLIC_KEY_PATH = os.path.join(KEY_DIRECTORY, "log_signing_public.pem")


def generate_key_pair(private_key_path: str = DEFAULT_PRIVATE_KEY_PATH,
                    public_key_path: str = DEFAULT_PUBLIC_KEY_PATH,
                    key_size: int = 2048,
                    force: bool = False) -> bool:
    """Generate a new RSA key pair for signing and verification.
    
    Args:
        private_key_path: Path to save the private key
        public_key_path: Path to save the public key
        key_size: RSA key size in bits
        force: If True, overwrite existing keys
        
    Returns:
        bool: True if keys were generated or already existed
    """
    # Check if keys already exist
    if not force and (os.path.exists(private_key_path) and os.path.exists(public_key_path)):
        logging.info("Signing keys already exist. Use force=True to regenerate.")
        return True
    
    try:
        # Generate a new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard for RSA
            key_size=key_size
        )
        public_key = private_key.public_key()
        
        # Serialize private key with high security
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # In production, use BestAvailableEncryption
        )
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Write keys to files with restricted permissions
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        os.chmod(private_key_path, 0o600)  # Only owner can read/write
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        os.chmod(public_key_path, 0o644)  # Owner can read/write, others can read
        
        logging.info(f"Generated new signing key pair at {KEY_DIRECTORY}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to generate key pair: {e}")
        return False


def load_private_key(key_path: str = DEFAULT_PRIVATE_KEY_PATH) -> Any:
    """Load the private key from file."""
    try:
        with open(key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None  # In production, use password protection
            )
        return private_key
    except Exception as e:
        logging.error(f"Failed to load private key: {e}")
        raise


def load_public_key(key_path: str = DEFAULT_PUBLIC_KEY_PATH) -> Any:
    """Load the public key from file."""
    try:
        with open(key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key
    except Exception as e:
        logging.error(f"Failed to load public key: {e}")
        raise


def sign_log_data(data: Dict[str, Any], private_key_path: str = DEFAULT_PRIVATE_KEY_PATH) -> str:
    """Sign log data with RSA private key.
    
    Args:
        data: Dictionary of log data to sign
        private_key_path: Path to the private key file
        
    Returns:
        str: Base64-encoded signature
    """
    try:
        # Create a normalized representation of the data
        # First remove any existing signature field
        data_to_sign = {k: v for k, v in data.items() if k != "signature"}
        
        # Create a canonical representation (sorted keys, consistent format)
        canonical_data = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))
        data_bytes = canonical_data.encode('utf-8')
        
        # Load the private key and sign
        private_key = load_private_key(private_key_path)
        signature = private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Return base64 encoded signature
        return base64.b64encode(signature).decode('ascii')
        
    except Exception as e:
        logging.error(f"Failed to sign log data: {e}")
        raise


def verify_log_signature(data: Dict[str, Any], signature: str,
                       public_key_path: str = DEFAULT_PUBLIC_KEY_PATH) -> bool:
    """Verify the signature of log data.
    
    Args:
        data: Dictionary of log data (without signature field)
        signature: Base64-encoded signature to verify
        public_key_path: Path to the public key file
        
    Returns:
        bool: True if signature is valid
    """
    try:
        # Create a normalized representation of the data
        # Make sure we don't include the signature field in verification
        data_to_verify = {k: v for k, v in data.items() if k != "signature"}
        
        # Create a canonical representation (sorted keys, consistent format)
        canonical_data = json.dumps(data_to_verify, sort_keys=True, separators=(',', ':'))
        data_bytes = canonical_data.encode('utf-8')
        
        # Decode the signature from base64
        signature_bytes = base64.b64decode(signature)
        
        # Load the public key and verify
        public_key = load_public_key(public_key_path)
        public_key.verify(
            signature_bytes,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # If we get here without an exception, the signature is valid
        return True
        
    except InvalidSignature:
        logging.warning("Invalid signature detected - possible tampering")
        return False
    except Exception as e:
        logging.error(f"Error during signature verification: {e}")
        return False


def sign_activity_log(activity_data: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Sign a complete activity log entry.
    
    This is the main function to use from the activity logger.
    
    Args:
        activity_data: The complete activity log data
        
    Returns:
        Tuple containing:
            - Updated activity data with signature metadata
            - The signature string
    """
    # Ensure we have the necessary keys
    if not (os.path.exists(DEFAULT_PRIVATE_KEY_PATH) and os.path.exists(DEFAULT_PUBLIC_KEY_PATH)):
        generate_key_pair()
    
    # Add signature metadata
    signed_data = dict(activity_data)
    signed_data["signature_metadata"] = {
        "timestamp": datetime.utcnow().isoformat(),
        "key_id": "default"  # In production, use real key IDs for rotation
    }
    
    # Generate the signature
    signature = sign_log_data(signed_data)
    
    # Add the signature to the data
    signed_data["signature"] = signature
    
    return signed_data, signature


def verify_activity_log(activity_data: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the signature on an activity log entry.
    
    Args:
        activity_data: The complete activity log data with signature
        
    Returns:
        Dict containing verification results
    """
    # Check if the log has a signature
    if "signature" not in activity_data:
        return {"verified": False, "reason": "No signature found"}
    
    # Extract the signature
    signature = activity_data["signature"]
    
    # Verify the signature
    is_valid = verify_log_signature(activity_data, signature)
    
    if is_valid:
        return {
            "verified": True,
            "timestamp": activity_data.get("signature_metadata", {}).get("timestamp"),
            "key_id": activity_data.get("signature_metadata", {}).get("key_id", "unknown")
        }
    else:
        return {"verified": False, "reason": "Invalid signature"}


# Generate keys on module import if they don't exist
if not (os.path.exists(DEFAULT_PRIVATE_KEY_PATH) and os.path.exists(DEFAULT_PUBLIC_KEY_PATH)):
    generate_key_pair()
