import os
import json
import base64
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Key management constants
KEY_DIR = os.environ.get('COOPERATIVA_KEY_DIR', 
                        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'keys'))
KEY_METADATA_FILE = 'key_metadata.json'
DEFAULT_ROTATION_DAYS = 90

# Create keys directory if it doesn't exist
os.makedirs(KEY_DIR, exist_ok=True)

# Key status constants
KEY_STATUS_ACTIVE = "active"
KEY_STATUS_INACTIVE = "inactive"
KEY_STATUS_EXPIRED = "expired"
KEY_STATUS_REVOKED = "revoked"


class KeyManagementError(Exception):
    """Exception for key management errors"""
    pass


def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Derive an encryption key from a password using PBKDF2
    
    Args:
        password: The password to derive key from
        salt: Optional salt (will generate if None)
        
    Returns:
        Tuple containing the derived key and salt
    """
    if salt is None:
        salt = os.urandom(16)  # Generate random salt
        
    # Use PBKDF2 with high iteration count
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,  # OWASP recommended minimum
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def generate_key_pair(password: Optional[str] = None, 
                     rotation_days: int = DEFAULT_ROTATION_DAYS) -> Dict[str, Any]:
    """Generate a new RSA key pair with optional password protection
    
    Args:
        password: Optional password for private key encryption
        rotation_days: Days until the key expires
        
    Returns:
        Dictionary with key information
    """
    # Generate key ID
    key_id = f"key-{secrets.token_hex(8)}-{int(datetime.now().timestamp())}"
    
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Calculate key expiry
    created_at = datetime.now()
    expires_at = created_at + timedelta(days=rotation_days)
    
    # Export public key in PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save public key to file
    public_key_path = os.path.join(KEY_DIR, f"{key_id}.pub")
    with open(public_key_path, 'wb') as f:
        f.write(public_key_pem)
    
    # Prepare key info
    key_info = {
        "key_id": key_id,
        "status": KEY_STATUS_ACTIVE,
        "created_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "public_key_path": public_key_path,
    }
    
    # Handle private key with optional encryption
    if password:
        # Encrypt private key with password
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Derive key from password
        key, salt = derive_key_from_password(password)
        fernet = Fernet(key)
        
        # Encrypt the private key
        encrypted_key = fernet.encrypt(private_key_pem)
        
        # Save encrypted private key with metadata
        private_key_data = {
            "encrypted": True,
            "data": base64.b64encode(encrypted_key).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "method": "fernet-pbkdf2"
        }
        
        key_info["password_protected"] = True
    else:
        # Save private key without encryption (not recommended for production)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        private_key_data = {
            "encrypted": False,
            "data": base64.b64encode(private_key_pem).decode('utf-8')
        }
        
        key_info["password_protected"] = False
        logger.warning("Creating an unencrypted private key is not recommended for production use")
    
    # Save private key data to file
    private_key_path = os.path.join(KEY_DIR, f"{key_id}.key")
    with open(private_key_path, 'w') as f:
        json.dump(private_key_data, f)
    
    # Set restrictive permissions on private key file
    try:
        if os.name != 'nt':  # Skip on Windows
            os.chmod(private_key_path, 0o600)  # Read-write only for owner
    except Exception as e:
        logger.warning(f"Could not set permissions on key file: {str(e)}")
    
    key_info["private_key_path"] = private_key_path
    
    # Update key metadata file
    update_key_metadata(key_info)
    
    logger.info(f"Generated new key pair with ID: {key_id}")
    return key_info


def update_key_metadata(key_info: Dict[str, Any]) -> None:
    """Update the key metadata file with new key information
    
    Args:
        key_info: Dictionary with key information to add/update
    """
    metadata_path = os.path.join(KEY_DIR, KEY_METADATA_FILE)
    
    # Read existing metadata or create new
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
        except json.JSONDecodeError:
            metadata = {"keys": {}}
    else:
        metadata = {"keys": {}}
    
    # Add/update key info
    metadata["keys"][key_info["key_id"]] = {
        "status": key_info["status"],
        "created_at": key_info["created_at"],
        "expires_at": key_info["expires_at"],
        "public_key_path": key_info["public_key_path"],
        "private_key_path": key_info["private_key_path"],
        "password_protected": key_info.get("password_protected", False)
    }
    
    # If this is an active key, deactivate previous active keys
    if key_info["status"] == KEY_STATUS_ACTIVE:
        for k_id, k_info in metadata["keys"].items():
            if k_id != key_info["key_id"] and k_info["status"] == KEY_STATUS_ACTIVE:
                metadata["keys"][k_id]["status"] = KEY_STATUS_INACTIVE
    
    # Write updated metadata
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)


def load_private_key(key_id: str, password: Optional[str] = None) -> rsa.RSAPrivateKey:
    """Load a private key, decrypting if necessary
    
    Args:
        key_id: The ID of the key to load
        password: Password for encrypted keys
        
    Returns:
        The RSA private key object
    """
    # Get key metadata
    metadata = get_key_metadata()
    
    if key_id not in metadata["keys"]:
        raise KeyManagementError(f"Key with ID {key_id} not found")
    
    key_info = metadata["keys"][key_id]
    key_path = key_info["private_key_path"]
    
    if not os.path.exists(key_path):
        raise KeyManagementError(f"Private key file not found at {key_path}")
    
    # Load key data
    with open(key_path, 'r') as f:
        key_data = json.load(f)
    
    # Handle encrypted keys
    if key_data.get("encrypted", False):
        if not password:
            raise KeyManagementError("Password required for encrypted key")
        
        try:
            # Get encrypted key and salt
            encrypted_key = base64.b64decode(key_data["data"])
            salt = base64.b64decode(key_data["salt"])
            
            # Derive key from password
            key, _ = derive_key_from_password(password, salt)
            fernet = Fernet(key)
            
            # Decrypt the key
            private_key_pem = fernet.decrypt(encrypted_key)
            
            # Load the private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            
            return private_key
        except Exception as e:
            raise KeyManagementError(f"Failed to decrypt private key: {str(e)}")
    else:
        # Load unencrypted key
        try:
            private_key_pem = base64.b64decode(key_data["data"])
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            return private_key
        except Exception as e:
            raise KeyManagementError(f"Failed to load private key: {str(e)}")


def load_public_key(key_id: str) -> rsa.RSAPublicKey:
    """Load a public key by ID
    
    Args:
        key_id: The ID of the key to load
        
    Returns:
        The RSA public key object
    """
    # Get key metadata
    metadata = get_key_metadata()
    
    if key_id not in metadata["keys"]:
        raise KeyManagementError(f"Key with ID {key_id} not found")
    
    key_info = metadata["keys"][key_id]
    key_path = key_info["public_key_path"]
    
    if not os.path.exists(key_path):
        raise KeyManagementError(f"Public key file not found at {key_path}")
    
    # Load public key
    try:
        with open(key_path, 'rb') as f:
            public_key_pem = f.read()
        
        public_key = serialization.load_pem_public_key(public_key_pem)
        return public_key
    except Exception as e:
        raise KeyManagementError(f"Failed to load public key: {str(e)}")


def get_key_metadata() -> Dict:
    """Get the metadata for all keys
    
    Returns:
        Dictionary containing key metadata
    """
    metadata_path = os.path.join(KEY_DIR, KEY_METADATA_FILE)
    
    if not os.path.exists(metadata_path):
        return {"keys": {}}
    
    try:
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        return metadata
    except Exception as e:
        raise KeyManagementError(f"Failed to load key metadata: {str(e)}")


def get_active_key_id() -> Optional[str]:
    """Get the ID of the current active key
    
    Returns:
        Key ID of active key or None if no active key exists
    """
    metadata = get_key_metadata()
    
    # Find active keys
    active_keys = [k_id for k_id, k_info in metadata["keys"].items() 
                  if k_info["status"] == KEY_STATUS_ACTIVE]
    
    if not active_keys:
        return None
    
    # If multiple active keys exist, use the most recently created one
    if len(active_keys) > 1:
        active_keys.sort(key=lambda k_id: metadata["keys"][k_id]["created_at"], reverse=True)
        logger.warning(f"Multiple active keys found, using most recent: {active_keys[0]}")
    
    return active_keys[0]


def rotate_key(password: Optional[str] = None) -> Dict[str, Any]:
    """Rotate the current active key
    
    Args:
        password: Optional password for the new key
        
    Returns:
        Dictionary with new key information
    """
    # Generate a new key pair
    new_key_info = generate_key_pair(password)
    logger.info(f"Key rotation complete. New active key: {new_key_info['key_id']}")
    
    return new_key_info


def check_key_expiration() -> List[Dict]:
    """Check for expired keys and update their status
    
    Returns:
        List of expired keys that were updated
    """
    metadata = get_key_metadata()
    now = datetime.now()
    updated_keys = []
    
    for key_id, key_info in metadata["keys"].items():
        if key_info["status"] in [KEY_STATUS_ACTIVE, KEY_STATUS_INACTIVE]:
            expires_at = datetime.fromisoformat(key_info["expires_at"])
            
            if now > expires_at:
                # Key has expired
                key_info["status"] = KEY_STATUS_EXPIRED
                updated_keys.append({
                    "key_id": key_id,
                    "expires_at": key_info["expires_at"],
                    "previous_status": KEY_STATUS_ACTIVE if key_info["status"] == KEY_STATUS_ACTIVE else KEY_STATUS_INACTIVE,
                    "new_status": KEY_STATUS_EXPIRED
                })
    
    # If any keys were updated, save the metadata
    if updated_keys:
        metadata_path = os.path.join(KEY_DIR, KEY_METADATA_FILE)
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # If the active key expired, we should generate a new one
        if any(k["previous_status"] == KEY_STATUS_ACTIVE for k in updated_keys):
            logger.warning("Active key has expired. A new key should be generated.")
    
    return updated_keys
