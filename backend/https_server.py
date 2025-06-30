"""
HTTPS Server configuration for cooperativa-app
This module provides secure HTTPS server setup for the FastAPI backend
"""

import os
import ssl
import uvicorn
from pathlib import Path
from loguru import logger

# Default certificate paths
CERT_DIR = Path(os.path.dirname(os.path.abspath(__file__))) / "certs"
SSL_CERT_FILE = CERT_DIR / "server.crt"
SSL_KEY_FILE = CERT_DIR / "server.key"

def generate_self_signed_cert():
    """Generate a self-signed certificate for development purposes only"""
    try:
        # Ensure certificate directory exists
        os.makedirs(CERT_DIR, exist_ok=True)
        
        # Only generate if certs don't already exist
        if SSL_CERT_FILE.exists() and SSL_KEY_FILE.exists():
            logger.info("SSL certificates already exist")
            return True
        
        logger.info("Generating self-signed SSL certificate...")
        
        # Generate a key
        os.system(f"openssl genrsa -out {SSL_KEY_FILE} 2048")
        
        # Generate a certificate signing request
        os.system(f"openssl req -new -key {SSL_KEY_FILE} -out {CERT_DIR / 'server.csr'} "
                  f"-subj '/CN=localhost/O=Cooperativa/C=BR'")
        
        # Generate a self-signed certificate
        os.system(f"openssl x509 -req -days 365 -in {CERT_DIR / 'server.csr'} "
                  f"-signkey {SSL_KEY_FILE} -out {SSL_CERT_FILE}")
        
        if SSL_CERT_FILE.exists() and SSL_KEY_FILE.exists():
            logger.info("SSL certificates successfully generated")
            return True
        else:
            logger.error("Failed to generate SSL certificates")
            return False
            
    except Exception as e:
        logger.error(f"Error generating SSL certificates: {str(e)}")
        return False


def setup_letsencrypt_cert(domain):
    """Set up Let's Encrypt certificate for production deployment
    
    This function requires certbot to be installed on the server.
    Run: pip install certbot
    
    Args:
        domain: Domain name for the certificate (e.g., cooperativa-app.example.com)
        
    Returns:
        bool: True if certificate was successfully obtained, False otherwise
    """
    try:
        logger.info(f"Requesting Let's Encrypt certificate for {domain}")
        
        # Define certificate paths
        letsencrypt_cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        letsencrypt_key = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        
        # Check if certificates already exist
        if os.path.exists(letsencrypt_cert) and os.path.exists(letsencrypt_key):
            logger.info("Let's Encrypt certificates already exist")
            
            # Create symlinks to the app's certificate directory
            os.makedirs(CERT_DIR, exist_ok=True)
            if os.path.exists(SSL_CERT_FILE):
                os.remove(SSL_CERT_FILE)
            if os.path.exists(SSL_KEY_FILE):
                os.remove(SSL_KEY_FILE)
                
            # Create symlinks
            os.symlink(letsencrypt_cert, SSL_CERT_FILE)
            os.symlink(letsencrypt_key, SSL_KEY_FILE)
            
            logger.info("Symlinks to Let's Encrypt certificates created")
            return True
        
        # Request new certificate using certbot
        cmd = f"certbot certonly --standalone -d {domain} --agree-tos --non-interactive"
        result = os.system(cmd)
        
        if result == 0 and os.path.exists(letsencrypt_cert) and os.path.exists(letsencrypt_key):
            # Create symlinks to the app's certificate directory
            os.makedirs(CERT_DIR, exist_ok=True)
            if os.path.exists(SSL_CERT_FILE):
                os.remove(SSL_CERT_FILE)
            if os.path.exists(SSL_KEY_FILE):
                os.remove(SSL_KEY_FILE)
                
            # Create symlinks
            os.symlink(letsencrypt_cert, SSL_CERT_FILE)
            os.symlink(letsencrypt_key, SSL_KEY_FILE)
            
            logger.info(f"Let's Encrypt certificates obtained and linked for {domain}")
            
            # Setup auto-renewal
            renewal_cmd = "(crontab -l 2>/dev/null; echo '0 0 * * * certbot renew --quiet && systemctl restart cooperativa-app') | crontab -"
            os.system(renewal_cmd)
            logger.info("Certificate auto-renewal configured")
            
            return True
        else:
            logger.error("Failed to obtain Let's Encrypt certificates")
            return False
            
    except Exception as e:
        logger.error(f"Error setting up Let's Encrypt certificates: {str(e)}")
        return False


def create_ssl_context():
    """Create an SSL context for the HTTPS server"""
    try:
        # Generate certificate if needed
        if not (SSL_CERT_FILE.exists() and SSL_KEY_FILE.exists()):
            generate_self_signed_cert()
        
        # Create SSL context
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(str(SSL_CERT_FILE), str(SSL_KEY_FILE))
        
        # Configure secure settings
        ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
        ssl_context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
        
        return ssl_context
    except Exception as e:
        logger.error(f"Error creating SSL context: {str(e)}")
        return None


def run_https_server(app, host="0.0.0.0", port=8443):
    """Run the FastAPI app with HTTPS"""
    try:
        ssl_context = create_ssl_context()
        
        if not ssl_context:
            logger.error("Failed to create SSL context, falling back to HTTP")
            uvicorn.run(app, host=host, port=8000)
            return
        
        logger.info(f"Starting HTTPS server on {host}:{port}")
        uvicorn.run(
            app,
            host=host,
            port=port,
            ssl_keyfile=str(SSL_KEY_FILE),
            ssl_certfile=str(SSL_CERT_FILE)
        )
    except Exception as e:
        logger.error(f"Error running HTTPS server: {str(e)}")
        logger.info("Falling back to HTTP server")
        uvicorn.run(app, host=host, port=8000)


if __name__ == "__main__":
    # Test certificate generation
    generate_self_signed_cert()
