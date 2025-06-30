import os
import requests
import pdfplumber
import re
import json
import configparser
import logging
import pathlib
from typing import Dict, Any, Optional
from requests.exceptions import RequestException
from jose import jwt

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('importer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('pdf_importer')

# Load configuration from config file
config = configparser.ConfigParser()
config_file = pathlib.Path(__file__).parent / 'config.ini'

# Default configuration
DEFAULT_CONFIG = {
    'PATHS': {
        'PDF_DIR': os.path.expanduser('~/Documents/PDFs'),
    },
    'API': {
        'BASE_URL': 'http://127.0.0.1:8000',
        'TOKEN_URL': '/token',
        'COOPERATIVADOS_URL': '/api/cooperativados'
    },
    'AUTH': {
        'USERNAME': '',
        'PASSWORD': ''
    }
}

# If config file doesn't exist, create it with default values
if not config_file.exists():
    for section, options in DEFAULT_CONFIG.items():
        if not config.has_section(section):
            config.add_section(section)
        for option, value in options.items():
            config.set(section, option, str(value))
    
    with open(config_file, 'w') as f:
        config.write(f)
    logger.info(f"Created default configuration file at {config_file}")
    logger.warning("Please update the configuration with valid credentials")
else:
    config.read(config_file)

# Read configuration values
PDF_DIR = config.get('PATHS', 'PDF_DIR')
BASE_URL = config.get('API', 'BASE_URL')
API_URL = BASE_URL + config.get('API', 'COOPERATIVADOS_URL')
TOKEN_URL = BASE_URL + config.get('API', 'TOKEN_URL')
USERNAME = config.get('AUTH', 'USERNAME')
PASSWORD = config.get('AUTH', 'PASSWORD')

# Validate configuration
if not os.path.exists(PDF_DIR):
    logger.error(f"PDF directory does not exist: {PDF_DIR}")
    os.makedirs(PDF_DIR, exist_ok=True)
    logger.info(f"Created PDF directory: {PDF_DIR}")

if not USERNAME or not PASSWORD:
    logger.error("Authentication credentials are not configured")
    raise ValueError("Please update config.ini with valid credentials")

# Função para extrair dados básicos do texto do PDF
# Ajuste conforme o padrão dos documentos

def validate_pdf(file_path: str) -> bool:
    """Validate if the PDF file is safe to process"""
    try:
        # Check file size
        max_size_bytes = int(config.get('SECURITY', 'MAX_PDF_SIZE_MB', fallback='10')) * 1024 * 1024
        file_size = os.path.getsize(file_path)
        if file_size > max_size_bytes:
            logger.warning(f"File too large: {file_path} ({file_size} bytes)")
            return False
        
        # Check if file is actually a PDF
        with open(file_path, 'rb') as f:
            header = f.read(4)
            if header != b'%PDF':
                logger.warning(f"Not a PDF file: {file_path}")
                return False
        
        # Try to open with pdfplumber as a basic validation
        with pdfplumber.open(file_path) as pdf:
            if len(pdf.pages) == 0:
                logger.warning(f"PDF has no pages: {file_path}")
                return False
            
            # Sample the first page to verify it's readable
            try:
                pdf.pages[0].extract_text()
            except Exception as e:
                logger.warning(f"Cannot extract text from PDF: {file_path}, {str(e)}")
                return False
        
        return True
    except Exception as e:
        logger.error(f"Error validating PDF {file_path}: {str(e)}")
        return False

def sanitize_text(text: str) -> str:
    """Sanitize text extracted from PDF"""
    if not text:
        return ""
    # Remove control characters
    text = ''.join(char for char in text if ord(char) >= 32 or char == '\n')
    # Limit length
    return text[:10000]  # Reasonable limit for text fields

def extrair_campos(texto):
    """Extract and validate fields from PDF text"""
    # Sanitize input text
    texto = sanitize_text(texto)
    
    # Initialize fields with safe defaults
    result = {
        'nome': None,
        'cpf': None,
        'matricula': None,
        'valor': None,
        'parcelas': None,
        'titulo': None,
        'partido': None,
        'foto': None
    }
    
    try:
        # Nome: geralmente aparece no início
        nome_match = re.search(r'Nome[:\s]+([A-ZÁÉÍÓÚÇÂÊÎÔÛÃÕa-záéíóúçâêîôûãõ\s]+)', texto)
        if nome_match:
            result['nome'] = nome_match.group(1).strip()[:100]  # Limit length
        
        # CPF - Validate format
        cpf_match = re.search(r'CPF[:\s]+([0-9]{3}\.?[0-9]{3}\.?[0-9]{3}-?[0-9]{2})', texto)
        if cpf_match:
            cpf = cpf_match.group(1).strip()
            # Standardize CPF format
            if re.match(r'^\d{11}$', cpf.replace('.', '').replace('-', '')):
                result['cpf'] = cpf
        
        # Matrícula
        mat_match = re.search(r'Matr[ií]cula[:\s]+([0-9A-Za-z]+)', texto)
        if mat_match:
            result['matricula'] = mat_match.group(1).strip()[:20]  # Limit length
        
        # Valor - Validate is numeric
        val_match = re.search(r'Valor[:\s]+([0-9\.,]+)', texto)
        if val_match:
            valor_str = val_match.group(1).replace('.', '').replace(',', '.')
            try:
                valor = float(valor_str)
                if valor > 0:  # Ensure positive value
                    result['valor'] = valor
            except (ValueError, TypeError):
                logger.warning(f"Invalid valor format: {val_match.group(1)}")
        
        # Parcelas - Validate is positive integer
        par_match = re.search(r'Parcelas[:\s]+([0-9]+)', texto)
        if par_match:
            try:
                parcelas = int(par_match.group(1))
                if 0 < parcelas <= 1000:  # Reasonable range
                    result['parcelas'] = parcelas
            except (ValueError, TypeError):
                logger.warning(f"Invalid parcelas format: {par_match.group(1)}")
        
        # Título
        tit_match = re.search(r'T[ií]tulo[:\s]+(\S[\w\s]{0,49})', texto)
        if tit_match:
            result['titulo'] = tit_match.group(1).strip()
        
        # Partido
        part_match = re.search(r'Partido[:\s]+(\S[\w\s]{0,49})', texto)
        if part_match:
            result['partido'] = part_match.group(1).strip()
            
        logger.info(f"Successfully extracted fields: nome={result['nome']}, matricula={result['matricula']}")
    except Exception as e:
        logger.error(f"Error extracting fields: {str(e)}")
        
    return result

def get_auth_token() -> str:
    """Get authentication token from API"""
    try:
        logger.info(f"Authenticating as {USERNAME}")
        response = requests.post(
            TOKEN_URL,
            data={"username": USERNAME, "password": PASSWORD},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if response.status_code != 200:
            logger.error(f"Authentication failed: {response.status_code} {response.text}")
            raise ValueError(f"Authentication failed: {response.status_code}")
            
        token_data = response.json()
        return token_data["access_token"]
    except Exception as e:
        logger.error(f"Error during authentication: {str(e)}")
        raise

def add_cooperativado(data: dict, token: str) -> bool:
    """Add cooperativado with authentication token"""
    try:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = requests.post(API_URL, json=data, headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            logger.info(f"Successfully added cooperativado: {data['matricula']}")
            return True
        else:
            logger.error(f"Failed to add cooperativado: {response.status_code} {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error adding cooperativado: {str(e)}")
        return False

def importar_pdfs():
    """Import PDFs with security enhancements"""
    try:
        # Get authentication token
        token = get_auth_token()
        logger.info("Successfully authenticated")
        
        # Track statistics
        stats = {"processed": 0, "success": 0, "failed": 0, "skipped": 0}
        matriculas_usadas = set()
        idx = 1
        
        # Process each PDF file
        pdf_files = [f for f in os.listdir(PDF_DIR) if f.lower().endswith('.pdf')]
        logger.info(f"Found {len(pdf_files)} PDF files to process")
        
        for filename in pdf_files:
            path = os.path.join(PDF_DIR, filename)
            stats["processed"] += 1
            
            try:
                # Validate PDF first
                if config.getboolean('SECURITY', 'VALIDATE_PDF', fallback=True) and not validate_pdf(path):
                    logger.warning(f"Skipping invalid PDF: {filename}")
                    stats["skipped"] += 1
                    continue
                
                # Extract text with proper error handling
                texto = ''
                try:
                    with pdfplumber.open(path) as pdf:
                        for page in pdf.pages:
                            page_text = page.extract_text() or ''
                            texto += page_text + '\n'
                except Exception as e:
                    logger.error(f"Error processing PDF {filename}: {str(e)}")
                    stats["failed"] += 1
                    continue
                    
                # Extract and validate fields
                campos = extrair_campos(texto)
                
                # Ensure we have required fields
                if not campos['nome']:
                    campos['nome'] = os.path.splitext(filename)[0][:100]  # Use filename with limit
                
                # Generate unique matricula if needed
                base_matricula = campos['matricula'] or os.path.splitext(filename)[0].replace(' ', '_')
                base_matricula = re.sub(r'[^\w]', '_', base_matricula)[:20]  # Sanitize and limit length
                
                matricula = base_matricula
                while matricula in matriculas_usadas:
                    idx += 1
                    matricula = f"{base_matricula[:15]}_{idx}"
                    
                matriculas_usadas.add(matricula)
                campos['matricula'] = matricula
                
                # Ensure valid CPF format or empty
                if not campos['cpf']:
                    campos['cpf'] = ''
                
                # Validate data before sending to API
                for key in ['valor', 'parcelas']:
                    if not isinstance(campos[key], (int, float)) and campos[key] is not None:
                        campos[key] = None
                
                # Sanitize text fields
                for key in ['titulo', 'partido']:
                    if campos[key]:
                        campos[key] = campos[key][:50]
                
                logger.info(f"Importing: {campos['matricula']} - {campos['nome']}")
                
                # Send to API with authentication
                if add_cooperativado(campos, token):
                    stats["success"] += 1
                else:
                    stats["failed"] += 1
                    
            except Exception as e:
                logger.error(f"Unexpected error processing {filename}: {str(e)}")
                stats["failed"] += 1
        
        # Report statistics
        logger.info(f"Import completed: {stats['processed']} processed, {stats['success']} successful, " 
                   f"{stats['failed']} failed, {stats['skipped']} skipped")
        return stats
        
    except Exception as e:
        logger.error(f"Critical error during import process: {str(e)}")
        return {"error": str(e)}

if __name__ == '__main__':
    try:
        stats = importar_pdfs()
        print(f"Import completed: {stats}")
    except Exception as e:
        print(f"Import failed: {str(e)}")
        logger.critical(f"Import process failed: {str(e)}")
