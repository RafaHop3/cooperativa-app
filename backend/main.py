from fastapi import FastAPI, HTTPException, Depends, status, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, validator, constr, EmailStr
import sqlite3
from typing import List, Optional, Annotated, Dict, Any
import os
import re
from datetime import timedelta, datetime
import secrets
from loguru import logger
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import json

# Import authentication module
from auth import (
    User, Token, get_current_active_user, get_admin_user,
    authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
)

# Import activity logging module
from activity_logger import log_activity, get_activities, ActivityLog

# Setup logging
logger.add("app.log", rotation="10 MB", retention="1 week", level="INFO")

# Banco de dados
DB_PATH = os.path.join(os.path.dirname(__file__), 'cooperativa.db')

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Create a secure database connection function
def get_db_connection():
    """Create a secure database connection with proper error handling"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database connection error")

def init_db():
    """Initialize database with proper error handling"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create cooperativados table with improved schema
        cursor.execute('''CREATE TABLE IF NOT EXISTS cooperativados (
            matricula TEXT PRIMARY KEY,
            nome TEXT NOT NULL,
            cpf TEXT NOT NULL,
            valor REAL,
            parcelas INTEGER,
            titulo TEXT,
            partido TEXT,
            foto TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT
        )''')
        
        # Create fotos table with improved schema
        cursor.execute('''CREATE TABLE IF NOT EXISTS fotos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            descricao TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT
        )''')
        
        # Add audit log table
        cursor.execute('''CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            table_name TEXT NOT NULL,
            record_id TEXT NOT NULL,
            user_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database initialization error")

# Initialize database
init_db()

# Create FastAPI app with rate limiter
app = FastAPI()
app.state.limiter = limiter

# Configure CORS - restrict to localhost/127.0.0.1 origins
origins = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://localhost:5000",
    "https://127.0.0.1:5000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "DELETE", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
)

# Add security middlewares
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "*"])

# Environment check for production mode
PRODUCTION_MODE = os.environ.get("COOPERATIVA_ENV", "").lower() == "production"

# Enable HTTPS redirect in production
if PRODUCTION_MODE:
    app.add_middleware(HTTPSRedirectMiddleware)
    logger.info("HTTPS redirect middleware enabled in production mode")

# Create middleware for adding security headers
# Add audit logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Log the request
    logger.info(f"Request: {request.method} {request.url.path}")
    
    # Process the request and get the response
    response = await call_next(request)
    
    # Log the response status
    logger.info(f"Response status: {response.status_code}")
    
    return response

# Enhanced Pydantic models with validation
class Cooperativado(BaseModel):
    matricula: constr(min_length=1, max_length=20) 
    nome: constr(min_length=2, max_length=100)
    cpf: constr(min_length=11, max_length=14) = ''
    valor: Optional[float] = None
    parcelas: Optional[int] = None
    titulo: Optional[constr(max_length=50)] = None
    partido: Optional[constr(max_length=50)] = None
    foto: Optional[constr(max_length=255)] = None
    
    # Input validation for CPF format
    @validator('cpf')
    def validate_cpf(cls, v):
        if v and not re.match(r'^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$', v):
            raise ValueError('CPF deve estar no formato XXX.XXX.XXX-XX ou 11 dígitos')
        return v
    
    # Validate foto URL format if provided
    @validator('foto')
    def validate_foto_url(cls, v):
        if v and not v.startswith(('http://', 'https://')):
            raise ValueError('URL deve começar com http:// ou https://')
        return v
    
    # Validate valor is positive if provided
    @validator('valor')
    def validate_valor(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Valor deve ser positivo')
        return v
    
    # Validate parcelas is positive if provided
    @validator('parcelas')
    def validate_parcelas(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Número de parcelas deve ser positivo')
        return v

# Authentication endpoints
@app.post("/token", response_model=Token)
@limiter.limit("5/minute")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        logger.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logger.info(f"Successful login for user: {user.username}")
    return {"access_token": access_token, "token_type": "bearer"}

# User management endpoints (admin only)
@app.post("/api/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    role: str = Form("user"),
    current_user: User = Depends(get_admin_user)
):
    # Check if username already exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Insert new user
    from auth import get_password_hash
    hashed_password = get_password_hash(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, email, full_name, hashed_password, role) VALUES (?, ?, ?, ?, ?)",
            (username, email, full_name, hashed_password, role)
        )
        conn.commit()
        logger.info(f"User {username} created by {current_user.username}")
        conn.close()
        return {"status": "success", "message": f"User {username} created successfully"}
    except Exception as e:
        conn.close()
        logger.error(f"Error creating user: {str(e)}")
        raise HTTPException(status_code=500, detail="Error creating user")

# Enhanced API endpoints with authentication and improved database security
@app.get("/api/cooperativados", response_model=List[Cooperativado])
async def listar_cooperativados(current_user: User = Depends(get_current_active_user)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT matricula, nome, cpf, valor, parcelas, titulo, partido, foto FROM cooperativados")
        rows = cursor.fetchall()
        conn.close()
        
        result = []
        for row in rows:
            try:
                coop = Cooperativado(
                    matricula=row[0], 
                    nome=row[1], 
                    cpf=row[2] if row[2] else '', 
                    valor=row[3], 
                    parcelas=row[4], 
                    titulo=row[5], 
                    partido=row[6], 
                    foto=row[7]
                )
                result.append(coop)
            except Exception as e:
                logger.warning(f"Invalid cooperativado data: {str(e)}")
        
        logger.info(f"User {current_user.username} retrieved cooperativados list")
        return result
    except Exception as e:
        logger.error(f"Error retrieving cooperativados: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving cooperativados")

@app.get("/api/fotos", response_model=List[str])
async def listar_fotos(current_user: User = Depends(get_current_active_user)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM fotos")
        rows = cursor.fetchall()
        conn.close()
        
        # Validate URLs before returning
        urls = []
        for row in rows:
            url = row[0]
            if url and (url.startswith('http://') or url.startswith('https://')):
                urls.append(url)
            else:
                logger.warning(f"Skipping invalid URL format: {url}")
        
        logger.info(f"User {current_user.username} retrieved photos list")
        return urls
    except Exception as e:
        logger.error(f"Error retrieving photos: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving photos")

# Endpoint para adicionar cooperativado com autenticação e log de auditoria
@app.post("/api/cooperativados")
async def adicionar_cooperativado(coop: Cooperativado, current_user: User = Depends(get_current_active_user)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert into cooperativados with audit fields
        try:
            cursor.execute(
                """INSERT INTO cooperativados 
                    (matricula, nome, cpf, valor, parcelas, titulo, partido, foto, created_by) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (coop.matricula, coop.nome, coop.cpf or '', coop.valor, 
                coop.parcelas, coop.titulo, coop.partido, coop.foto, current_user.username)
            )
            
            # Add audit log entry
            cursor.execute(
                "INSERT INTO audit_log (action, table_name, record_id, user_id, details) VALUES (?, ?, ?, ?, ?)",
                ('CREATE', 'cooperativados', coop.matricula, current_user.username, f"Added cooperativado: {coop.nome}")
            )
            
            conn.commit()
            logger.info(f"User {current_user.username} added cooperativado {coop.matricula}")
        except sqlite3.IntegrityError:
            conn.close()
            logger.warning(f"User {current_user.username} attempted to add duplicate matricula: {coop.matricula}")
            raise HTTPException(status_code=400, detail="Matrícula já cadastrada.")
        
        conn.close()
        return {"status": "ok", "message": "Cooperativado adicionado com sucesso"}
    except Exception as e:
        logger.error(f"Error adding cooperativado: {str(e)}")
        raise HTTPException(status_code=500, detail="Error adding cooperativado")

# Endpoint para adicionar foto com autenticação e validação
@app.post("/api/fotos", status_code=status.HTTP_201_CREATED)
async def adicionar_foto(
    url: constr(min_length=10, max_length=255),
    descricao: Optional[str] = None,
    current_user: User = Depends(get_current_active_user)
):
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert with audit information
        cursor.execute(
            "INSERT INTO fotos (url, descricao, created_by) VALUES (?, ?, ?)", 
            (url, descricao, current_user.username)
        )
        
        # Get the ID of the inserted photo
        foto_id = cursor.lastrowid
        
        # Log da ação para auditoria
        cursor.execute(
            "INSERT INTO audit_log (action, table_name, record_id, user_id, details) VALUES (?, ?, ?, ?, ?)",
            ('add', 'fotos', str(foto_id), current_user.username, f"URL: {url}")
        )
        
        # Log to activity log system
        log_activity(
            user_id=current_user.username,
            activity_type="add_photo",
            details={"photo_id": foto_id, "url": url, "description": descricao},
            ip_address=None
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"User {current_user.username} added new photo with ID {foto_id}")
        return {"id": foto_id, "url": url}
    except Exception as e:
        logger.error(f"Error adding photo: {str(e)}")
        raise HTTPException(status_code=500, detail="Error adding photo")

# Activity Logging Endpoints

@app.post("/api/activity-log", status_code=status.HTTP_201_CREATED)
async def record_activity(
    activity: ActivityLog,
    current_user: User = Depends(get_current_active_user),
    request: Request = None
):
    """
    Record a user activity from the frontend
    """
    try:
        # Use the current user's ID from authentication
        user_id = current_user.username
        
        # Get client IP if request is available
        ip_address = request.client.host if request else None
        
        # Log the activity
        log_id = log_activity(
            user_id=user_id,
            activity_type=activity.activity_type,
            details=activity.details,
            ip_address=ip_address
        )
        
        return {"id": log_id, "status": "recorded"}
    except Exception as e:
        logger.error(f"Error recording activity: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to record activity: {str(e)}")

@app.get("/api/activity-logs")
async def get_activity_logs(
    limit: int = 100,
    offset: int = 0,
    user_id: Optional[str] = None,
    activity_type: Optional[str] = None,
    current_user: User = Depends(get_admin_user)  # Only admins can view all logs
):
    """
    Retrieve activity logs with filtering options
    """
    try:
        logs = get_activities(
            limit=limit,
            offset=offset,
            user_id=user_id,
            activity_type=activity_type
        )
        return {"total": len(logs), "logs": logs}
    except Exception as e:
        logger.error(f"Error retrieving activity logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve activity logs: {str(e)}")
