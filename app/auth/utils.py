import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Union
from passlib.context import CryptContext
from jose import JWTError, jwt

from app.auth.config import auth_settings
from app.auth.database import user_db
from app.models.auth import TokenData

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(
    schemes=auth_settings.PWD_CONTEXT_SCHEMES,
    deprecated=auth_settings.PWD_CONTEXT_DEPRECATED
)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)

def generate_api_key() -> str:
    """Generate a secure API key"""
    return f"bp_{secrets.token_urlsafe(32)}"

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, auth_settings.SECRET_KEY, algorithm=auth_settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[TokenData]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, auth_settings.SECRET_KEY, algorithms=[auth_settings.ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        scopes: list = payload.get("scopes", [])
        
        if username is None or user_id is None:
            return None
            
        return TokenData(username=username, user_id=user_id, scopes=scopes)
    except JWTError:
        return None

def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate user with username and password"""
    user = user_db.get_user_by_username(username)
    if not user:
        return None
    
    if not user["is_active"]:
        return None
    
    # Check if user is locked
    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.utcnow() < locked_until:
            return None
    
    if not verify_password(password, user["hashed_password"]):
        # Increment failed login attempts
        user_db.increment_failed_login(user["id"])
        
        # Lock account if too many failed attempts
        if user["failed_login_attempts"] >= auth_settings.MAX_LOGIN_ATTEMPTS - 1:
            lock_until = datetime.utcnow() + timedelta(minutes=auth_settings.LOCKOUT_DURATION_MINUTES)
            # TODO: Implement account locking in database
        
        return None
    
    # Update last login
    user_db.update_last_login(user["id"])
    
    return user

def create_default_admin():
    """Create default admin user if it doesn't exist"""
    try:
        existing_admin = user_db.get_user_by_username(auth_settings.DEFAULT_ADMIN_USERNAME)
        if not existing_admin:
            hashed_password = get_password_hash(auth_settings.DEFAULT_ADMIN_PASSWORD)
            user_id = user_db.create_user(
                username=auth_settings.DEFAULT_ADMIN_USERNAME,
                email=auth_settings.DEFAULT_ADMIN_EMAIL,
                hashed_password=hashed_password,
                full_name="Default Admin",
                is_admin=True
            )
            
            if user_id:
                logger.info(f"Default admin user created with ID: {user_id}")
                
                # Create default API key
                api_key = auth_settings.DEFAULT_API_KEY
                user_db.create_api_key("Default API Key", api_key, user_id)
                logger.info("Default API key created")
            else:
                logger.error("Failed to create default admin user")
        else:
            logger.info("Default admin user already exists")
    except Exception as e:
        logger.error(f"Error creating default admin: {e}")

def init_auth_system():
    """Initialize authentication system"""
    logger.info("Initializing authentication system...")
    create_default_admin()
    logger.info("Authentication system initialized")