import os
from datetime import timedelta

class AuthSettings:
    """Authentication settings"""
    
    # JWT Settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-super-secret-key-change-this-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    # Password Settings
    PWD_CONTEXT_SCHEMES: list = ["bcrypt"]
    PWD_CONTEXT_DEPRECATED: str = "auto"
    
    # Security Settings
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    
    # Admin User (Default admin account)
    DEFAULT_ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "admin123")
    DEFAULT_ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@badproxy.local")
    
    # Database file for users (SQLite)
    DATABASE_FILE: str = "badproxy_users.db"
    
    # API Key Settings (Alternative auth method)
    API_KEY_HEADER: str = "X-API-Key"
    DEFAULT_API_KEY: str = os.getenv("API_KEY", "badproxy-api-key-12345")

# Create auth settings instance
auth_settings = AuthSettings()