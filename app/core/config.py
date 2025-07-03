from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # API Settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # V2Ray-Agent Script Settings
    V2RAY_SCRIPT_PATH: str = "/root/v2ray-agent/install.sh"
    V2RAY_CONFIG_DIR: str = "/etc/v2ray-agent"
    XRAY_CONFIG_PATH: str = "/etc/v2ray-agent/xray/conf"
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-this"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "/var/log/v2ray-api.log"
    
    class Config:
        env_file = ".env"

settings = Settings()
