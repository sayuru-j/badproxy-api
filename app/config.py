class Settings:
    """Application settings"""
    
    # V2Ray Agent paths
    V2RAY_AGENT_PATH: str = "/etc/v2ray-agent"
    INSTALL_SCRIPT_PATH: str = f"{V2RAY_AGENT_PATH}/install.sh"
    CONFIG_PATH: str = f"{V2RAY_AGENT_PATH}/xray/conf"
    SUBSCRIBE_LOCAL_PATH: str = f"{V2RAY_AGENT_PATH}/subscribe_local"
    SUBSCRIBE_PATH: str = f"{V2RAY_AGENT_PATH}/subscribe"
    
    # API settings
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = False
    
    # Default values
    DEFAULT_SECURITY: str = "aes-128-gcm"
    DEFAULT_TIMEOUT: int = 30
    ALLOW_INSECURE: bool = True
    
    # Popular SNI domains for domain fronting
    POPULAR_SNI_DOMAINS = {
        "cloudflare": [
            "www.cloudflare.com",
            "blog.cloudflare.com",
            "dash.cloudflare.com"
        ],
        "microsoft": [
            "www.microsoft.com",
            "outlook.office365.com",
            "login.microsoftonline.com",
            "graph.microsoft.com"
        ],
        "zoom": [
            "m.zoom.us",
            "zoom.us",
            "www.zoom.us"
        ],
        "google": [
            "www.google.com",
            "accounts.google.com",
            "drive.google.com"
        ],
        "amazon": [
            "www.amazon.com",
            "aws.amazon.com",
            "s3.amazonaws.com"
        ],
        "akamai": [
            "www.akamai.com",
            "download.akamai.com"
        ]
    }

# Create settings instance
settings = Settings()