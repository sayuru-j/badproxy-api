from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from app.models.vmess import (
    VMessUsersResponse, VMessConfigResponse, CustomVMessRequest, 
    CustomVMessResponse, PopularSNIResponse
)
from app.services.system import system_service
from app.services.v2ray import v2ray_service
from app.services.vmess import vmess_service
from app.utils.constants import ConfigFormat
from app.config import settings

router = APIRouter()

@router.get("/users", response_model=VMessUsersResponse)
async def get_vmess_users(
    config_file: Optional[str] = Query(None, description="Specific config file to read (e.g., '03_VMess_WS_inbounds.json')")
):
    """Get all users with VMess configurations
    
    Args:
        config_file: Optional specific config file to read. If not provided, will auto-detect VMess files.
    """
    if not system_service.check_v2ray_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    vmess_users = []
    
    # If specific config file is provided, use it
    if config_file:
        if not v2ray_service.validate_config_file(config_file):
            raise HTTPException(status_code=404, detail=f"Config file {config_file} not found")
        
        config_file_path = f"{settings.CONFIG_PATH}/{config_file}"
        vmess_users = vmess_service.get_vmess_users_from_config(config_file_path)
    else:
        # Auto-detect VMess config files
        config_files_to_check = vmess_service.find_vmess_config_files()
        
        for config_file_path in config_files_to_check:
            users = vmess_service.get_vmess_users_from_config(config_file_path)
            vmess_users.extend(users)
    
    return VMessUsersResponse(
        total_vmess_users=len(vmess_users),
        users=vmess_users
    )

@router.get("/users/{email}", response_model=VMessConfigResponse)
async def get_user_vmess_config(
    email: str,
    format: ConfigFormat = Query(ConfigFormat.v2ray, description="Output format"),
    sni: Optional[str] = Query(None, description="Custom SNI for domain fronting (e.g., m.zoom.us)")
):
    """Get VMess configuration for a user
    
    Args:
        email: User email
        format: Output format - 'subscription' (base64 link), 'decoded' (JSON), 'v2ray' (full config)
        sni: Custom SNI for domain fronting
    """
    if not system_service.check_v2ray_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    vmess_config = vmess_service.parse_vmess_from_subscription(email)
    
    if not vmess_config:
        raise HTTPException(status_code=404, detail=f"No VMess configuration found for user {email}")
    
    if format == ConfigFormat.subscription:
        return VMessConfigResponse(
            email=email,
            format="subscription",
            vmess_link=vmess_config["vmess_link"],
            note="Base64 encoded VMess subscription link"
        )
    elif format == ConfigFormat.decoded:
        return VMessConfigResponse(
            email=email,
            format="decoded",
            vmess_config=vmess_config["vmess_decoded"],
            note="Decoded VMess JSON configuration"
        )
    elif format == ConfigFormat.v2ray:
        # Generate config with custom SNI if provided
        v2ray_config = vmess_service.convert_vmess_to_v2ray_config(vmess_config["vmess_base_config"], sni)
        
        response = VMessConfigResponse(
            email=email,
            format="v2ray",
            v2ray_config=v2ray_config
        )
        
        # Add SNI information to response
        if sni:
            response.custom_sni = sni
            response.note = f"Using custom SNI: {sni} for domain fronting with allowInsecure=true"
        else:
            original_sni = vmess_config["vmess_base_config"].get("sni", vmess_config["vmess_base_config"].get("host", ""))
            response.original_sni = original_sni
            response.note = f"Using original SNI: {original_sni}. Add ?sni=your-domain.com for custom SNI"
        
        return response

@router.post("/users/{email}/generate", response_model=CustomVMessResponse)
async def generate_custom_vmess_config(email: str, request: CustomVMessRequest):
    """Generate custom VMess V2Ray configuration with specific SNI
    
    Args:
        email: User email
        request: Custom configuration request with SNI and security settings
    """
    if not system_service.check_v2ray_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    vmess_config = vmess_service.parse_vmess_from_subscription(email)
    
    if not vmess_config:
        raise HTTPException(status_code=404, detail=f"No VMess configuration found for user {email}")
    
    base_config = vmess_config["vmess_base_config"]
    
    # Create custom configuration
    custom_config = {
        "outbounds": [{
            "mux": {},
            "protocol": "vmess",
            "sendThrough": "0.0.0.0",
            "settings": {
                "vnext": [{
                    "address": base_config.get("add", ""),
                    "port": int(base_config.get("port", 443)),
                    "users": [{
                        "id": base_config.get("id", ""),
                        "security": request.security or base_config.get("scy", settings.DEFAULT_SECURITY),
                        "alterId": int(base_config.get("aid", 0))
                    }]
                }]
            },
            "streamSettings": {
                "network": base_config.get("net", "ws"),
                "security": base_config.get("tls", "tls"),
                "tlsSettings": {
                    "allowInsecure": settings.ALLOW_INSECURE,
                    "disableSystemRoot": False,
                    "serverName": request.sni  # Custom SNI here
                },
                "wsSettings": {
                    "headers": {
                        "Host": base_config.get("host", "")
                    },
                    "path": base_config.get("path", "/")
                },
                "xtlsSettings": {
                    "disableSystemRoot": False
                }
            },
            "tag": "PROXY"
        }]
    }
    
    return CustomVMessResponse(
        email=email,
        custom_config=custom_config,
        settings={
            "custom_sni": request.sni,
            "original_host": base_config.get("host", ""),
            "security": request.security or base_config.get("scy", settings.DEFAULT_SECURITY),
            "allow_insecure": settings.ALLOW_INSECURE,
            "server_address": base_config.get("add", ""),
            "server_port": int(base_config.get("port", 443)),
            "websocket_path": base_config.get("path", "/")
        },
        note="This config uses custom SNI for domain fronting with allowInsecure=true"
    )

@router.get("/popular-sni", response_model=PopularSNIResponse)
async def get_popular_sni_domains():
    """Get list of popular SNI domains for domain fronting"""
    popular_domains = vmess_service.get_popular_sni_domains()
    
    return PopularSNIResponse(
        popular_sni_domains=popular_domains,
        note="These domains are commonly used for domain fronting to bypass censorship",
        usage="Use any of these as the 'sni' parameter in your VMess configuration requests"
    )