from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import subprocess
import json
import os
import logging
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="BadProxy API",
    description="VMess Management API for v2ray-agent with domain fronting support",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
V2RAY_AGENT_PATH = "/etc/v2ray-agent"
INSTALL_SCRIPT_PATH = f"{V2RAY_AGENT_PATH}/install.sh"
CONFIG_PATH = f"{V2RAY_AGENT_PATH}/xray/conf"

# Enums
class ServiceStatus(str, Enum):
    running = "running"
    stopped = "stopped"
    unknown = "unknown"

class ConfigFormat(str, Enum):
    subscription = "subscription"
    decoded = "decoded"
    v2ray = "v2ray"

# Pydantic Models
class ServiceStatusResponse(BaseModel):
    service: str
    status: ServiceStatus
    pid: Optional[int] = None
    uptime: Optional[str] = None

class VMessUser(BaseModel):
    email: str
    uuid: str
    has_subscription: bool
    vmess_available: bool

class VMessUsersResponse(BaseModel):
    total_vmess_users: int
    users: List[VMessUser]

class VMessConfigResponse(BaseModel):
    email: str
    format: str
    vmess_link: Optional[str] = None
    vmess_config: Optional[Dict[str, Any]] = None
    v2ray_config: Optional[Dict[str, Any]] = None
    custom_sni: Optional[str] = None
    original_sni: Optional[str] = None
    note: Optional[str] = None

class CustomVMessRequest(BaseModel):
    sni: str = Field(..., description="Custom SNI for domain fronting (e.g., m.zoom.us)")
    security: Optional[str] = Field(None, description="Security method (default: aes-128-gcm)")

class CustomVMessResponse(BaseModel):
    email: str
    custom_config: Dict[str, Any]
    settings: Dict[str, Any]
    note: str

class ConfigFileInfo(BaseModel):
    filename: str
    size: int
    exists: bool
    is_vmess: bool
    client_count: Optional[int] = None

class ConfigFilesResponse(BaseModel):
    config_path: str
    total_files: int
    json_files: List[ConfigFileInfo]
    vmess_files: List[str]

class PopularSNIResponse(BaseModel):
    popular_sni_domains: Dict[str, List[str]]
    note: str
    usage: str

# Utility Functions
async def run_shell_command(command: str, timeout: int = 30) -> Dict[str, Any]:
    """Execute shell command and return result"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "Command timed out",
            "returncode": -1
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }

def check_installation() -> bool:
    """Check if v2ray-agent is installed"""
    return os.path.exists(V2RAY_AGENT_PATH) and os.path.exists(INSTALL_SCRIPT_PATH)

def get_service_status(service: str) -> ServiceStatus:
    """Get status of a systemd service"""
    try:
        result = subprocess.run(
            f"systemctl is-active {service}",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip() == "active":
            return ServiceStatus.running
        else:
            return ServiceStatus.stopped
    except:
        return ServiceStatus.unknown

def get_subscription_salt() -> str:
    """Get or create subscription salt"""
    salt_file = f"{V2RAY_AGENT_PATH}/subscribe_local/subscribeSalt"
    try:
        if os.path.exists(salt_file):
            with open(salt_file, 'r') as f:
                return f.read().strip()
        else:
            # Generate random salt
            import secrets
            import string
            salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
            os.makedirs(os.path.dirname(salt_file), exist_ok=True)
            with open(salt_file, 'w') as f:
                f.write(salt)
            return salt
    except Exception:
        return "defaultsalt123"

def get_current_domain() -> str:
    """Get current domain from nginx config"""
    try:
        nginx_conf_path = "/etc/nginx/conf.d/alone.conf"
        if os.path.exists(nginx_conf_path):
            with open(nginx_conf_path, 'r') as f:
                content = f.read()
                # Extract server_name
                import re
                match = re.search(r'server_name\s+([^;]+);', content)
                if match:
                    return match.group(1).strip()
    except Exception:
        pass
    return "localhost"

def decode_vmess_link(vmess_link: str) -> Optional[Dict[str, Any]]:
    """Decode VMess link and return JSON config"""
    try:
        if vmess_link.startswith("vmess://"):
            import base64
            encoded_part = vmess_link[8:]  # Remove "vmess://" prefix
            decoded_json = base64.b64decode(encoded_part).decode('utf-8')
            return json.loads(decoded_json)
    except Exception as e:
        logger.warning(f"Failed to decode VMess link: {e}")
    return None

def convert_vmess_to_v2ray_config(vmess_config: Dict[str, Any], custom_sni: Optional[str] = None) -> Dict[str, Any]:
    """Convert VMess subscription format to full V2Ray outbound config
    
    Args:
        vmess_config: Decoded VMess configuration
        custom_sni: Custom SNI to override the default serverName
    """
    # Use custom SNI if provided, otherwise use the original SNI from config
    server_name = custom_sni or vmess_config.get("sni", vmess_config.get("host", ""))
    
    return {
        "outbounds": [{
            "mux": {},
            "protocol": "vmess",
            "sendThrough": "0.0.0.0",
            "settings": {
                "vnext": [{
                    "address": vmess_config.get("add", ""),
                    "port": int(vmess_config.get("port", 443)),
                    "users": [{
                        "id": vmess_config.get("id", ""),
                        "security": vmess_config.get("scy", "aes-128-gcm"),
                        "alterId": int(vmess_config.get("aid", 0))
                    }]
                }]
            },
            "streamSettings": {
                "network": vmess_config.get("net", "ws"),
                "security": vmess_config.get("tls", "tls"),
                "tlsSettings": {
                    "allowInsecure": True,
                    "disableSystemRoot": False,
                    "serverName": server_name
                },
                "wsSettings": {
                    "headers": {
                        "Host": vmess_config.get("host", "")
                    },
                    "path": vmess_config.get("path", "/")
                },
                "xtlsSettings": {
                    "disableSystemRoot": False
                }
            },
            "tag": "PROXY"
        }]
    }

def read_user_subscription_file(email: str) -> List[str]:
    """Read user's subscription file from subscribe_local/default/{email}"""
    try:
        user_sub_file = f"{V2RAY_AGENT_PATH}/subscribe_local/default/{email}"
        if os.path.exists(user_sub_file):
            with open(user_sub_file, 'r') as f:
                lines = f.readlines()
            return [line.strip() for line in lines if line.strip()]
    except Exception as e:
        logger.warning(f"Failed to read subscription file for {email}: {e}")
    return []

def parse_vmess_from_subscription(email: str) -> Optional[Dict[str, Any]]:
    """Parse VMess configuration from subscription files"""
    subscription_lines = read_user_subscription_file(email)
    
    for line in subscription_lines:
        if line.startswith("vmess://"):
            vmess_decoded = decode_vmess_link(line)
            if vmess_decoded:
                return {
                    "vmess_link": line,
                    "vmess_decoded": vmess_decoded,
                    "vmess_base_config": vmess_decoded
                }
    return None

# API Routes

@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint"""
    return {
        "message": "BadProxy API - VMess Management",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

@app.get("/status", response_model=SystemInfo, tags=["System"])
async def get_system_status():
    """Get overall system status and information"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Check if VMess is installed
    vmess_config = f"{CONFIG_PATH}/03_VMess_WS_inbounds.json"
    vmess_enabled = os.path.exists(vmess_config)
    
    # Get installed protocols
    installed_protocols = []
    config_files = {
        "vless": "02_VLESS_TCP_inbounds.json",
        "vmess": "03_VMess_WS_inbounds.json", 
        "trojan": "04_trojan_TCP_inbounds.json",
        "reality": "07_VLESS_vision_reality_inbounds.json"
    }
    
    for protocol, config_file in config_files.items():
        if os.path.exists(f"{CONFIG_PATH}/{config_file}"):
            installed_protocols.append(protocol)
    
    # Get version
    version_result = await run_shell_command(f"grep 'Current version:' {INSTALL_SCRIPT_PATH} | head -1")
    version = "unknown"
    if version_result["success"] and version_result["stdout"]:
        version = version_result["stdout"].split(":")[-1].strip().replace('"', '')
    
    return SystemInfo(
        installed_protocols=installed_protocols,
        version=version,
        config_path=CONFIG_PATH,
        vmess_enabled=vmess_enabled
    )

@app.get("/services", response_model=List[ServiceStatusResponse], tags=["Services"])
async def get_services_status():
    """Get status of all v2ray-agent related services"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    services = ["xray", "v2ray", "nginx"]
    service_statuses = []
    
    for service in services:
        status = get_service_status(service)
        service_info = ServiceStatusResponse(
            service=service,
            status=status
        )
        
        # Get PID if running
        if status == ServiceStatus.running:
            pid_result = await run_shell_command(f"systemctl show {service} --property=MainPID --value")
            if pid_result["success"] and pid_result["stdout"].strip():
                try:
                    service_info.pid = int(pid_result["stdout"].strip())
                except ValueError:
                    pass
        
        service_statuses.append(service_info)
    
    return service_statuses

class SystemInfo(BaseModel):
    installed_protocols: List[str]
    version: str
    config_path: str
    vmess_enabled: bool

# VMess Management API Routes

@app.get("/config/files", response_model=ConfigFilesResponse, tags=["Configuration"])
async def list_config_files():
    """List all JSON configuration files in the config directory"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    if not os.path.exists(CONFIG_PATH):
        raise HTTPException(status_code=404, detail=f"Configuration path {CONFIG_PATH} not found")
    
    json_files = []
    vmess_files = []
    
    try:
        for filename in os.listdir(CONFIG_PATH):
            if filename.endswith('.json'):
                file_path = os.path.join(CONFIG_PATH, filename)
                file_size = os.path.getsize(file_path)
                
                # Check if this is a VMess config by reading the file
                is_vmess = False
                client_count = None
                
                try:
                    with open(file_path, 'r') as f:
                        config = json.load(f)
                    
                    # Check if it's a VMess configuration
                    if 'inbounds' in config:
                        for inbound in config['inbounds']:
                            if ('protocol' in inbound and inbound['protocol'] == 'vmess') or \
                               ('settings' in inbound and 'clients' in inbound['settings']):
                                is_vmess = True
                                if 'settings' in inbound and 'clients' in inbound['settings']:
                                    client_count = len(inbound['settings']['clients'])
                                    vmess_files.append(filename)
                                break
                                
                except Exception as e:
                    logger.warning(f"Failed to parse {filename}: {e}")
                
                json_files.append(ConfigFileInfo(
                    filename=filename,
                    size=file_size,
                    exists=True,
                    is_vmess=is_vmess,
                    client_count=client_count
                ))
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read config directory: {str(e)}")
    
    # Sort files by name
    json_files.sort(key=lambda x: x.filename)
    
    return ConfigFilesResponse(
        config_path=CONFIG_PATH,
        total_files=len(json_files),
        json_files=json_files,
        vmess_files=sorted(vmess_files)
    )

@app.get("/vmess/users", response_model=VMessUsersResponse, tags=["VMess Management"])
async def get_vmess_users(
    config_file: Optional[str] = Query(None, description="Specific config file to read (e.g., '03_VMess_WS_inbounds.json')")
):
    """Get all users with VMess configurations
    
    Args:
        config_file: Optional specific config file to read. If not provided, will auto-detect VMess files.
    """
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    vmess_users = []
    
    # If specific config file is provided, use it
    if config_file:
        config_file_path = f"{CONFIG_PATH}/{config_file}"
        if not os.path.exists(config_file_path):
            raise HTTPException(status_code=404, detail=f"Config file {config_file} not found")
        
        config_files_to_check = [config_file_path]
    else:
        # Auto-detect VMess config files
        config_files_to_check = []
        try:
            for filename in os.listdir(CONFIG_PATH):
                if filename.endswith('.json'):
                    file_path = os.path.join(CONFIG_PATH, filename)
                    try:
                        with open(file_path, 'r') as f:
                            config = json.load(f)
                        
                        # Check if it's a VMess configuration
                        if 'inbounds' in config:
                            for inbound in config['inbounds']:
                                if ('protocol' in inbound and inbound['protocol'] == 'vmess') or \
                                   ('settings' in inbound and 'clients' in inbound['settings']):
                                    config_files_to_check.append(file_path)
                                    break
                    except Exception:
                        continue
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to scan config files: {str(e)}")
    
    # Parse VMess config files for users
    for config_file_path in config_files_to_check:
        try:
            with open(config_file_path, 'r') as f:
                config = json.load(f)
            
            if 'inbounds' in config:
                for inbound in config['inbounds']:
                    if 'settings' in inbound and 'clients' in inbound['settings']:
                        for client in inbound['settings']['clients']:
                            email = client.get('email', 'unknown')
                            uuid = client.get('id', 'unknown')
                            
                            # Get VMess config from subscription files
                            vmess_config = parse_vmess_from_subscription(email)
                            
                            vmess_users.append(VMessUser(
                                email=email,
                                uuid=uuid,
                                has_subscription=vmess_config is not None,
                                vmess_available=vmess_config is not None
                            ))
                            
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Failed to parse VMess config {config_file_path}: {e}")
    
    return VMessUsersResponse(
        total_vmess_users=len(vmess_users),
        users=vmess_users
    )

@app.get("/vmess/users/{email}", response_model=VMessConfigResponse, tags=["VMess Management"])
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
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    vmess_config = parse_vmess_from_subscription(email)
    
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
        v2ray_config = convert_vmess_to_v2ray_config(vmess_config["vmess_base_config"], sni)
        
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

@app.post("/vmess/users/{email}/generate", response_model=CustomVMessResponse, tags=["VMess Management"])
async def generate_custom_vmess_config(email: str, request: CustomVMessRequest):
    """Generate custom VMess V2Ray configuration with specific SNI
    
    Args:
        email: User email
        request: Custom configuration request with SNI and security settings
    """
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    vmess_config = parse_vmess_from_subscription(email)
    
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
                        "security": request.security or base_config.get("scy", "aes-128-gcm"),
                        "alterId": int(base_config.get("aid", 0))
                    }]
                }]
            },
            "streamSettings": {
                "network": base_config.get("net", "ws"),
                "security": base_config.get("tls", "tls"),
                "tlsSettings": {
                    "allowInsecure": True,
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
            "security": request.security or base_config.get("scy", "aes-128-gcm"),
            "allow_insecure": True,
            "server_address": base_config.get("add", ""),
            "server_port": int(base_config.get("port", 443)),
            "websocket_path": base_config.get("path", "/")
        },
        note="This config uses custom SNI for domain fronting with allowInsecure=true"
    )

@app.get("/vmess/popular-sni", response_model=PopularSNIResponse, tags=["VMess Management"])
async def get_popular_sni_domains():
    """Get list of popular SNI domains for domain fronting"""
    popular_domains = {
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
    
    return PopularSNIResponse(
        popular_sni_domains=popular_domains,
        note="These domains are commonly used for domain fronting to bypass censorship",
        usage="Use any of these as the 'sni' parameter in your VMess configuration requests"
    )

@app.get("/logs/{service}", tags=["Logs"])
async def get_service_logs(service: str, lines: int = Query(100, ge=1, le=1000)):
    """Get logs for a specific service"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    valid_services = ["xray", "v2ray", "nginx", "access", "error"]
    if service not in valid_services:
        raise HTTPException(status_code=400, detail=f"Invalid service. Valid services: {valid_services}")
    
    if service in ["access", "error"]:
        log_file = f"{V2RAY_AGENT_PATH}/{service}.log"
        if not os.path.exists(log_file):
            return {"logs": "", "message": f"Log file {log_file} does not exist"}
        
        command = f"tail -n {lines} {log_file}"
    else:
        command = f"journalctl -u {service} -n {lines} --no-pager"
    
    result = await run_shell_command(command)
    
    if not result["success"]:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get logs: {result['stderr']}"
        )
    
    return {
        "service": service,
        "logs": result["stdout"],
        "lines": lines
    }

@app.post("/certificate/renew", tags=["Certificate"])
async def renew_certificate():
    """Renew TLS certificate"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Use the v2ray-agent script to renew certificate
    command = f"echo '9' | {INSTALL_SCRIPT_PATH}"
    
    result = await run_shell_command(command, timeout=120)
    
    if not result["success"]:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to renew certificate: {result['stderr']}"
        )
    
    return {"message": "Certificate renewal initiated"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)