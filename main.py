from fastapi import FastAPI, HTTPException, BackgroundTasks
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
    title="V2Ray Agent Management API",
    description="FastAPI for managing v2ray-agent installation and configurations",
    version="1.0.0"
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

class ProtocolType(str, Enum):
    vless = "vless"
    vmess = "vmess"
    trojan = "trojan"
    hysteria = "hysteria"
    reality = "reality"
    tuic = "tuic"

# Pydantic Models
class ServiceStatusResponse(BaseModel):
    service: str
    status: ServiceStatus
    pid: Optional[int] = None
    uptime: Optional[str] = None

class User(BaseModel):
    email: str
    uuid: str
    protocol: ProtocolType
    created_at: Optional[datetime] = None
    config_links: Optional[Dict[str, str]] = None

class AddUserRequest(BaseModel):
    email: str
    uuid: Optional[str] = None
    protocol: ProtocolType = ProtocolType.vless

class ServiceControlRequest(BaseModel):
    action: str = Field(..., pattern="^(start|stop|restart)$")

class CertificateInfo(BaseModel):
    domain: str
    expiry_date: Optional[str] = None
    issuer: Optional[str] = None
    status: str

class SystemInfo(BaseModel):
    installed_protocols: List[str]
    version: str
    config_path: str
    log_status: bool
    certificate_info: Optional[CertificateInfo] = None

class SubscriptionInfo(BaseModel):
    email: str
    default_subscription: Optional[str] = None
    clash_meta_subscription: Optional[str] = None
    qr_code_url: Optional[str] = None
    subscription_url: Optional[str] = None

class AddSubscriptionRequest(BaseModel):
    domain: str
    port: int
    alias: str

class AccountSummary(BaseModel):
    total_users: int
    protocols: Dict[str, int]
    subscription_enabled: bool
    users: List[User]

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
                    "allowInsecure": bool(vmess_config.get("allowInsecure", 0)),
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

def parse_config_links_from_subscription(email: str) -> Dict[str, Any]:
    """Parse configuration links from actual subscription files"""
    links = {}
    
    # Read from subscribe_local/default/{email}
    subscription_lines = read_user_subscription_file(email)
    
    for line in subscription_lines:
        if line.startswith("vless://"):
            if "flow=xtls-rprx-vision" in line:
                links["vless_tcp_vision"] = line
            elif "type=ws" in line:
                links["vless_ws"] = line
            elif "type=grpc" in line:
                links["vless_grpc"] = line
            elif "security=reality" in line:
                if "type=grpc" in line:
                    links["vless_reality_grpc"] = line
                else:
                    links["vless_reality_vision"] = line
                    
        elif line.startswith("vmess://"):
            links["vmess_ws"] = line
            # Decode VMess and add full config
            vmess_decoded = decode_vmess_link(line)
            if vmess_decoded:
                links["vmess_decoded"] = vmess_decoded
                links["vmess_v2ray_config"] = convert_vmess_to_v2ray_config(vmess_decoded)
                # Store the base config for custom SNI generation
                links["vmess_base_config"] = vmess_decoded
                
        elif line.startswith("trojan://"):
            if "type=grpc" in line:
                links["trojan_grpc"] = line
            else:
                links["trojan_tcp"] = line
    
    # Add QR code for the first available link
    if links:
        first_link = None
        for key in ["vless_tcp_vision", "vless_ws", "vmess_ws", "trojan_tcp"]:
            if key in links:
                first_link = links[key]
                break
        
        if first_link:
            import urllib.parse
            encoded_link = urllib.parse.quote(first_link, safe='')
            links["qr_code"] = f"https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={encoded_link}"
    
    return links

def generate_user_config_links(email: str, uuid: str, protocol: str) -> Dict[str, str]:
    """Generate configuration links for a user"""
    domain = get_current_domain()
    salt = get_subscription_salt()
    
    # Generate MD5 hash for subscription
    import hashlib
    email_hash = hashlib.md5(f"{email}{salt}".encode()).hexdigest()
    
    links = {}
    
    if protocol == "vless":
        # VLESS TCP TLS
        vless_link = f"vless://{uuid}@{domain}:443?encryption=none&security=tls&type=tcp&host={domain}&fp=chrome&headerType=none&sni={domain}&flow=xtls-rprx-vision#{email}"
        links["vless_tcp"] = vless_link
        
        # VLESS WS TLS  
        vless_ws_link = f"vless://{uuid}@{domain}:443?encryption=none&security=tls&type=ws&host={domain}&sni={domain}&fp=chrome&path=/ws#{email}"
        links["vless_ws"] = vless_ws_link
        
    elif protocol == "vmess":
        # VMess WS TLS - need to create proper VMess format
        import base64
        vmess_config = {
            "v": "2",
            "ps": email,
            "add": domain,
            "port": "443",
            "id": uuid,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": domain,
            "path": "/ws",
            "tls": "tls",
            "sni": domain,
            "alpn": "",
            "fp": "chrome"
        }
        vmess_json = json.dumps(vmess_config)
        vmess_base64 = base64.b64encode(vmess_json.encode()).decode().strip()
        vmess_link = f"vmess://{vmess_base64}"
        links["vmess_ws"] = vmess_link
        
        # Also add a simpler VMess format for compatibility
        vmess_simple = f"vmess://{uuid}@{domain}:443?encryption=none&security=tls&type=ws&host={domain}&path=/ws&sni={domain}&fp=chrome#{email}"
        links["vmess_ws_simple"] = vmess_simple
        
    elif protocol == "trojan":
        # Trojan TCP TLS
        trojan_link = f"trojan://{uuid}@{domain}:443?encryption=none&security=tls&type=tcp&host={domain}&headerType=none&sni={domain}#{email}"
        links["trojan_tcp"] = trojan_link
    
    # QR Code URL
    if links:
        first_link = list(links.values())[0]
        qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={first_link.replace(':', '%3A').replace('/', '%2F').replace('?', '%3F').replace('&', '%26').replace('=', '%3D').replace('#', '%23')}"
        links["qr_code"] = qr_url
    
    return links

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

# API Routes

@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint"""
    return {
        "message": "V2Ray Agent Management API",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }
async def check_accounts():
    """1. Check account - Get comprehensive account information"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    users = []
    protocol_counts = {"vless": 0, "vmess": 0, "trojan": 0, "hysteria": 0, "reality": 0, "tuic": 0}
    
    # Parse Xray config files for users
    config_files = [
        ("02_VLESS_TCP_inbounds.json", "vless"),
        ("03_VMess_WS_inbounds.json", "vmess"),
        ("04_trojan_TCP_inbounds.json", "trojan"),
        ("07_VLESS_vision_reality_inbounds.json", "reality")
    ]
    
    for config_file, protocol in config_files:
        config_path_full = f"{CONFIG_PATH}/{config_file}"
        if os.path.exists(config_path_full):
            try:
                with open(config_path_full, 'r') as f:
                    config = json.load(f)
                
                if 'inbounds' in config:
                    for inbound in config['inbounds']:
                        if 'settings' in inbound and 'clients' in inbound['settings']:
                            for client in inbound['settings']['clients']:
                                email = client.get('email', 'unknown')
                                uuid = client.get('id', client.get('password', 'unknown'))
                                
                                # Get config links from actual subscription files
                                config_links = parse_config_links_from_subscription(email)
                                
                                users.append(User(
                                    email=email,
                                    uuid=uuid,
                                    protocol=protocol,
                                    config_links=config_links
                                ))
                                protocol_counts[protocol] += 1
                                
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Failed to parse {config_file}: {e}")
    
    # Check Hysteria users
    hysteria_config = "/etc/v2ray-agent/hysteria/conf.json"
    if os.path.exists(hysteria_config):
        try:
            with open(hysteria_config, 'r') as f:
                config = json.load(f)
            if 'auth' in config and 'config' in config['auth']:
                for auth_key in config['auth']['config']:
                    users.append(User(
                        email=f"hysteria_user_{auth_key[:8]}",
                        uuid=auth_key,
                        protocol="hysteria"
                    ))
                    protocol_counts["hysteria"] += 1
        except Exception as e:
            logger.warning(f"Failed to parse Hysteria config: {e}")
    
    # Check if subscription is enabled
    subscription_enabled = os.path.exists(f"{V2RAY_AGENT_PATH}/subscribe_local/subscribeSalt")
    
    return AccountSummary(
        total_users=len(users),
        protocols=protocol_counts,
        subscription_enabled=subscription_enabled,
        users=users
    )

@app.get("/subscriptions", response_model=List[SubscriptionInfo], tags=["Account Management"])  
async def view_subscriptions():
    """2. View subscription - Get subscription links for all users"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    subscriptions = []
    salt = get_subscription_salt()
    domain = get_current_domain()
    
    # Get all users first
    accounts = await check_accounts()
    
    for user in accounts.users:
        import hashlib
        email_hash = hashlib.md5(f"{user.email}{salt}".encode()).hexdigest()
        
        subscription_info = SubscriptionInfo(
            email=user.email,
            subscription_url=f"https://{domain}/s/default/{email_hash}",
            qr_code_url=f"https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https%3A%2F%2F{domain}%2Fs%2Fdefault%2F{email_hash}"
        )
        
        # Check if subscription files exist
        default_sub_file = f"{V2RAY_AGENT_PATH}/subscribe/default/{email_hash}"
        clash_sub_file = f"{V2RAY_AGENT_PATH}/subscribe/clashMeta/{email_hash}"
        
        if os.path.exists(default_sub_file):
            subscription_info.default_subscription = f"https://{domain}/s/default/{email_hash}"
            
        if os.path.exists(clash_sub_file):
            subscription_info.clash_meta_subscription = f"https://{domain}/s/clashMeta/{email_hash}"
        
        subscriptions.append(subscription_info)
    
    return subscriptions

@app.post("/subscriptions/generate", tags=["Account Management"])
async def generate_subscriptions():
    """Generate/Regenerate subscription files for all users"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Use the v2ray-agent script to generate subscriptions
    command = f"echo '2' | {INSTALL_SCRIPT_PATH}"
    
    result = await run_shell_command(command, timeout=60)
    
    if not result["success"]:
        # If script method fails, try to generate manually
        try:
            salt = get_subscription_salt()
            os.makedirs(f"{V2RAY_AGENT_PATH}/subscribe/default", exist_ok=True)
            os.makedirs(f"{V2RAY_AGENT_PATH}/subscribe/clashMeta", exist_ok=True)
            
            accounts = await check_accounts()
            for user in accounts.users:
                import hashlib
                email_hash = hashlib.md5(f"{user.email}{salt}".encode()).hexdigest()
                
                # Generate subscription content
                if user.config_links:
                    # Create default subscription (base64 encoded URLs)
                    links = [link for key, link in user.config_links.items() if key != "qr_code"]
                    if links:
                        import base64
                        content = "\n".join(links)
                        encoded_content = base64.b64encode(content.encode()).decode()
                        
                        with open(f"{V2RAY_AGENT_PATH}/subscribe/default/{email_hash}", 'w') as f:
                            f.write(encoded_content)
            
            return {"message": "Subscriptions generated successfully (manual method)"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to generate subscriptions: {str(e)}")
    
    return {"message": "Subscriptions generated successfully"}

@app.post("/subscriptions/remote", tags=["Account Management"])
async def add_remote_subscription(request: AddSubscriptionRequest):
    """3. Add subscription - Add remote machine subscription"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Format: domain:port:alias
    remote_url = f"{request.domain}:{request.port}:{request.alias}"
    
    # Add to remote subscription file
    remote_sub_file = f"{V2RAY_AGENT_PATH}/subscribe_remote/remoteSubscribeUrl"
    os.makedirs(os.path.dirname(remote_sub_file), exist_ok=True)
    
    try:
        with open(remote_sub_file, 'a') as f:
            f.write(f"{remote_url}\n")
        
        return {
            "message": f"Remote subscription added successfully: {request.alias}",
            "remote_url": remote_url
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add remote subscription: {str(e)}")

@app.get("/subscriptions/remote", tags=["Account Management"])
async def get_remote_subscriptions():
    """Get list of remote subscriptions"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    remote_sub_file = f"{V2RAY_AGENT_PATH}/subscribe_remote/remoteSubscribeUrl"
    
    if not os.path.exists(remote_sub_file):
        return {"remote_subscriptions": []}
    
    try:
        with open(remote_sub_file, 'r') as f:
            lines = f.readlines()
        
        remote_subs = []
        for line in lines:
            line = line.strip()
            if line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 3:
                    remote_subs.append({
                        "domain": parts[0],
                        "port": parts[1],
                        "alias": parts[2],
                        "full_url": line
                    })
        
        return {"remote_subscriptions": remote_subs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read remote subscriptions: {str(e)}")

@app.delete("/subscriptions/remote/{alias}", tags=["Account Management"])
async def remove_remote_subscription(alias: str):
    """Remove remote subscription by alias"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    remote_sub_file = f"{V2RAY_AGENT_PATH}/subscribe_remote/remoteSubscribeUrl"
    
    if not os.path.exists(remote_sub_file):
        raise HTTPException(status_code=404, detail="No remote subscriptions found")
    
    try:
        with open(remote_sub_file, 'r') as f:
            lines = f.readlines()
        
        new_lines = []
        removed = False
        for line in lines:
            if not line.strip().endswith(f":{alias}"):
                new_lines.append(line)
            else:
                removed = True
        
        if not removed:
            raise HTTPException(status_code=404, detail=f"Remote subscription with alias '{alias}' not found")
        
        with open(remote_sub_file, 'w') as f:
            f.writelines(new_lines)
        
        return {"message": f"Remote subscription '{alias}' removed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove remote subscription: {str(e)}")

@app.post("/accounts/users", tags=["Account Management"])
async def add_user_account(user_request: AddUserRequest):
    """4. Add user - Add a new user account"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Generate UUID if not provided
    if not user_request.uuid:
        import uuid
        user_request.uuid = str(uuid.uuid4())
    
    # Use the v2ray-agent script to add user
    # Format: 7 (account management) -> 4 (add user) -> email -> uuid
    command = f"echo '7\n4\n{user_request.email}\n{user_request.uuid}\n' | timeout 60 {INSTALL_SCRIPT_PATH}"
    
    result = await run_shell_command(command, timeout=90)
    
    if not result["success"]:
        # Try alternative method by directly modifying config files
        try:
            # Find the appropriate config file based on protocol
            protocol_files = {
                "vless": "02_VLESS_TCP_inbounds.json",
                "vmess": "03_VMess_WS_inbounds.json", 
                "trojan": "04_trojan_TCP_inbounds.json"
            }
            
            if user_request.protocol.value in protocol_files:
                config_file = f"{CONFIG_PATH}/{protocol_files[user_request.protocol.value]}"
                
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                    
                    # Add new user to clients array
                    new_client = {
                        "id" if user_request.protocol.value != "trojan" else "password": user_request.uuid,
                        "email": user_request.email
                    }
                    
                    if user_request.protocol.value == "vless":
                        new_client["flow"] = "xtls-rprx-vision"
                    elif user_request.protocol.value == "vmess":
                        new_client["alterId"] = 0
                    
                    config['inbounds'][0]['settings']['clients'].append(new_client)
                    
                    # Write back to file
                    with open(config_file, 'w') as f:
                        json.dump(config, f, indent=2)
                    
                    # Reload core
                    reload_result = await run_shell_command("systemctl reload xray")
                    
                    # Generate config links
                    config_links = generate_user_config_links(user_request.email, user_request.uuid, user_request.protocol.value)
                    
                    return {
                        "message": "User added successfully",
                        "email": user_request.email,
                        "uuid": user_request.uuid,
                        "protocol": user_request.protocol,
                        "config_links": config_links,
                        "reload_status": "success" if reload_result["success"] else "failed"
                    }
                else:
                    raise HTTPException(status_code=400, detail=f"Protocol {user_request.protocol.value} is not installed")
            else:
                raise HTTPException(status_code=400, detail=f"Protocol {user_request.protocol.value} is not supported for direct addition")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to add user: {str(e)}")
    
    # Generate config links for successful addition
    config_links = generate_user_config_links(user_request.email, user_request.uuid, user_request.protocol.value)
    
    return {
        "message": "User added successfully",
        "email": user_request.email,
        "uuid": user_request.uuid,
        "protocol": user_request.protocol,
        "config_links": config_links
    }

@app.delete("/accounts/users/{email}", tags=["Account Management"])
async def delete_user_account(email: str):
    """5. Delete user - Remove user account"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Use the v2ray-agent script to delete user
    # Format: 7 (account management) -> 5 (delete user) -> email
    command = f"echo '7\n5\n{email}\n' | timeout 60 {INSTALL_SCRIPT_PATH}"
    
    result = await run_shell_command(command, timeout=90)
    
    if not result["success"]:
        # Try alternative method by directly modifying config files
        try:
            deleted = False
            config_files = [
                "02_VLESS_TCP_inbounds.json",
                "03_VMess_WS_inbounds.json",
                "04_trojan_TCP_inbounds.json",
                "07_VLESS_vision_reality_inbounds.json"
            ]
            
            for config_file in config_files:
                config_path_full = f"{CONFIG_PATH}/{config_file}"
                if os.path.exists(config_path_full):
                    with open(config_path_full, 'r') as f:
                        config = json.load(f)
                    
                    if 'inbounds' in config:
                        for inbound in config['inbounds']:
                            if 'settings' in inbound and 'clients' in inbound['settings']:
                                clients = inbound['settings']['clients']
                                original_length = len(clients)
                                
                                # Remove clients with matching email
                                inbound['settings']['clients'] = [
                                    client for client in clients 
                                    if client.get('email') != email
                                ]
                                
                                if len(inbound['settings']['clients']) < original_length:
                                    deleted = True
                                    
                                    # Write back to file
                                    with open(config_path_full, 'w') as f:
                                        json.dump(config, f, indent=2)
            
            if deleted:
                # Reload core
                reload_result = await run_shell_command("systemctl reload xray")
                
                # Clean up subscription files
                salt = get_subscription_salt()
                import hashlib
                email_hash = hashlib.md5(f"{email}{salt}".encode()).hexdigest()
                
                sub_files = [
                    f"{V2RAY_AGENT_PATH}/subscribe/default/{email_hash}",
                    f"{V2RAY_AGENT_PATH}/subscribe/clashMeta/{email_hash}",
                    f"{V2RAY_AGENT_PATH}/subscribe_local/default/{email}",
                    f"{V2RAY_AGENT_PATH}/subscribe_local/clashMeta/{email}"
                ]
                
                for sub_file in sub_files:
                    if os.path.exists(sub_file):
                        os.remove(sub_file)
                
                return {
                    "message": f"User {email} deleted successfully",
                    "reload_status": "success" if reload_result["success"] else "failed"
                }
            else:
                raise HTTPException(status_code=404, detail=f"User {email} not found")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete user: {str(e)}")
    
    return {"message": f"User {email} deleted successfully"}

@app.get("/accounts/users/{email}/configs", tags=["Account Management"])
async def get_user_configs(email: str):
    """Get detailed configuration for a specific user"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Parse config links from subscription files
    config_links = parse_config_links_from_subscription(email)
    
    if not config_links:
        raise HTTPException(status_code=404, detail=f"No configurations found for user {email}")
    
    return {
        "email": email,
        "configurations": config_links,
        "total_configs": len([k for k in config_links.keys() if not k.endswith('_decoded') and k != 'qr_code'])
    }

@app.get("/accounts/users/{email}/vmess", tags=["Account Management"])
async def get_user_vmess_config(email: str, format: str = "subscription", sni: Optional[str] = None):
    """Get VMess configuration for a user in different formats
    
    Args:
        email: User email
        format: 'subscription' (base64 link), 'decoded' (JSON), 'v2ray' (full V2Ray config)
        sni: Custom SNI for domain fronting (only affects 'v2ray' format)
    """
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    config_links = parse_config_links_from_subscription(email)
    
    if "vmess_ws" not in config_links:
        raise HTTPException(status_code=404, detail=f"No VMess configuration found for user {email}")
    
    if format == "subscription":
        return {
            "email": email,
            "format": "subscription",
            "vmess_link": config_links["vmess_ws"],
            "note": "Use format=v2ray with sni parameter for custom SNI"
        }
    elif format == "decoded":
        if "vmess_decoded" not in config_links:
            raise HTTPException(status_code=404, detail="Failed to decode VMess configuration")
        return {
            "email": email,
            "format": "decoded",
            "vmess_config": config_links["vmess_decoded"],
            "note": "Use format=v2ray with sni parameter for custom SNI"
        }
    elif format == "v2ray":
        if "vmess_base_config" not in config_links:
            raise HTTPException(status_code=404, detail="Failed to generate V2Ray configuration")
        
        # Generate config with custom SNI if provided
        v2ray_config = convert_vmess_to_v2ray_config(config_links["vmess_base_config"], sni)
        
        response = {
            "email": email,
            "format": "v2ray",
            "v2ray_config": v2ray_config
        }
        
        # Add SNI information to response
        if sni:
            response["custom_sni"] = sni
            response["note"] = f"Using custom SNI: {sni} for domain fronting"
        else:
            original_sni = config_links["vmess_base_config"].get("sni", config_links["vmess_base_config"].get("host", ""))
            response["original_sni"] = original_sni
            response["note"] = f"Using original SNI: {original_sni}. Add ?sni=your-domain.com for custom SNI"
        
        return response
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'subscription', 'decoded', or 'v2ray'")

@app.post("/accounts/users/{email}/vmess/generate", tags=["Account Management"])
async def generate_custom_vmess_config(email: str, sni: str, security: Optional[str] = None, allow_insecure: bool = False):
    """Generate custom VMess V2Ray configuration with specific SNI and settings
    
    Args:
        email: User email
        sni: Custom SNI for domain fronting (e.g., m.zoom.us)
        security: Custom security method (default: aes-128-gcm)
        allow_insecure: Allow insecure connections
    """
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    config_links = parse_config_links_from_subscription(email)
    
    if "vmess_base_config" not in config_links:
        raise HTTPException(status_code=404, detail=f"No VMess configuration found for user {email}")
    
    base_config = config_links["vmess_base_config"]
    
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
                        "security": security or base_config.get("scy", "aes-128-gcm"),
                        "alterId": int(base_config.get("aid", 0))
                    }]
                }]
            },
            "streamSettings": {
                "network": base_config.get("net", "ws"),
                "security": base_config.get("tls", "tls"),
                "tlsSettings": {
                    "allowInsecure": allow_insecure,
                    "disableSystemRoot": False,
                    "serverName": sni  # Custom SNI here
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
    
    return {
        "email": email,
        "custom_config": custom_config,
        "settings": {
            "custom_sni": sni,
            "original_host": base_config.get("host", ""),
            "security": security or base_config.get("scy", "aes-128-gcm"),
            "allow_insecure": allow_insecure,
            "server_address": base_config.get("add", ""),
            "server_port": int(base_config.get("port", 443)),
            "websocket_path": base_config.get("path", "/")
        },
        "note": "This config uses custom SNI for domain fronting while keeping the original Host header"
    }

@app.get("/subscriptions/files", tags=["Account Management"])
async def list_subscription_files():
    """List all subscription files and their contents"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    subscription_info = {
        "subscribe_local": {},
        "subscribe": {},
        "subscription_types": []
    }
    
    # List subscribe_local files
    local_default_path = f"{V2RAY_AGENT_PATH}/subscribe_local/default"
    if os.path.exists(local_default_path):
        local_files = os.listdir(local_default_path)
        for file in local_files:
            file_path = os.path.join(local_default_path, file)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read().strip()
                    subscription_info["subscribe_local"][file] = {
                        "lines": len(content.split('\n')) if content else 0,
                        "size": len(content),
                        "preview": content[:200] + "..." if len(content) > 200 else content
                    }
                except Exception as e:
                    subscription_info["subscribe_local"][file] = {"error": str(e)}
    
    # List subscribe files (the hashed ones)
    subscribe_path = f"{V2RAY_AGENT_PATH}/subscribe"
    if os.path.exists(subscribe_path):
        for sub_type in os.listdir(subscribe_path):
            sub_type_path = os.path.join(subscribe_path, sub_type)
            if os.path.isdir(sub_type_path):
                subscription_info["subscription_types"].append(sub_type)
                subscription_info["subscribe"][sub_type] = {}
                
                for file in os.listdir(sub_type_path):
                    file_path = os.path.join(sub_type_path, file)
                    if os.path.isfile(file_path):
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read().strip()
                            
                            # Try to decode if it looks like base64
                            decoded_content = None
                            if sub_type == "default":
                                try:
                                    import base64
                                    decoded_content = base64.b64decode(content).decode('utf-8')
                                except:
                                    decoded_content = content
                            
                            subscription_info["subscribe"][sub_type][file] = {
                                "size": len(content),
                                "is_base64": sub_type == "default" and decoded_content != content,
                                "content": decoded_content if decoded_content else content[:200] + "..." if len(content) > 200 else content
                            }
                        except Exception as e:
                            subscription_info["subscribe"][sub_type][file] = {"error": str(e)}
    
    return subscription_info

@app.get("/status", response_model=SystemInfo, tags=["System"])
async def get_system_status():
    """Get overall system status and information"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Get installed protocols
    installed_protocols = []
    config_files = {
        "vless": "02_VLESS_TCP_inbounds.json",
        "vmess": "03_VMess_WS_inbounds.json", 
        "trojan": "04_trojan_TCP_inbounds.json",
        "hysteria": "/etc/v2ray-agent/hysteria/conf.json",
        "reality": "07_VLESS_vision_reality_inbounds.json"
    }
    
    for protocol, config_file in config_files.items():
        if protocol == "hysteria":
            if os.path.exists(config_file):
                installed_protocols.append(protocol)
        else:
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
        log_status=os.path.exists(f"{V2RAY_AGENT_PATH}/access.log"),
        certificate_info=None  # TODO: Implement certificate parsing
    )

@app.get("/services", response_model=List[ServiceStatusResponse], tags=["Services"])
async def get_services_status():
    """Get status of all v2ray-agent related services"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    services = ["xray", "v2ray", "hysteria", "tuic"]
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

@app.post("/services/{service}/control", tags=["Services"])
async def control_service(service: str, request: ServiceControlRequest):
    """Control a specific service (start/stop/restart)"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    valid_services = ["xray", "v2ray", "hysteria", "tuic"]
    if service not in valid_services:
        raise HTTPException(status_code=400, detail=f"Invalid service. Valid services: {valid_services}")
    
    command = f"systemctl {request.action} {service}"
    result = await run_shell_command(command)
    
    if not result["success"]:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to {request.action} {service}: {result['stderr']}"
        )
    
    return {
        "message": f"Successfully {request.action}ed {service}",
        "service": service,
        "action": request.action
    }

@app.get("/users", response_model=List[User], tags=["User Management"])
async def get_users():
    """Get list of all configured users"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    users = []
    
    # Parse Xray config files for users
    config_files = [
        "02_VLESS_TCP_inbounds.json",
        "03_VMess_WS_inbounds.json",
        "04_trojan_TCP_inbounds.json",
        "07_VLESS_vision_reality_inbounds.json"
    ]
    
    for config_file in config_files:
        config_path = f"{CONFIG_PATH}/{config_file}"
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                if 'inbounds' in config:
                    for inbound in config['inbounds']:
                        if 'settings' in inbound and 'clients' in inbound['settings']:
                            for client in inbound['settings']['clients']:
                                protocol = "vless" if "VLESS" in config_file else "vmess" if "VMess" in config_file else "trojan"
                                users.append(User(
                                    email=client.get('email', 'unknown'),
                                    uuid=client.get('id', client.get('password', 'unknown')),
                                    protocol=protocol
                                ))
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse {config_file}")
            except Exception as e:
                logger.error(f"Error reading {config_file}: {e}")
    
    return users

@app.post("/users", tags=["User Management"])
async def add_user(user_request: AddUserRequest, background_tasks: BackgroundTasks):
    """Add a new user"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Use the v2ray-agent script to add user
    # This is a simplified approach - in reality, you'd need to interact with the script properly
    command = f"echo '4\n{user_request.email}\n{user_request.uuid or ''}\n' | {INSTALL_SCRIPT_PATH}"
    
    result = await run_shell_command(command, timeout=60)
    
    if not result["success"]:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to add user: {result['stderr']}"
        )
    
    return {
        "message": "User added successfully",
        "email": user_request.email,
        "protocol": user_request.protocol
    }

@app.delete("/users/{email}", tags=["User Management"])
async def delete_user(email: str):
    """Delete a user by email"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    # Use the v2ray-agent script to delete user
    command = f"echo '5\n{email}\n' | {INSTALL_SCRIPT_PATH}"
    
    result = await run_shell_command(command, timeout=60)
    
    if not result["success"]:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete user: {result['stderr']}"
        )
    
    return {"message": f"User {email} deleted successfully"}

@app.get("/logs/{service}", tags=["Logs"])
async def get_service_logs(service: str, lines: int = 100):
    """Get logs for a specific service"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    valid_services = ["xray", "v2ray", "hysteria", "tuic", "access", "error"]
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

@app.get("/config/backup", tags=["Configuration"])
async def backup_config():
    """Create a backup of current configuration"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    backup_dir = f"{V2RAY_AGENT_PATH}/backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    command = f"cp -r {CONFIG_PATH} {backup_dir}"
    
    result = await run_shell_command(command)
    
    if not result["success"]:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create backup: {result['stderr']}"
        )
    
    return {
        "message": "Configuration backup created",
        "backup_path": backup_dir
    }

@app.post("/update", tags=["System"])
async def update_v2ray_agent():
    """Update v2ray-agent to latest version"""
    if not check_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    command = f"echo '17' | {INSTALL_SCRIPT_PATH}"
    
    result = await run_shell_command(command, timeout=180)
    
    if not result["success"]:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update v2ray-agent: {result['stderr']}"
        )
    
    return {"message": "V2Ray Agent update initiated"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)