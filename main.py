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

# API Routes

@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint"""
    return {
        "message": "V2Ray Agent Management API",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }

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