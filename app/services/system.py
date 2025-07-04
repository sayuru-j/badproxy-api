import os
import re
import subprocess
import logging
from typing import List, Optional

from app.config import settings
from app.utils.constants import ServiceStatus
from app.utils.helpers import run_shell_command, check_installation, get_file_size

logger = logging.getLogger(__name__)

class SystemService:
    """Service for system-related operations"""
    
    def check_v2ray_installation(self) -> bool:
        """Check if v2ray-agent is installed"""
        return check_installation(settings.V2RAY_AGENT_PATH, settings.INSTALL_SCRIPT_PATH)
    
    def get_service_status(self, service: str) -> ServiceStatus:
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
    
    async def get_service_pid(self, service: str) -> Optional[int]:
        """Get PID of a running service"""
        pid_result = await run_shell_command(f"systemctl show {service} --property=MainPID --value")
        if pid_result["success"] and pid_result["stdout"].strip():
            try:
                return int(pid_result["stdout"].strip())
            except ValueError:
                pass
        return None
    
    def get_current_domain(self) -> str:
        """Get current domain from nginx config"""
        try:
            nginx_conf_path = "/etc/nginx/conf.d/alone.conf"
            if os.path.exists(nginx_conf_path):
                with open(nginx_conf_path, 'r') as f:
                    content = f.read()
                    # Extract server_name
                    match = re.search(r'server_name\s+([^;]+);', content)
                    if match:
                        return match.group(1).strip()
        except Exception:
            pass
        return "localhost"
    
    async def get_v2ray_version(self) -> str:
        """Get v2ray-agent version"""
        version_result = await run_shell_command(f"grep 'Current version:' {settings.INSTALL_SCRIPT_PATH} | head -1")
        if version_result["success"] and version_result["stdout"]:
            return version_result["stdout"].split(":")[-1].strip().replace('"', '')
        return "unknown"
    
    def get_installed_protocols(self) -> List[str]:
        """Get list of installed protocols"""
        protocols = []
        config_files = {
            "vless": "02_VLESS_TCP_inbounds.json",
            "vmess": "03_VMess_WS_inbounds.json", 
            "trojan": "04_trojan_TCP_inbounds.json",
            "reality": "07_VLESS_vision_reality_inbounds.json"
        }
        
        for protocol, config_file in config_files.items():
            if os.path.exists(f"{settings.CONFIG_PATH}/{config_file}"):
                protocols.append(protocol)
        
        return protocols
    
    def is_vmess_enabled(self) -> bool:
        """Check if VMess is enabled"""
        vmess_config = f"{settings.CONFIG_PATH}/03_VMess_WS_inbounds.json"
        return os.path.exists(vmess_config)
    
    async def get_service_logs(self, service: str, lines: int = 100) -> str:
        """Get logs for a service"""
        if service in ["access", "error"]:
            log_file = f"{settings.V2RAY_AGENT_PATH}/{service}.log"
            if not os.path.exists(log_file):
                return ""
            command = f"tail -n {lines} {log_file}"
        else:
            command = f"journalctl -u {service} -n {lines} --no-pager"
        
        result = await run_shell_command(command)
        return result["stdout"] if result["success"] else ""
    
    async def renew_certificate(self) -> bool:
        """Renew TLS certificate"""
        command = f"echo '9' | {settings.INSTALL_SCRIPT_PATH}"
        result = await run_shell_command(command, timeout=120)
        return result["success"]

# Create service instance
system_service = SystemService()