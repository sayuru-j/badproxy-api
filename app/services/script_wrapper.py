import asyncio
import subprocess
import json
import os
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

from app.models import *
from app.core.config import settings

logger = logging.getLogger("v2ray-api")

class V2RayAgentWrapper:
    """Wrapper for the original v2ray-agent bash script"""
    
    def __init__(self):
        self.script_path = settings.V2RAY_SCRIPT_PATH
        self.config_dir = settings.V2RAY_CONFIG_DIR
    
    async def execute_script_command(self, command: str, timeout: int = 300) -> str:
        """Execute a command with the original script"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(self.script_path)
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Script command failed: {error_msg}")
                raise Exception(f"Script execution failed: {error_msg}")
            
            return stdout.decode()
        
        except asyncio.TimeoutError:
            logger.error(f"Script command timed out: {command}")
            raise Exception("Script execution timed out")
        except Exception as e:
            logger.error(f"Error executing script command: {e}")
            raise
    
    async def get_system_status(self) -> SystemStatus:
        """Get system status by checking services"""
        try:
            # Check various services
            xray_status = await self._check_service_status("xray")
            hysteria_status = await self._check_service_status("hysteria") 
            tuic_status = await self._check_service_status("tuic")
            nginx_status = await self._check_service_status("nginx")
            
            return SystemStatus(
                xray_status=xray_status,
                hysteria_status=hysteria_status,
                tuic_status=tuic_status,
                nginx_status=nginx_status
            )
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            raise
    
    async def _check_service_status(self, service_name: str) -> ServiceStatus:
        """Check if a systemd service is running"""
        try:
            result = await self.execute_script_command(
                f"systemctl is-active {service_name}", 
                timeout=10
            )
            if "active" in result.lower():
                return ServiceStatus.RUNNING
            else:
                return ServiceStatus.STOPPED
        except:
            return ServiceStatus.NOT_INSTALLED
    
    async def get_install_status(self) -> InstallStatus:
        """Get installation status of components"""
        try:
            # Check if config directories exist
            xray_installed = os.path.exists(f"{self.config_dir}/xray")
            hysteria_installed = os.path.exists(f"{self.config_dir}/hysteria")
            tuic_installed = os.path.exists(f"{self.config_dir}/tuic")
            
            installed_protocols = []
            if xray_installed:
                installed_protocols.extend(["vless", "vmess", "trojan"])
            if hysteria_installed:
                installed_protocols.append("hysteria")
            if tuic_installed:
                installed_protocols.append("tuic")
            
            # Check TLS status
            tls_installed = os.path.exists("/etc/v2ray-agent/tls")
            
            return InstallStatus(
                core_type="xray" if xray_installed else None,
                installed_protocols=installed_protocols,
                tls_installed=tls_installed,
                cloudflare_configured=False,  # Would need to check configs
                warp_configured=False
            )
        except Exception as e:
            logger.error(f"Error getting install status: {e}")
            raise
    
    async def install_protocol(self, request: InstallRequest):
        """Install protocols using the original script"""
        try:
            # The original script uses interactive menus, so we need to simulate inputs
            # This is a simplified version - you'd need to map the protocol types 
            # to the script's menu options
            
            protocol_map = {
                ProtocolType.VLESS_TCP_TLS: "1",
                ProtocolType.VMESS_WS_TLS: "7",
                # Add other mappings
            }
            
            commands = []
            for protocol in request.protocols:
                if protocol in protocol_map:
                    commands.append(protocol_map[protocol])
            
            # This would need to be adapted based on how the original script works
            # For now, this is a placeholder
            command = f"echo '{chr(10).join(commands)}' | bash {self.script_path}"
            
            result = await self.execute_script_command(command, timeout=600)
            logger.info(f"Protocol installation completed: {result}")
            
        except Exception as e:
            logger.error(f"Error installing protocols: {e}")
            raise
    
    async def add_user(self, user_request: UserCreateRequest) -> User:
        """Add user using the original script's user management"""
        try:
            # The script's user management is typically interactive
            # We'd need to simulate the inputs for adding a user
            
            # Generate UUID if not provided
            uuid = user_request.custom_uuid or await self._generate_uuid()
            
            # This is a placeholder - would need to be adapted to actual script interface
            command = f"""
            echo -e "7\\n4\\n{user_request.email}\\n{uuid}\\n" | bash {self.script_path}
            """
            
            result = await self.execute_script_command(command)
            
            return User(
                id=uuid,
                email=user_request.email,
                protocol=user_request.protocol,
                created_at=datetime.now(),
                alter_id=user_request.alter_id,
                level=user_request.level
            )
            
        except Exception as e:
            logger.error(f"Error adding user: {e}")
            raise
    
    async def delete_user(self, user_id: str) -> str:
        """Delete user using original script"""
        try:
            # Simulate user deletion through script menu
            command = f"""
            echo -e "7\\n5\\n{user_id}\\n" | bash {self.script_path}
            """
            
            result = await self.execute_script_command(command)
            return result
            
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            raise
    
    async def show_accounts(self) -> List[AccountInfo]:
        """Get account information using script's show accounts function"""
        try:
            # Use script's account display function
            command = f"""
            echo -e "7\\n1\\n" | bash {self.script_path}
            """
            
            result = await self.execute_script_command(command)
            
            # Parse the output to extract account information
            # This would need to be adapted based on actual script output format
            accounts = self._parse_account_output(result)
            
            return accounts
            
        except Exception as e:
            logger.error(f"Error getting accounts: {e}")
            raise
    
    async def install_certificate(self, cert_request: CertificateRequest) -> str:
        """Install SSL certificate using script"""
        try:
            # Navigate to certificate installation menu
            command = f"""
            echo -e "9\\n{cert_request.domain}\\n{cert_request.email}\\n" | bash {self.script_path}
            """
            
            result = await self.execute_script_command(command, timeout=300)
            return result
            
        except Exception as e:
            logger.error(f"Error installing certificate: {e}")
            raise
    
    async def renew_certificate(self) -> str:
        """Renew SSL certificate"""
        try:
            command = f"""
            echo -e "9\\n" | bash {self.script_path}
            """
            
            result = await self.execute_script_command(command)
            return result
            
        except Exception as e:
            logger.error(f"Error renewing certificate: {e}")
            raise
    
    async def restart_service(self, service_name: str) -> str:
        """Restart specific service"""
        try:
            result = await self.execute_script_command(f"systemctl restart {service_name}")
            return f"Service {service_name} restarted successfully"
        except Exception as e:
            logger.error(f"Error restarting service {service_name}: {e}")
            raise
    
    async def get_logs(self, log_type: str, lines: int = 100) -> str:
        """Get service logs"""
        try:
            if log_type == "xray":
                command = f"journalctl -u xray -n {lines} --no-pager"
            elif log_type == "hysteria":
                command = f"journalctl -u hysteria -n {lines} --no-pager"
            else:
                command = f"tail -n {lines} /var/log/{log_type}.log"
            
            result = await self.execute_script_command(command)
            return result
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            raise
    
    async def get_warp_status(self) -> Dict[str, Any]:
        """Get WARP configuration status"""
        try:
            # Check if WARP is configured
            warp_config_exists = os.path.exists(f"{self.config_dir}/warp")
            
            return {
                "enabled": warp_config_exists,
                "config_path": f"{self.config_dir}/warp" if warp_config_exists else None
            }
        except Exception as e:
            logger.error(f"Error getting WARP status: {e}")
            raise
    
    async def configure_warp(self, warp_config: WarpConfigRequest) -> str:
        """Configure WARP using script"""
        try:
            # Navigate to WARP configuration menu
            command = f"""
            echo -e "11\\n1\\n" | bash {self.script_path}
            """
            
            result = await self.execute_script_command(command)
            return result
        except Exception as e:
            logger.error(f"Error configuring WARP: {e}")
            raise
    
    async def get_subscriptions(self) -> List[SubscriptionInfo]:
        """Get subscription information"""
        try:
            # Check subscription directory
            sub_dir = f"{self.config_dir}/subscribe"
            if not os.path.exists(sub_dir):
                return []
            
            subscriptions = []
            # Parse subscription files
            # This would need implementation based on actual subscription format
            
            return subscriptions
        except Exception as e:
            logger.error(f"Error getting subscriptions: {e}")
            raise
    
    async def create_subscription(self, sub_request: SubscriptionCreateRequest) -> SubscriptionInfo:
        """Create new subscription"""
        try:
            # Use script's subscription management
            command = f"""
            echo -e "7\\n3\\n{sub_request.name}\\n" | bash {self.script_path}
            """
            
            result = await self.execute_script_command(command)
            
            # Return subscription info
            return SubscriptionInfo(
                id=f"sub_{datetime.now().timestamp()}",
                name=sub_request.name,
                url="",  # Would be generated by script
                users=sub_request.users,
                created_at=datetime.now()
            )
        except Exception as e:
            logger.error(f"Error creating subscription: {e}")
            raise
    
    async def add_routing_rule(self, rule: RoutingRuleRequest) -> str:
        """Add routing rule using script"""
        try:
            # Navigate to routing management
            command = f"""
            echo -e "11\\n2\\n{','.join(rule.domains)}\\n" | bash {self.script_path}
            """
            
            result = await self.execute_script_command(command)
            return result
        except Exception as e:
            logger.error(f"Error adding routing rule: {e}")
            raise
    
    async def _generate_uuid(self) -> str:
        """Generate UUID using system command"""
        try:
            result = await self.execute_script_command("uuidgen", timeout=5)
            return result.strip()
        except:
            # Fallback to Python UUID
            import uuid
            return str(uuid.uuid4())
    
    def _parse_account_output(self, output: str) -> List[AccountInfo]:
        """Parse account information from script output"""
        # This would need to be implemented based on actual script output format
        # Placeholder implementation
        accounts = []
        
        # Parse the output and extract account details
        # This is highly dependent on the actual script output format
        
        return accounts