import json
import base64
import os
import logging
from typing import List, Optional, Dict, Any

from app.config import settings
from app.utils.helpers import get_file_size
from app.models.vmess import VMessUser

logger = logging.getLogger(__name__)

class VMessService:
    """Service for VMess-related operations"""
    
    def decode_vmess_link(self, vmess_link: str) -> Optional[Dict[str, Any]]:
        """Decode VMess link and return JSON config"""
        try:
            if vmess_link.startswith("vmess://"):
                encoded_part = vmess_link[8:]  # Remove "vmess://" prefix
                decoded_json = base64.b64decode(encoded_part).decode('utf-8')
                return json.loads(decoded_json)
        except Exception as e:
            logger.warning(f"Failed to decode VMess link: {e}")
        return None
    
    def convert_vmess_to_v2ray_config(self, vmess_config: Dict[str, Any], custom_sni: Optional[str] = None) -> Dict[str, Any]:
        """Convert VMess subscription format to full V2Ray outbound config"""
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
                            "security": vmess_config.get("scy", settings.DEFAULT_SECURITY),
                            "alterId": int(vmess_config.get("aid", 0))
                        }]
                    }]
                },
                "streamSettings": {
                    "network": vmess_config.get("net", "ws"),
                    "security": vmess_config.get("tls", "tls"),
                    "tlsSettings": {
                        "allowInsecure": settings.ALLOW_INSECURE,
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
    
    def read_user_subscription_file(self, email: str) -> List[str]:
        """Read user's subscription file from subscribe_local/default/{email}"""
        try:
            user_sub_file = f"{settings.SUBSCRIBE_LOCAL_PATH}/default/{email}"
            if os.path.exists(user_sub_file):
                with open(user_sub_file, 'r') as f:
                    lines = f.readlines()
                return [line.strip() for line in lines if line.strip()]
        except Exception as e:
            logger.warning(f"Failed to read subscription file for {email}: {e}")
        return []
    
    def parse_vmess_from_subscription(self, email: str) -> Optional[Dict[str, Any]]:
        """Parse VMess configuration from subscription files"""
        subscription_lines = self.read_user_subscription_file(email)
        
        for line in subscription_lines:
            if line.startswith("vmess://"):
                vmess_decoded = self.decode_vmess_link(line)
                if vmess_decoded:
                    return {
                        "vmess_link": line,
                        "vmess_decoded": vmess_decoded,
                        "vmess_base_config": vmess_decoded
                    }
        return None
    
    def get_vmess_users_from_config(self, config_file_path: str) -> List[VMessUser]:
        """Get VMess users from a specific config file"""
        users = []
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
                            vmess_config = self.parse_vmess_from_subscription(email)
                            
                            users.append(VMessUser(
                                email=email,
                                uuid=uuid,
                                has_subscription=vmess_config is not None,
                                vmess_available=vmess_config is not None
                            ))
        except Exception as e:
            logger.warning(f"Failed to parse VMess config {config_file_path}: {e}")
        
        return users
    
    def find_vmess_config_files(self) -> List[str]:
        """Find all VMess configuration files"""
        vmess_files = []
        try:
            for filename in os.listdir(settings.CONFIG_PATH):
                if filename.endswith('.json'):
                    file_path = os.path.join(settings.CONFIG_PATH, filename)
                    try:
                        with open(file_path, 'r') as f:
                            config = json.load(f)
                        
                        # Check if it's a VMess configuration
                        if 'inbounds' in config:
                            for inbound in config['inbounds']:
                                if ('protocol' in inbound and inbound['protocol'] == 'vmess') or \
                                   ('settings' in inbound and 'clients' in inbound['settings']):
                                    vmess_files.append(file_path)
                                    break
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"Failed to scan config files: {e}")
        
        return vmess_files
    
    def get_popular_sni_domains(self) -> Dict[str, List[str]]:
        """Get popular SNI domains for domain fronting"""
        return settings.POPULAR_SNI_DOMAINS

# Create service instance
vmess_service = VMessService()