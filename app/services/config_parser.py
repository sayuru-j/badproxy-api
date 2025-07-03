import json
import os
import aiofiles
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime

from app.models import User, RoutingRule
from app.core.config import settings

logger = logging.getLogger("v2ray-api")

class ConfigParser:
    """Parser for v2ray-agent configuration files"""
    
    def __init__(self):
        self.config_dir = settings.V2RAY_CONFIG_DIR
        self.xray_config_dir = settings.XRAY_CONFIG_PATH
    
    async def get_all_users(self) -> List[User]:
        """Parse all configuration files to extract users"""
        users = []
        
        try:
            # Check different protocol configuration files
            config_files = [
                "02_VLESS_TCP_inbounds.json",
                "03_VLESS_WS_inbounds.json", 
                "04_trojan_TCP_inbounds.json",
                "05_VMess_WS_inbounds.json",
                "07_VLESS_vision_reality_inbounds.json"
            ]
            
            for config_file in config_files:
                file_path = os.path.join(self.xray_config_dir, config_file)
                if os.path.exists(file_path):
                    file_users = await self._parse_config_file(file_path)
                    users.extend(file_users)
            
            # Parse Hysteria users
            hysteria_users = await self._parse_hysteria_users()
            users.extend(hysteria_users)
            
            # Parse Tuic users
            tuic_users = await self._parse_tuic_users()
            users.extend(tuic_users)
            
            return users
            
        except Exception as e:
            logger.error(f"Error parsing users: {e}")
            raise
    
    async def _parse_config_file(self, file_path: str) -> List[User]:
        """Parse a single configuration file"""
        users = []
        
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
                config = json.loads(content)
            
            # Extract protocol from filename
            protocol = self._get_protocol_from_filename(os.path.basename(file_path))
            
            # Parse inbound configurations
            if 'inbounds' in config:
                for inbound in config['inbounds']:
                    if 'settings' in inbound and 'clients' in inbound['settings']:
                        for client in inbound['settings']['clients']:
                            user = User(
                                id=client.get('id', ''),
                                email=client.get('email', ''),
                                protocol=protocol,
                                alter_id=client.get('alterId', 0),
                                level=client.get('level', 0)
                            )
                            users.append(user)
            
            return users
            
        except Exception as e:
            logger.error(f"Error parsing config file {file_path}: {e}")
            return []
    
    async def _parse_hysteria_users(self) -> List[User]:
        """Parse Hysteria configuration for users"""
        users = []
        
        try:
            hysteria_config = os.path.join(self.config_dir, "hysteria", "config.json")
            if not os.path.exists(hysteria_config):
                return users
            
            async with aiofiles.open(hysteria_config, 'r') as f:
                content = await f.read()
                config = json.loads(content)
            
            if 'auth' in config and 'config' in config['auth']:
                # Parse Hysteria user configuration
                # Format depends on Hysteria version
                pass
            
            return users
            
        except Exception as e:
            logger.error(f"Error parsing Hysteria users: {e}")
            return []
    
    async def _parse_tuic_users(self) -> List[User]:
        """Parse Tuic configuration for users"""
        users = []
        
        try:
            tuic_config = os.path.join(self.config_dir, "tuic", "config.json")
            if not os.path.exists(tuic_config):
                return users
            
            async with aiofiles.open(tuic_config, 'r') as f:
                content = await f.read()
                config = json.loads(content)
            
            if 'users' in config:
                for user_id, user_data in config['users'].items():
                    user = User(
                        id=user_id,
                        email=user_data.get('email', user_id),
                        protocol='tuic'
                    )
                    users.append(user)
            
            return users
            
        except Exception as e:
            logger.error(f"Error parsing Tuic users: {e}")
            return []
    
    def _get_protocol_from_filename(self, filename: str) -> str:
        """Extract protocol type from configuration filename"""
        protocol_map = {
            "02_VLESS_TCP_inbounds.json": "vless_tcp",
            "03_VLESS_WS_inbounds.json": "vless_ws", 
            "04_trojan_TCP_inbounds.json": "trojan_tcp",
            "05_VMess_WS_inbounds.json": "vmess_ws",
            "07_VLESS_vision_reality_inbounds.json": "vless_reality"
        }
        
        return protocol_map.get(filename, "unknown")
    
    async def get_full_config(self) -> Dict[str, Any]:
        """Get complete configuration from all files"""
        config = {}
        
        try:
            # Read main configuration files
            config_files = [
                "00_log.json",
                "01_api.json", 
                "02_dns.json",
                "03_routing.json",
                "10_ipv4_outbounds.json"
            ]
            
            for config_file in config_files:
                file_path = os.path.join(self.xray_config_dir, config_file)
                if os.path.exists(file_path):
                    async with aiofiles.open(file_path, 'r') as f:
                        content = await f.read()
                        config[config_file.replace('.json', '')] = json.loads(content)
            
            return config
            
        except Exception as e:
            logger.error(f"Error getting full config: {e}")
            raise
    
    async def get_routing_rules(self) -> List[RoutingRule]:
        """Parse routing rules from configuration"""
        rules = []
        
        try:
            routing_file = os.path.join(self.xray_config_dir, "03_routing.json")
            if not os.path.exists(routing_file):
                return rules
            
            async with aiofiles.open(routing_file, 'r') as f:
                content = await f.read()
                routing_config = json.loads(content)
            
            if 'routing' in routing_config and 'rules' in routing_config['routing']:
                for i, rule in enumerate(routing_config['routing']['rules']):
                    routing_rule = RoutingRule(
                        id=f"rule_{i}",
                        domains=rule.get('domain', []),
                        outbound=rule.get('outboundTag', 'direct'),
                        type=rule.get('type', 'field')
                    )
                    rules.append(routing_rule)
            
            return rules
            
        except Exception as e:
            logger.error(f"Error parsing routing rules: {e}")
            return []