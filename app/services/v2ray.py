import json
import os
import logging
from typing import List, Dict, Any, Optional

from app.config import settings
from app.utils.helpers import get_file_size
from app.models.system import ConfigFileInfo

logger = logging.getLogger(__name__)

class V2RayService:
    """Service for V2Ray configuration management"""
    
    def get_config_files(self) -> List[ConfigFileInfo]:
        """Get all JSON configuration files in the config directory"""
        json_files = []
        
        if not os.path.exists(settings.CONFIG_PATH):
            return json_files
        
        try:
            for filename in os.listdir(settings.CONFIG_PATH):
                if filename.endswith('.json'):
                    file_path = os.path.join(settings.CONFIG_PATH, filename)
                    file_size = get_file_size(file_path)
                    
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
            logger.error(f"Failed to read config directory: {e}")
            raise
        
        # Sort files by name
        json_files.sort(key=lambda x: x.filename)
        return json_files
    
    def get_vmess_files(self) -> List[str]:
        """Get list of VMess configuration files"""
        vmess_files = []
        config_files = self.get_config_files()
        
        for config_file in config_files:
            if config_file.is_vmess:
                vmess_files.append(config_file.filename)
        
        return sorted(vmess_files)
    
    def validate_config_file(self, filename: str) -> bool:
        """Validate if config file exists and is accessible"""
        file_path = os.path.join(settings.CONFIG_PATH, filename)
        return os.path.exists(file_path) and os.path.isfile(file_path)
    
    def read_config_file(self, filename: str) -> Optional[Dict[str, Any]]:
        """Read and parse a configuration file"""
        file_path = os.path.join(settings.CONFIG_PATH, filename)
        
        if not self.validate_config_file(filename):
            return None
        
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read config file {filename}: {e}")
            return None

# Create service instance
v2ray_service = V2RayService()