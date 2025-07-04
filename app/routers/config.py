from fastapi import APIRouter, HTTPException

from app.models.system import ConfigFilesResponse
from app.services.system import system_service
from app.services.v2ray import v2ray_service
from app.config import settings

router = APIRouter()

@router.get("/files", response_model=ConfigFilesResponse)
async def list_config_files():
    """List all JSON configuration files in the config directory"""
    if not system_service.check_v2ray_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    try:
        json_files = v2ray_service.get_config_files()
        vmess_files = v2ray_service.get_vmess_files()
        
        return ConfigFilesResponse(
            config_path=settings.CONFIG_PATH,
            total_files=len(json_files),
            json_files=json_files,
            vmess_files=vmess_files
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read config directory: {str(e)}")