from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List

from app.models.system import SystemInfo, LogsResponse
from app.models.base import ServiceStatusResponse, APIResponse
from app.models.auth import UserResponse
from app.services.system import system_service
from app.utils.constants import VALID_SERVICES, VALID_LOG_SERVICES
from app.config import settings
from app.auth.dependencies import get_current_active_user

router = APIRouter()

@router.get("/status", response_model=SystemInfo)
async def get_system_status(current_user: UserResponse = Depends(get_current_active_user)):
    """Get overall system status and information"""
    if not system_service.check_v2ray_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    return SystemInfo(
        installed_protocols=system_service.get_installed_protocols(),
        version=await system_service.get_v2ray_version(),
        config_path=settings.CONFIG_PATH,
        vmess_enabled=system_service.is_vmess_enabled()
    )

@router.get("/services", response_model=List[ServiceStatusResponse])
async def get_services_status(current_user: UserResponse = Depends(get_current_active_user)):
    """Get status of all v2ray-agent related services"""
    if not system_service.check_v2ray_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    service_statuses = []
    
    for service in VALID_SERVICES:
        status = system_service.get_service_status(service)
        service_info = ServiceStatusResponse(
            service=service,
            status=status
        )
        
        # Get PID if running
        if status.value == "running":
            service_info.pid = await system_service.get_service_pid(service)
        
        service_statuses.append(service_info)
    
    return service_statuses

@router.get("/logs/{service}", response_model=LogsResponse)
async def get_service_logs(
    service: str, 
    lines: int = Query(100, ge=1, le=1000, description="Number of log lines to retrieve"),
    current_user: UserResponse = Depends(get_current_active_user)
):
    """Get logs for a specific service"""
    if not system_service.check_v2ray_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    if service not in VALID_LOG_SERVICES:
        raise HTTPException(status_code=400, detail=f"Invalid service. Valid services: {VALID_LOG_SERVICES}")
    
    logs = await system_service.get_service_logs(service, lines)
    
    return LogsResponse(
        service=service,
        logs=logs,
        lines=lines
    )

@router.post("/certificate/renew", response_model=APIResponse)
async def renew_certificate(current_user: UserResponse = Depends(get_current_active_user)):
    """Renew TLS certificate"""
    if not system_service.check_v2ray_installation():
        raise HTTPException(status_code=404, detail="V2Ray Agent not installed")
    
    success = await system_service.renew_certificate()
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to renew certificate")
    
    return APIResponse(
        message="Certificate renewal initiated",
        success=True
    )