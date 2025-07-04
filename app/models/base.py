from pydantic import BaseModel
from typing import Optional
from app.utils.constants import ServiceStatus

class ServiceStatusResponse(BaseModel):
    service: str
    status: ServiceStatus
    pid: Optional[int] = None
    uptime: Optional[str] = None

class APIResponse(BaseModel):
    message: str
    success: bool = True
    data: Optional[dict] = None

class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None