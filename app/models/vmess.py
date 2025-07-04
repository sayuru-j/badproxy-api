from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class VMessUser(BaseModel):
    email: str
    uuid: str
    has_subscription: bool
    vmess_available: bool

class VMessUsersResponse(BaseModel):
    total_vmess_users: int
    users: List[VMessUser]

class VMessConfigResponse(BaseModel):
    email: str
    format: str
    vmess_link: Optional[str] = None
    vmess_config: Optional[Dict[str, Any]] = None
    v2ray_config: Optional[Dict[str, Any]] = None
    custom_sni: Optional[str] = None
    original_sni: Optional[str] = None
    note: Optional[str] = None

class CustomVMessRequest(BaseModel):
    sni: str = Field(..., description="Custom SNI for domain fronting (e.g., m.zoom.us)")
    security: Optional[str] = Field(None, description="Security method (default: aes-128-gcm)")

class CustomVMessResponse(BaseModel):
    email: str
    custom_config: Dict[str, Any]
    settings: Dict[str, Any]
    note: str

class PopularSNIResponse(BaseModel):
    popular_sni_domains: Dict[str, List[str]]
    note: str
    usage: str