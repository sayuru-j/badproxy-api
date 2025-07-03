from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any, Union
from enum import Enum
from datetime import datetime

class ProtocolType(str, Enum):
    VLESS_TCP_TLS = "vless_tcp_tls"
    VLESS_TCP_XTLS = "vless_tcp_xtls"
    VLESS_GRPC_TLS = "vless_grpc_tls"
    VLESS_WS_TLS = "vless_ws_tls"
    TROJAN_TCP_TLS = "trojan_tcp_tls"
    TROJAN_GRPC_TLS = "trojan_grpc_tls"
    VMESS_WS_TLS = "vmess_ws_tls"
    HYSTERIA = "hysteria"
    REALITY = "reality"
    TUIC = "tuic"

class ServiceStatus(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    NOT_INSTALLED = "not_installed"

class User(BaseModel):
    id: str
    email: str
    protocol: str
    created_at: Optional[datetime] = None
    alter_id: Optional[int] = 0
    level: Optional[int] = 0

class UserCreateRequest(BaseModel):
    email: EmailStr
    protocol: Optional[str] = "vmess"
    alter_id: Optional[int] = 0
    level: Optional[int] = 0
    custom_uuid: Optional[str] = None

class SystemStatus(BaseModel):
    xray_status: ServiceStatus
    hysteria_status: ServiceStatus
    tuic_status: ServiceStatus
    nginx_status: ServiceStatus
    system_uptime: Optional[str] = None
    memory_usage: Optional[Dict[str, Any]] = None
    cpu_usage: Optional[float] = None

class InstallStatus(BaseModel):
    core_type: Optional[str] = None
    installed_protocols: List[str] = []
    tls_installed: bool = False
    cloudflare_configured: bool = False
    warp_configured: bool = False

class InstallRequest(BaseModel):
    protocols: List[ProtocolType]
    domain: str
    port: Optional[int] = None
    custom_install: bool = False
    cloudflare_email: Optional[str] = None
    cloudflare_key: Optional[str] = None

class InstallResponse(BaseModel):
    message: str
    task_id: str
    status: str

class ProtocolInfo(BaseModel):
    name: str
    description: str
    port_required: bool
    default_port: Optional[int] = None

class AccountInfo(BaseModel):
    protocol: str
    user: str
    uuid: str
    config_url: Optional[str] = None
    qr_code: Optional[str] = None
    client_config: Optional[Dict[str, Any]] = None

class CertificateRequest(BaseModel):
    domain: str
    dns_provider: Optional[str] = "cloudflare"
    dns_api_token: Optional[str] = None
    email: Optional[str] = None

class RoutingRule(BaseModel):
    id: str
    domains: List[str]
    outbound: str
    type: str

class RoutingRuleRequest(BaseModel):
    domains: List[str]
    outbound: str
    type: str = "domain"

class WarpConfigRequest(BaseModel):
    enabled: bool
    domains: Optional[List[str]] = None
    global_routing: bool = False

class SubscriptionInfo(BaseModel):
    id: str
    name: str
    url: str
    users: List[str]
    created_at: datetime

class SubscriptionCreateRequest(BaseModel):
    name: str
    users: List[str]
    format: str = "v2ray"  # v2ray, clash, etc.