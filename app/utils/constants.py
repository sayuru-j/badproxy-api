from enum import Enum

class ServiceStatus(str, Enum):
    running = "running"
    stopped = "stopped"
    unknown = "unknown"

class ConfigFormat(str, Enum):
    subscription = "subscription"
    decoded = "decoded"
    v2ray = "v2ray"

class ProtocolType(str, Enum):
    vless = "vless"
    vmess = "vmess"
    trojan = "trojan"
    hysteria = "hysteria"
    reality = "reality"
    tuic = "tuic"

# Valid services for monitoring
VALID_SERVICES = ["xray", "v2ray", "nginx"]
VALID_LOG_SERVICES = ["xray", "v2ray", "nginx", "access", "error"]

# VMess configuration defaults
VMESS_DEFAULTS = {
    "network": "ws",
    "security": "tls",
    "port": 443,
    "alter_id": 0
}