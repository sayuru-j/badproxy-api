from pydantic import BaseModel
from typing import List, Optional

class SystemInfo(BaseModel):
    installed_protocols: List[str]
    version: str
    config_path: str
    vmess_enabled: bool

class ConfigFileInfo(BaseModel):
    filename: str
    size: int
    exists: bool
    is_vmess: bool
    client_count: Optional[int] = None

class ConfigFilesResponse(BaseModel):
    config_path: str
    total_files: int
    json_files: List[ConfigFileInfo]
    vmess_files: List[str]

class LogsResponse(BaseModel):
    service: str
    logs: str
    lines: int