import subprocess
import os
import logging
import secrets
import string
from typing import Dict, Any

logger = logging.getLogger(__name__)

async def run_shell_command(command: str, timeout: int = 30) -> Dict[str, Any]:
    """Execute shell command and return result"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "Command timed out",
            "returncode": -1
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }

def check_installation(v2ray_agent_path: str, install_script_path: str) -> bool:
    """Check if v2ray-agent is installed"""
    return os.path.exists(v2ray_agent_path) and os.path.exists(install_script_path)

def generate_random_salt(length: int = 16) -> str:
    """Generate random salt for subscriptions"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def get_file_size(file_path: str) -> int:
    """Get file size safely"""
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0