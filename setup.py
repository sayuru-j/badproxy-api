import os
import sys
import subprocess
from pathlib import Path

def install_dependencies():
    """Install Python dependencies"""
    print("Installing Python dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def create_directories():
    """Create necessary directories"""
    directories = [
        "/var/log",
        "/etc/v2ray-agent",
        "app/services",
        "app/core",
        "app/utils"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {directory}")

def setup_environment():
    """Setup environment file"""
    if not os.path.exists(".env"):
        print("Creating .env file from template...")
        subprocess.run(["cp", ".env.example", ".env"])
        print("Please edit .env file with your specific configuration!")

def check_v2ray_agent():
    """Check if v2ray-agent script is available"""
    script_paths = [
        "/root/v2ray-agent/install.sh",
        "./v2ray-agent/install.sh",
        "../v2ray-agent/install.sh"
    ]
    
    for path in script_paths:
        if os.path.exists(path):
            print(f"Found v2ray-agent script at: {path}")
            return path
    
    print("WARNING: v2ray-agent script not found!")
    print("Please ensure you have the original v2ray-agent installed.")
    print("You can get it from: https://github.com/mack-a/v2ray-agent")
    return None

def main():
    """Main setup function"""
    print("Setting up V2Ray-Agent FastAPI Wrapper...")
    
    # Create directories
    create_directories()
    
    # Install dependencies
    install_dependencies()
    
    # Setup environment
    setup_environment()
    
    # Check for v2ray-agent
    script_path = check_v2ray_agent()
    
    print("\n" + "="*50)
    print("Setup completed!")
    print("="*50)
    
    if script_path:
        print("✅ v2ray-agent script found")
    else:
        print("❌ v2ray-agent script not found - please install it first")
    
    print("\nNext steps:")
    print("1. Edit .env file with your configuration")
    print("2. Ensure v2ray-agent script is available")
    print("3. Run: uvicorn main:app --reload")
    print("4. Access API docs at: http://localhost:8000/docs")

if __name__ == "__main__":
    main()