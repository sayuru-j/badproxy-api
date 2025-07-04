#!/bin/bash

# V2Ray Agent API Startup Script
# This script sets up and runs the FastAPI server for v2ray-agent management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_DIR="/root/v2ray-agent-api"
PYTHON_ENV="$API_DIR/.venv"
API_PORT=8000
API_HOST="0.0.0.0"

# Functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Check if v2ray-agent is installed
check_v2ray_agent() {
    if [[ ! -d "/etc/v2ray-agent" ]]; then
        print_error "V2Ray Agent is not installed. Please install it first."
        print_status "You can install it using:"
        echo "wget -P /root -N --no-check-certificate https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh && chmod 700 /root/install.sh && /root/install.sh"
        exit 1
    fi
    print_success "V2Ray Agent installation detected"
}

# Install system dependencies
install_dependencies() {
    print_status "Installing system dependencies..."

    # Detect OS
    if [[ -f /etc/redhat-release ]]; then
        # CentOS/RHEL
        yum update -y
        yum install -y python3 python3-pip python3-venv curl wget
    elif [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu
        apt update
        apt install -y python3 python3-pip python3-venv curl wget
    else
        print_error "Unsupported operating system"
        exit 1
    fi

    print_success "System dependencies installed"
}

# Setup Python environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."

    # Create API directory
    mkdir -p "$API_DIR"
    cd "$API_DIR"

    # Create virtual environment
    python3 -m venv "$PYTHON_ENV"
    source "$PYTHON_ENV/bin/activate"

    # Upgrade pip
    pip install --upgrade pip

    print_success "Python environment created"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."

    source "$PYTHON_ENV/bin/activate"

    # Install FastAPI and dependencies
    pip install fastapi==0.104.1
    pip install uvicorn[standard]==0.24.0
    pip install pydantic==2.5.0
    pip install python-multipart==0.0.6
    pip install aiofiles==23.2.1

    print_success "Python dependencies installed"
}

# Create API files
create_api_files() {
    print_status "Creating API files..."

    # The main.py file should be saved separately and copied here
    if [[ ! -f "$API_DIR/main.py" ]]; then
        print_error "main.py file not found in $API_DIR"
        print_status "Please copy the FastAPI code to $API_DIR/main.py"
        exit 1
    fi

    print_success "API files ready"
}

# Create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."

    cat >/etc/systemd/system/v2ray-agent-api.service <<EOF
[Unit]
Description=V2Ray Agent Management API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$API_DIR
Environment=PATH=$PYTHON_ENV/bin
ExecStart=$PYTHON_ENV/bin/uvicorn main:app --host $API_HOST --port $API_PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable v2ray-agent-api

    print_success "Systemd service created and enabled"
}

# Configure firewall
configure_firewall() {
    print_status "Configuring firewall..."

    # Check if firewall is active and configure accordingly
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=$API_PORT/tcp
        firewall-cmd --reload
        print_success "Firewalld configured"
    elif systemctl is-active --quiet ufw; then
        ufw allow $API_PORT/tcp
        print_success "UFW configured"
    else
        print_warning "No active firewall detected. Make sure port $API_PORT is accessible."
    fi
}

# Start the API service
start_service() {
    print_status "Starting V2Ray Agent API service..."

    systemctl start v2ray-agent-api

    if systemctl is-active --quiet v2ray-agent-api; then
        print_success "V2Ray Agent API service started successfully"
        print_status "API is running at: http://$(hostname -I | awk '{print $1}'):$API_PORT"
        print_status "API documentation: http://$(hostname -I | awk '{print $1}'):$API_PORT/docs"
    else
        print_error "Failed to start V2Ray Agent API service"
        print_status "Check logs with: journalctl -u v2ray-agent-api -f"
        exit 1
    fi
}

# Show status
show_status() {
    print_status "Service Status:"
    systemctl status v2ray-agent-api --no-pager

    echo ""
    print_status "Quick Commands:"
    echo "  Start:   systemctl start v2ray-agent-api"
    echo "  Stop:    systemctl stop v2ray-agent-api"
    echo "  Restart: systemctl restart v2ray-agent-api"
    echo "  Logs:    journalctl -u v2ray-agent-api -f"
    echo "  Status:  systemctl status v2ray-agent-api"
}

# Main installation function
install() {
    print_status "Starting V2Ray Agent API installation..."

    check_root
    check_v2ray_agent
    install_dependencies
    setup_python_env
    install_python_deps
    create_api_files
    create_systemd_service
    configure_firewall
    start_service
    show_status

    print_success "Installation completed successfully!"
    print_status "Your V2Ray Agent API is now running and ready to use."
}

# Handle command line arguments
case "${1:-install}" in
"install")
    install
    ;;
"start")
    systemctl start v2ray-agent-api
    print_success "Service started"
    ;;
"stop")
    systemctl stop v2ray-agent-api
    print_success "Service stopped"
    ;;
"restart")
    systemctl restart v2ray-agent-api
    print_success "Service restarted"
    ;;
"status")
    show_status
    ;;
"logs")
    journalctl -u v2ray-agent-api -f
    ;;
"uninstall")
    print_status "Uninstalling V2Ray Agent API..."
    systemctl stop v2ray-agent-api 2>/dev/null || true
    systemctl disable v2ray-agent-api 2>/dev/null || true
    rm -f /etc/systemd/system/v2ray-agent-api.service
    rm -rf "$API_DIR"
    systemctl daemon-reload
    print_success "Uninstalled successfully"
    ;;
*)
    echo "Usage: $0 {install|start|stop|restart|status|logs|uninstall}"
    echo ""
    echo "Commands:"
    echo "  install   - Install and setup the API service"
    echo "  start     - Start the API service"
    echo "  stop      - Stop the API service"
    echo "  restart   - Restart the API service"
    echo "  status    - Show service status"
    echo "  logs      - Show service logs"
    echo "  uninstall - Remove the API service"
    exit 1
    ;;
esac
