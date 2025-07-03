from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
import uvicorn
import os
from typing import List, Optional, Dict, Any
import asyncio
import json
import subprocess
from datetime import datetime
import logging
from contextlib import asynccontextmanager

from app.models import *
from app.services.script_wrapper import V2RayAgentWrapper
from app.services.config_parser import ConfigParser
from app.core.config import settings
from app.core.logger import setup_logger

# Setup logging
logger = setup_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting V2Ray-Agent FastAPI Wrapper")
    # Check if original script exists
    if not os.path.exists(settings.V2RAY_SCRIPT_PATH):
        logger.error(f"V2Ray-Agent script not found at {settings.V2RAY_SCRIPT_PATH}")
    yield
    # Shutdown
    logger.info("Shutting down V2Ray-Agent FastAPI Wrapper")

app = FastAPI(
    title="V2Ray-Agent Management API",
    description="FastAPI wrapper for v2ray-agent terminal script",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
script_wrapper = V2RayAgentWrapper()
config_parser = ConfigParser()
security = HTTPBearer()

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "script_available": os.path.exists(settings.V2RAY_SCRIPT_PATH)
    }

# System Information
@app.get("/api/system/status", response_model=SystemStatus)
async def get_system_status():
    """Get system and v2ray-agent status"""
    try:
        status = await script_wrapper.get_system_status()
        return status
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/system/install-status", response_model=InstallStatus)
async def get_install_status():
    """Get installation status of various components"""
    try:
        status = await script_wrapper.get_install_status()
        return status
    except Exception as e:
        logger.error(f"Error getting install status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Protocol Management
@app.post("/api/protocols/install", response_model=InstallResponse)
async def install_protocol(request: InstallRequest, background_tasks: BackgroundTasks):
    """Install protocols using original script"""
    try:
        # Add installation task to background
        background_tasks.add_task(script_wrapper.install_protocol, request)
        
        return InstallResponse(
            message="Installation started",
            task_id=f"install_{request.protocols}_{datetime.now().timestamp()}",
            status="started"
        )
    except Exception as e:
        logger.error(f"Error starting installation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/protocols/supported", response_model=List[ProtocolInfo])
async def get_supported_protocols():
    """Get list of supported protocols"""
    return [
        ProtocolInfo(name="vless_tcp_tls", description="VLESS+TCP+TLS", port_required=True),
        ProtocolInfo(name="vless_tcp_xtls", description="VLESS+TCP+XTLS", port_required=True),
        ProtocolInfo(name="vless_grpc_tls", description="VLESS+gRPC+TLS", port_required=True),
        ProtocolInfo(name="vless_ws_tls", description="VLESS+WS+TLS", port_required=True),
        ProtocolInfo(name="trojan_tcp_tls", description="Trojan+TCP+TLS", port_required=True),
        ProtocolInfo(name="trojan_grpc_tls", description="Trojan+gRPC+TLS", port_required=True),
        ProtocolInfo(name="vmess_ws_tls", description="VMess+WS+TLS", port_required=True),
        ProtocolInfo(name="hysteria", description="Hysteria", port_required=True),
        ProtocolInfo(name="reality", description="VLESS+Reality", port_required=True),
        ProtocolInfo(name="tuic", description="Tuic", port_required=True),
    ]

# User Management
@app.get("/api/users", response_model=List[User])
async def get_users():
    """Get all users from configuration"""
    try:
        users = await config_parser.get_all_users()
        return users
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/users", response_model=User)
async def add_user(user_request: UserCreateRequest):
    """Add new user using original script"""
    try:
        user = await script_wrapper.add_user(user_request)
        return user
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str):
    """Delete user using original script"""
    try:
        result = await script_wrapper.delete_user(user_id)
        return {"message": f"User {user_id} deleted successfully", "result": result}
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Configuration Management
@app.get("/api/config", response_model=Dict[str, Any])
async def get_configuration():
    """Get current configuration"""
    try:
        config = await config_parser.get_full_config()
        return config
    except Exception as e:
        logger.error(f"Error getting configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/config/accounts", response_model=List[AccountInfo])
async def get_accounts():
    """Get account information with connection details"""
    try:
        accounts = await script_wrapper.show_accounts()
        return accounts
    except Exception as e:
        logger.error(f"Error getting accounts: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Certificate Management
@app.post("/api/certificates/install")
async def install_certificate(cert_request: CertificateRequest):
    """Install SSL certificate"""
    try:
        result = await script_wrapper.install_certificate(cert_request)
        return {"message": "Certificate installation completed", "result": result}
    except Exception as e:
        logger.error(f"Error installing certificate: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/certificates/renew")
async def renew_certificate():
    """Renew SSL certificate"""
    try:
        result = await script_wrapper.renew_certificate()
        return {"message": "Certificate renewal completed", "result": result}
    except Exception as e:
        logger.error(f"Error renewing certificate: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Service Management
@app.post("/api/services/{service_name}/restart")
async def restart_service(service_name: str):
    """Restart specific service"""
    try:
        result = await script_wrapper.restart_service(service_name)
        return {"message": f"Service {service_name} restarted", "result": result}
    except Exception as e:
        logger.error(f"Error restarting service {service_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Logs
@app.get("/api/logs/{log_type}")
async def get_logs(log_type: str, lines: int = 100):
    """Get service logs"""
    try:
        logs = await script_wrapper.get_logs(log_type, lines)
        return {"logs": logs, "log_type": log_type, "lines": lines}
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Routing Management
@app.get("/api/routing/rules", response_model=List[RoutingRule])
async def get_routing_rules():
    """Get current routing rules"""
    try:
        rules = await config_parser.get_routing_rules()
        return rules
    except Exception as e:
        logger.error(f"Error getting routing rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/routing/rules")
async def add_routing_rule(rule: RoutingRuleRequest):
    """Add new routing rule"""
    try:
        result = await script_wrapper.add_routing_rule(rule)
        return {"message": "Routing rule added", "result": result}
    except Exception as e:
        logger.error(f"Error adding routing rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# WARP Management
@app.get("/api/warp/status")
async def get_warp_status():
    """Get WARP configuration status"""
    try:
        status = await script_wrapper.get_warp_status()
        return status
    except Exception as e:
        logger.error(f"Error getting WARP status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/warp/configure")
async def configure_warp(warp_config: WarpConfigRequest):
    """Configure WARP routing"""
    try:
        result = await script_wrapper.configure_warp(warp_config)
        return {"message": "WARP configured successfully", "result": result}
    except Exception as e:
        logger.error(f"Error configuring WARP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Subscriptions
@app.get("/api/subscriptions", response_model=List[SubscriptionInfo])
async def get_subscriptions():
    """Get subscription information"""
    try:
        subscriptions = await script_wrapper.get_subscriptions()
        return subscriptions
    except Exception as e:
        logger.error(f"Error getting subscriptions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/subscriptions")
async def create_subscription(sub_request: SubscriptionCreateRequest):
    """Create new subscription"""
    try:
        subscription = await script_wrapper.create_subscription(sub_request)
        return subscription
    except Exception as e:
        logger.error(f"Error creating subscription: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )