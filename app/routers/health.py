from fastapi import APIRouter
from datetime import datetime

router = APIRouter()

@router.get("/")
async def health_check():
    """Health check endpoint"""
    return {
        "message": "BadProxy API - VMess Management",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }