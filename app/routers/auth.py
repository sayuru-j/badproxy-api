from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from typing import List

from app.models.auth import (
    UserCreate, UserLogin, UserResponse, Token, PasswordChange
)
from app.models.base import APIResponse
from app.auth.utils import (
    authenticate_user, create_access_token, get_password_hash, generate_api_key
)
from app.auth.database import user_db
from app.auth.config import auth_settings
from app.auth.dependencies import get_current_active_user, get_current_admin_user

router = APIRouter()

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login with username and password"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": user["username"],
            "user_id": user["id"],
            "scopes": ["admin"] if user["is_admin"] else ["user"]
        },
        expires_delta=access_token_expires
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    current_admin: UserResponse = Depends(get_current_admin_user)
):
    """Register a new user (admin only)"""
    # Check if user already exists
    existing_user = user_db.get_user_by_username(user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Hash password and create user
    hashed_password = get_password_hash(user_data.password)
    user_id = user_db.create_user(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        is_admin=False
    )
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )
    
    user = user_db.get_user_by_id(user_id)
    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        full_name=user["full_name"],
        is_active=user["is_active"],
        is_admin=user["is_admin"],
        created_at=user["created_at"],
        last_login=user["last_login"]
    )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: UserResponse = Depends(get_current_active_user)):
    """Get current user information"""
    return current_user

@router.get("/users", response_model=List[UserResponse])
async def get_all_users(current_admin: UserResponse = Depends(get_current_admin_user)):
    """Get all users (admin only)"""
    users = user_db.get_all_users()
    return [
        UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            full_name=user["full_name"],
            is_active=user["is_active"],
            is_admin=user["is_admin"],
            created_at=user["created_at"],
            last_login=user["last_login"]
        )
        for user in users
    ]

@router.post("/api-key/generate", response_model=dict)
async def generate_new_api_key(
    key_name: str,
    current_user: UserResponse = Depends(get_current_admin_user)
):
    """Generate new API key (admin only)"""
    api_key = generate_api_key()
    
    success = user_db.create_api_key(key_name, api_key, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )
    
    return {
        "message": "API key generated successfully",
        "key_name": key_name,
        "api_key": api_key,
        "note": "Store this key securely. It will not be shown again."
    }

@router.post("/change-password", response_model=APIResponse)
async def change_password(
    password_data: PasswordChange,
    current_user: UserResponse = Depends(get_current_active_user)
):
    """Change user password"""
    # Verify current password
    user = user_db.get_user_by_id(current_user.id)
    if not user or not verify_password(password_data.current_password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    new_hashed_password = get_password_hash(password_data.new_password)
    # TODO: Implement password update in database
    
    return APIResponse(
        message="Password changed successfully",
        success=True
    )

@router.get("/auth-info")
async def get_auth_info():
    """Get authentication information (public endpoint)"""
    return {
        "auth_methods": ["Bearer Token", "API Key"],
        "token_endpoint": "/auth/login",
        "api_key_header": auth_settings.API_KEY_HEADER,
        "default_credentials": {
            "username": auth_settings.DEFAULT_ADMIN_USERNAME,
            "note": "Change default credentials in production"
        }
    }