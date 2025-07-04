from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from typing import Optional

from app.auth.utils import verify_token
from app.auth.database import user_db
from app.auth.config import auth_settings
from app.models.auth import UserResponse, TokenData

# Security schemes
security = HTTPBearer()
api_key_header = APIKeyHeader(name=auth_settings.API_KEY_HEADER, auto_error=False)

async def get_current_user_from_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> UserResponse:
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token_data = verify_token(credentials.credentials)
        if token_data is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    
    user = user_db.get_user_by_id(token_data.user_id)
    if user is None:
        raise credentials_exception
    
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )
    
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

async def get_current_user_from_api_key(api_key: Optional[str] = Security(api_key_header)) -> Optional[UserResponse]:
    """Get current user from API key"""
    if not api_key:
        return None
    
    api_key_data = user_db.validate_api_key(api_key)
    if not api_key_data:
        return None
    
    # If API key is not associated with a user, create a temporary admin user
    if not api_key_data["user_id"]:
        return UserResponse(
            id=0,
            username="api_user",
            email="api@badproxy.local",
            full_name="API User",
            is_active=True,
            is_admin=True,
            created_at="2023-01-01T00:00:00",
            last_login=None
        )
    
    user = user_db.get_user_by_id(api_key_data["user_id"])
    if not user or not user["is_active"]:
        return None
    
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

async def get_current_user(
    token_user: Optional[UserResponse] = Depends(get_current_user_from_token),
    api_user: Optional[UserResponse] = Depends(get_current_user_from_api_key)
) -> UserResponse:
    """Get current user from either JWT token or API key"""
    
    # Try API key first, then JWT token
    user = api_user or token_user
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Use Bearer token or API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

async def get_current_active_user(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )
    return current_user

async def get_current_admin_user(current_user: UserResponse = Depends(get_current_active_user)) -> UserResponse:
    """Get current admin user"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

# Optional authentication (for public endpoints that can benefit from user context)
async def get_optional_current_user(
    api_user: Optional[UserResponse] = Depends(get_current_user_from_api_key)
) -> Optional[UserResponse]:
    """Get current user optionally (no error if not authenticated)"""
    try:
        # Try to get token user without raising exceptions
        return api_user
    except:
        return None