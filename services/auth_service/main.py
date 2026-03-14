"""
CosmicSec Authentication Service
Handles user authentication, JWT tokens, OAuth2, and session management
"""
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os
import secrets
import logging

app = FastAPI(
    title="CosmicSec Auth Service",
    description="Authentication and authorization service for GuardAxisSphere",
    version="1.0.0"
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Data models
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str
    role: str = "user"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    email: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None


class User(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    is_active: bool = True
    created_at: datetime


# In-memory user storage (replace with database in production)
fake_users_db = {}


# Password utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password using bcrypt"""
    return pwd_context.hash(password)


# JWT utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> TokenData:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        role: str = payload.get("role")

        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )

        return TokenData(email=email, user_id=user_id, role=role)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


# Dependency to get current user
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get current authenticated user"""
    token_data = verify_token(token)

    user = fake_users_db.get(token_data.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return User(**user)


# API endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "auth",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/register", response_model=dict)
async def register(user_data: UserCreate):
    """Register a new user"""
    # Check if user already exists
    if user_data.email in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create new user
    user_id = secrets.token_urlsafe(16)
    hashed_password = get_password_hash(user_data.password)

    new_user = {
        "id": user_id,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "hashed_password": hashed_password,
        "role": user_data.role,
        "is_active": True,
        "created_at": datetime.utcnow()
    }

    fake_users_db[user_data.email] = new_user

    logger.info(f"New user registered: {user_data.email}")

    return {
        "message": "User registered successfully",
        "user_id": user_id,
        "email": user_data.email
    }


@app.post("/login", response_model=Token)
async def login(user_data: UserLogin):
    """Authenticate user and return JWT tokens"""
    # Get user from database
    user = fake_users_db.get(user_data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Verify password
    if not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Check if user is active
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    # Create tokens
    access_token_data = {
        "sub": user["email"],
        "user_id": user["id"],
        "role": user["role"]
    }

    access_token = create_access_token(access_token_data)
    refresh_token = create_refresh_token(access_token_data)

    logger.info(f"User logged in: {user_data.email}")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


@app.post("/refresh", response_model=Token)
async def refresh(refresh_token: str):
    """Refresh access token using refresh token"""
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )

        access_token_data = {
            "sub": payload.get("sub"),
            "user_id": payload.get("user_id"),
            "role": payload.get("role")
        }

        new_access_token = create_access_token(access_token_data)
        new_refresh_token = create_refresh_token(access_token_data)

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@app.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user


@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout user (invalidate token)"""
    # In production, add token to blacklist in Redis
    logger.info(f"User logged out: {current_user.email}")
    return {"message": "Successfully logged out"}


@app.get("/verify")
async def verify_token_endpoint(token: str):
    """Verify if a token is valid"""
    try:
        token_data = verify_token(token)
        return {
            "valid": True,
            "email": token_data.email,
            "user_id": token_data.user_id,
            "role": token_data.role
        }
    except HTTPException:
        return {"valid": False}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
