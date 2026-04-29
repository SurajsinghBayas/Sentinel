"""
Auth API — Login, Signup, Refresh, Profile
ANBU Sentinel
"""
import uuid
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse

from app.models.schemas import UserCreate, UserLogin, UserResponse, TokenPair, RefreshRequest
from app.core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_refresh_token,
    get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ── Flat-file user store ──────────────────────────────────────────────────────
USERS_FILE = Path(__file__).parent.parent / "data" / "users.json"


def _load_users() -> Dict[str, Any]:
    if USERS_FILE.exists():
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_users(users: Dict[str, Any]) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2, default=str)


def _find_user_by_email(email: str) -> Dict[str, Any] | None:
    users = _load_users()
    for user in users.values():
        if user["email"].lower() == email.lower():
            return user
    return None


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/signup", response_model=TokenPair, status_code=status.HTTP_201_CREATED)
async def signup(body: UserCreate):
    """Register a new user and return a JWT token pair."""
    existing = _find_user_by_email(body.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists"
        )

    user_id = str(uuid.uuid4())
    initials = "".join(w[0].upper() for w in body.name.split()[:2])
    user_record = {
        "id": user_id,
        "name": body.name,
        "email": body.email,
        "password_hash": hash_password(body.password),
        "role": "analyst",
        "avatar_initials": initials,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    users = _load_users()
    users[user_id] = user_record
    _save_users(users)

    token_data = {"sub": user_id, "email": body.email, "name": body.name}
    return TokenPair(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/login", response_model=TokenPair)
async def login(body: UserLogin):
    """Authenticate user credentials and return a JWT token pair."""
    user = _find_user_by_email(body.email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    token_data = {"sub": user["id"], "email": user["email"], "name": user["name"]}
    return TokenPair(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh_tokens(body: RefreshRequest):
    """Exchange a valid refresh token for a new token pair."""
    payload = decode_refresh_token(body.refresh_token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    users = _load_users()
    user = users.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    token_data = {"sub": user["id"], "email": user["email"], "name": user["name"]}
    return TokenPair(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Return the profile of the currently authenticated user."""
    users = _load_users()
    user = users.get(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserResponse(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        role=user.get("role", "analyst"),
        avatar_initials=user.get("avatar_initials"),
        created_at=datetime.fromisoformat(user["created_at"]),
    )
