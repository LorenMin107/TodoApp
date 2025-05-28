"""
Two-factor authentication module for the TodoApp application.

This module provides functionality for setting up, verifying, and disabling
two-factor authentication.
"""

import secrets
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional

from fastapi import Depends, HTTPException, Request, Response, Cookie
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from starlette.responses import RedirectResponse

from ...models import Users
from ...totp import setup_totp, verify_totp
from ...cache import cache_invalidate_pattern
from ...activity_logger import log_activity

from . import router
from .token_manager import (
    get_db, create_access_token, create_refresh_token,
    set_auth_cookies, get_current_user_from_cookie, pending_2fa_sessions
)

# Templates for rendering pages
templates = Jinja2Templates(directory="TodoApp/templates")


# Request models
class TOTPVerifyRequest(BaseModel):
    token: str

class TOTPSetupResponse(BaseModel):
    secret: str
    qr_code: str

def check_pending_2fa_session(request: Request) -> Tuple[bool, Optional[str]]:
    # Get the 2FA session cookie
    session_id = request.cookies.get("2fa_session")

    if not session_id:
        return False, None

    # Check if the session exists and is valid
    if session_id not in pending_2fa_sessions:
        return False, None

    session = pending_2fa_sessions[session_id]

    # Check if the session has expired
    if session["expires"] < datetime.now(timezone.utc):
        # Remove the expired session
        pending_2fa_sessions.pop(session_id, None)
        return False, None

    return True, session_id

# Routes
@router.get("/setup-2fa-page")
async def setup_2fa_page(request: Request, user: dict = Depends(get_current_user_from_cookie),
                         db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse(url="/auth/login-page", status_code=status.HTTP_303_SEE_OTHER)

    # Get the user from the database
    db_user = db.query(Users).filter(Users.id == user.get('id')).first()

    # Check if 2FA is already enabled
    if db_user.is_2fa_enabled:
        return RedirectResponse(url="/user/profile?error=2fa_already_enabled", status_code=status.HTTP_303_SEE_OTHER)

    # Generate TOTP secret and QR code
    secret, uri, qr_code = setup_totp(db_user.username)

    # Store the secret temporarily in the session
    session_id = secrets.token_urlsafe(32)
    pending_2fa_sessions[session_id] = {
        "user_id": db_user.id,
        "secret": secret,
        "expires": datetime.now(timezone.utc) + timedelta(minutes=10)
    }

    # Set a cookie with the session ID
    response = templates.TemplateResponse(
        "setup-2fa.html",
        {"request": request, "qr_code": qr_code, "secret": secret}
    )
    response.set_cookie(
        key="setup_2fa_session",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=600,  # 10 minutes
        path="/"
    )

    return response

@router.get("/verify-2fa-page")
async def verify_2fa_page(request: Request, session_id: str = Cookie(None, alias="2fa_session")):
    # Check if the session exists and is valid
    if session_id not in pending_2fa_sessions:
        return RedirectResponse(url="/auth/login-page", status_code=status.HTTP_303_SEE_OTHER)

    session = pending_2fa_sessions[session_id]

    # Check if the session has expired
    if session["expires"] < datetime.now(timezone.utc):
        # Remove the expired session
        pending_2fa_sessions.pop(session_id, None)
        return RedirectResponse(url="/auth/login-page?error=session_expired", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse("verify-2fa.html", {"request": request})

@router.post("/verify-2fa-setup", response_model=dict)
async def verify_2fa_setup(
        request: TOTPVerifyRequest,
        db: Session = Depends(get_db),
        session_id: str = Cookie(None, alias="setup_2fa_session")
):
    # Check if the session exists and is valid
    if session_id not in pending_2fa_sessions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Your two-factor authentication setup session has expired or is invalid. Please try setting up 2FA again."
        )

    session = pending_2fa_sessions[session_id]

    # Check if the session has expired
    if session["expires"] < datetime.now(timezone.utc):
        # Remove the expired session
        pending_2fa_sessions.pop(session_id, None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Your two-factor authentication setup session has expired. Please try setting up 2FA again."
        )

    # Verify the TOTP code
    if not verify_totp(session["secret"], request.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The verification code you entered is incorrect. Please make sure you're entering the current code from your authenticator app and try again."
        )

    # Get the user from the database
    user = db.query(Users).filter(Users.id == session["user_id"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found. Please contact support if you believe this is an error."
        )

    # Enable 2FA for the user
    user.totp_secret = session["secret"]
    user.is_2fa_enabled = True
    db.add(user)
    db.commit()

    # Invalidate cache for this user
    cache_invalidate_pattern(f"auth:get_user_by_username:{user.username}")

    # Log the 2FA setup activity
    log_activity(
        db=db,
        user_id=user.id,
        username=user.username,
        action="enable_2fa",
        details="User enabled two-factor authentication"
    )

    # Remove the session
    pending_2fa_sessions.pop(session_id, None)

    # Return success
    return {"message": "Two-factor authentication has been enabled successfully"}

@router.post("/verify-2fa")
async def verify_2fa(
        totp_request: TOTPVerifyRequest,
        request: Request,
        response: Response,
        db: Session = Depends(get_db),
        session_id: str = Cookie(None, alias="2fa_session")
):
    # Check if the session exists and is valid
    if session_id not in pending_2fa_sessions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired session"
        )

    session = pending_2fa_sessions[session_id]

    # Check if the session has expired
    if session["expires"] < datetime.now(timezone.utc):
        # Remove the expired session
        pending_2fa_sessions.pop(session_id, None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session expired"
        )

    # Get the user from the database
    user = db.query(Users).filter(Users.id == session["user_id"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Verify the TOTP code
    if not verify_totp(user.totp_secret, totp_request.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )

    # Remove the session
    pending_2fa_sessions.pop(session_id, None)

    # Get a user agent from request
    user_agent = request.headers.get("user-agent", "")

    # Create an access token (short-lived, 10 minutes)
    access_token, access_jti, access_exp = create_access_token(
        user.username, 
        user.id, 
        user.role, 
        timedelta(minutes=10),  # Reduced from 20 minutes to 10 minutes
        user_agent
    )

    # Create a refresh token (long-lived, 7 days)
    refresh_token, refresh_jti, refresh_exp = create_refresh_token(
        user.username, 
        user.id, 
        user.role, 
        timedelta(days=7),
        user_agent
    )

    # Set authentication cookies
    set_auth_cookies(response, access_token, refresh_token)

    # Log the 2FA verification activity
    log_activity(
        db=db,
        user_id=user.id,
        username=user.username,
        action="verify_2fa",
        details="User completed two-factor authentication"
    )

    # Return success
    return {"message": "Authentication successful"}

@router.post("/disable-2fa")
async def disable_2fa(
        db: Session = Depends(get_db),
        user: dict = Depends(get_current_user_from_cookie)
):
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    # Get the user from the database
    db_user = db.query(Users).filter(Users.id == user.get('id')).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if 2FA is enabled
    if not db_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is not enabled"
        )

    # Disable 2FA for the user
    db_user.is_2fa_enabled = False
    db_user.totp_secret = None
    db.add(db_user)
    db.commit()

    # Invalidate cache for this user
    cache_invalidate_pattern(f"auth:get_user_by_username:{db_user.username}")

    # Log the 2FA disabling activity
    log_activity(
        db=db,
        user_id=user.get('id'),
        username=user.get('username'),
        action="disable_2fa",
        details="User disabled two-factor authentication"
    )

    # Return success
    return {"message": "Two-factor authentication has been disabled successfully"}


# Register routes with the router
router.add_api_route("/setup-2fa-page", setup_2fa_page, methods=["GET"])
router.add_api_route("/verify-2fa-page", verify_2fa_page, methods=["GET"])
router.add_api_route("/verify-2fa-setup", verify_2fa_setup, methods=["POST"], response_model=dict)
router.add_api_route("/verify-2fa", verify_2fa, methods=["POST"])
router.add_api_route("/disable-2fa", disable_2fa, methods=["POST"])
