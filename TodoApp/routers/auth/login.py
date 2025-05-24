"""
Login module for the TodoApp application.

This module provides functionality for user authentication and login.
"""

import requests

from fastapi import Depends, HTTPException, Request, Response, Form, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Annotated

from starlette import status

from ...models import Users
from ...rate_limiter import check_rate_limit, record_failed_attempt, reset_attempts
from ...email_utils import generate_verification_token, send_verification_email
from ...cache import cached, cache_invalidate_pattern

from . import router
from .token_manager import (
    get_db, verify_password, create_access_token, create_refresh_token,
    set_auth_cookies, db_dependency, pending_2fa_sessions
)

# Templates for rendering pages
templates = Jinja2Templates(directory="TodoApp/templates")

# Standard reCAPTCHA v2 configuration test keys
RECAPTCHA_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
# The secret key for your reCAPTCHA v2 test site key
RECAPTCHA_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"


async def verify_recaptcha(recaptcha_response: str, action: str = None) -> bool:
    """
    Verify a reCAPTCHA response.

    Args:
        recaptcha_response: The reCAPTCHA response from the client
        action: The action to verify (not used in reCAPTCHA v2)

    Returns:
        True if the reCAPTCHA response is valid, False otherwise
    """
    if not recaptcha_response:
        return False

    # Log action if provided (for debugging, not used in verification)
    if action:
        print(f"Action specified: {action} (note: not used in reCAPTCHA v2 verification)")

    # Special case for test keys
    if RECAPTCHA_SITE_KEY == "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI" and RECAPTCHA_SECRET_KEY == "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe":
        print("Using reCAPTCHA test keys - verification automatically passes")
        return True

    try:
        # Google reCAPTCHA v2 verification API endpoint
        verify_url = "https://www.google.com/recaptcha/api/siteverify"

        # Prepare the payload for the verification request
        payload = {
            "secret": RECAPTCHA_SECRET_KEY,
            "response": recaptcha_response
        }

        # Send the verification request to Google
        response = requests.post(verify_url, data=payload)
        result = response.json()

        # Check if the verification was successful
        success = result.get("success", False)

        # Log the result for debugging
        if success:
            print("reCAPTCHA verification successful")
        else:
            error_codes = result.get("error-codes", [])
            print(f"reCAPTCHA verification failed: {error_codes}")

        return success

    except Exception as e:
        # Log the error in a production environment
        error_message = f"reCAPTCHA verification error: {str(e)}"
        print(error_message)

        # Log additional information for debugging
        print(f"reCAPTCHA response length: {len(recaptcha_response) if recaptcha_response else 0}")
        print(f"Using site key: {RECAPTCHA_SITE_KEY}")

        # In a production environment, you might want to log this to a file or monitoring service

        return False

@cached(key_prefix="auth", ttl=30)  # Cache for 30 seconds
def get_user_by_username(username: str, db):
    """
    Get a user by username.

    This function is cached to improve performance for repeated lookups.

    Args:
        username: The username of the user
        db: The database session

    Returns:
        The user object if found, None otherwise
    """
    return db.query(Users).filter(Users.username == username).first()


def authenticate_user(username: str, password: str, db):
    """
    Authenticate a user with the given username and password.

    Args:
        username: The username of the user
        password: The password of the user
        db: The database session

    Returns:
        The user object if authentication is successful, False otherwise
    """
    # Use the cached function to get the user
    user = get_user_by_username(username, db)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Routes
@router.get("/login-page")
def render_login_page(request: Request):
    """
    Render the login page.

    Args:
        request: The request object

    Returns:
        The rendered login page
    """
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/token")
async def login_for_access_token(
        request: Request,
        response: Response,
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: db_dependency,
        g_recaptcha_response: str = Form(None)
):
    from datetime import timedelta
    """
    Handle login requests and issue access and refresh tokens.

    Args:
        request: The request object
        response: The response object
        form_data: The form data containing username and password
        db: The database session
        g_recaptcha_response: The reCAPTCHA response from the client

    Returns:
        A dictionary containing the access token, refresh token, and token type
    """
    # Get reCAPTCHA response from query parameters if not in form data
    if g_recaptcha_response is None:
        g_recaptcha_response = request.query_params.get("g_recaptcha_response")

    # Verify reCAPTCHA first with a 'login' action
    recaptcha_verified = await verify_recaptcha(g_recaptcha_response, action="login")
    if not recaptcha_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security verification failed. Please check the reCAPTCHA box and try again. If the problem persists, refresh the page."
        )

    # Check if the request is rate-limited before processing
    # This will raise an HTTPException with status code 429 if rate limited
    check_rate_limit(request, form_data.username)

    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        # Record failed login attempt
        record_failed_attempt(request, form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed: The username or password you entered is incorrect. Please check your credentials and try again."
        )

    # Check if the email is verified
    if not user.email_verified:
        # Generate a new verification token
        verification_token = generate_verification_token()
        user.verification_token = verification_token
        db.add(user)
        db.commit()

        # Invalidate cache for this user
        cache_invalidate_pattern(f"auth:get_user_by_username:{user.username}")

        # Send a new verification email
        send_verification_email(
            to_email=user.email,
            token=verification_token,
            username=user.username
        )

        # Record failed login attempt due to unverified email
        record_failed_attempt(request, form_data.username)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your email address has not been verified yet. We've sent a new verification email to your inbox. Please check your email (including spam folder) and click the verification link to activate your account."
        )

    # Authentication successful, reset failed attempts
    reset_attempts(request, form_data.username)

    # Check if 2FA is enabled for the user
    if user.is_2fa_enabled:
        # Create a session for 2FA verification
        import secrets
        from datetime import datetime, timezone, timedelta

        session_id = secrets.token_urlsafe(32)
        pending_2fa_sessions[session_id] = {
            "user_id": user.id,
            "expires": datetime.now(timezone.utc) + timedelta(minutes=10)
        }

        # Set a cookie with the session ID
        response.set_cookie(
            key="2fa_session",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=600,  # 10 minutes
            path="/"
        )

        # Return a special response indicating 2FA is required
        return {
            'access_token': None,
            'refresh_token': None,
            'token_type': 'bearer',
            'requires_2fa': True,
            'redirect_url': '/auth/verify-2fa-page'
        }

    # If 2FA is not enabled, proceed with normal login
    # Get user agent from request
    user_agent = request.headers.get("user-agent", "")

    # Create access token (short-lived, 10 minutes)
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

    return {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'bearer'}

@router.post("/refresh-token")
async def refresh_access_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str = Cookie(None)
):
    from datetime import timedelta
    """
    Refresh an access token using a refresh token.

    Args:
        request: The request object
        response: The response object
        db: The database session
        refresh_token: The refresh token cookie

    Returns:
        A dictionary containing the new access token and token type
    """
    from jose import jwt, JWTError
    from .token_manager import SECRET_KEY, ALGORITHM, is_token_revoked, hash_user_agent, create_access_token

    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"
        )

    try:
        # Decode and validate the refresh token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        # Verify this is a refresh token
        token_type = payload.get('token_type')
        if token_type != 'refresh':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )

        # Get token identifier
        jti = payload.get('jti')
        if jti is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        # Check if token is revoked
        if is_token_revoked(jti, db):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )

        # Verify user agent fingerprint if present in token
        token_fingerprint = payload.get('fgp')
        if token_fingerprint:
            # Get user agent from request
            user_agent = request.headers.get("user-agent", "")
            # Hash the current user agent
            current_fingerprint = hash_user_agent(user_agent)
            # Compare fingerprints
            if token_fingerprint != current_fingerprint:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    detail="Token was issued for a different device or browser"
                )

        # Extract user information from the refresh token
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')

        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        # Get user agent from request
        user_agent = request.headers.get("user-agent", "")

        # Create a new access token
        new_access_token, new_access_jti, new_access_exp = create_access_token(
            username=username,
            user_id=user_id,
            role=user_role,
            expires_delta=timedelta(minutes=10),  # Reduced from 20 minutes to 10 minutes
            user_agent=user_agent
        )

        # Set the new access token as a cookie (reuse the existing refresh token)
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=600,  # 10 minutes in seconds (reduced from 20 minutes)
            path="/"
        )

        # Return the new access token
        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@router.get("/logout")
async def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db), 
    access_token: str = Cookie(None),
    refresh_token: str = Cookie(None)
):
    """
    Log out a user by revoking their tokens and clearing cookies.

    Args:
        request: The request object
        response: The response object
        db: The database session
        access_token: The access token cookie
        refresh_token: The refresh token cookie

    Returns:
        A dictionary with a success message
    """
    from jose import jwt, JWTError
    from .token_manager import SECRET_KEY, ALGORITHM, revoke_token
    from datetime import datetime, timezone

    # Revoke the access token if present
    if access_token:
        try:
            # Decode the token to get the jti and expiration
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get('jti')
            exp = payload.get('exp')

            if jti and exp:
                # Convert exp to datetime
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                # Revoke the token
                revoke_token(jti, expires_at, db)
        except JWTError:
            # If the token is invalid, just continue with logout
            pass

    # Revoke the refresh token if present
    if refresh_token:
        try:
            # Decode the token to get the jti and expiration
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get('jti')
            exp = payload.get('exp')

            if jti and exp:
                # Convert exp to datetime
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                # Revoke the token
                revoke_token(jti, expires_at, db)
        except JWTError:
            # If the token is invalid, just continue with logout
            pass

    # Clear the access_token cookie
    response.delete_cookie(key="access_token", path="/")
    # Clear the refresh_token cookie
    response.delete_cookie(key="refresh_token", path="/auth/")
    # Return success
    return {"status": "success"}

# Register routes with the router
router.add_api_route("/login-page", render_login_page, methods=["GET"])
router.add_api_route("/token", login_for_access_token, methods=["POST"], response_model=dict)
router.add_api_route("/refresh-token", refresh_access_token, methods=["POST"], response_model=dict)
router.add_api_route("/logout", logout, methods=["GET"], response_model=dict)
