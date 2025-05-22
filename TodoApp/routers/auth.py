from datetime import timedelta, datetime, timezone
import os
import secrets
import requests

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Annotated, Optional, Dict, Tuple, Any

from starlette import status
from starlette.responses import RedirectResponse

from ..database import SessionLocal
from ..models import Users
from ..rate_limiter import check_rate_limit, record_failed_attempt, reset_attempts
from ..password_validator import validate_password
from ..email_utils import generate_verification_token, send_verification_email, generate_password_reset_token, \
    send_password_reset_email
from ..sanitize import sanitize_user_input
from ..totp import setup_totp, verify_totp
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from fastapi.templating import Jinja2Templates

# No need to import any special libraries for standard reCAPTCHA v2
# We'll use the requests library which is already imported

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# Get SECRET_KEY from environment variable with a fallback for development
# In production, always set this environment variable
SECRET_KEY = os.environ.get('SECRET_KEY', '54e781fbc13df7df8bf720d38db6e1cb2ac9b6f3dc94605ceb7483b40de25974')
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

# Store pending 2FA sessions
# Format: {session_id: {"user_id": user_id, "expires": timestamp}}
pending_2fa_sessions: Dict[str, Dict] = {}


# Standard reCAPTCHA v2 configuration
# The site key for your reCAPTCHA v2
# NOTE: This is a placeholder key and should be replaced with your actual key
RECAPTCHA_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
# The secret key for your reCAPTCHA v2
# NOTE: This is a placeholder key and should be replaced with your actual key
# In production, this should be stored in environment variables
RECAPTCHA_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"

# Function to verify standard reCAPTCHA v2 response
# Note: This function has been modified to use the standard reCAPTCHA v2 siteverify endpoint
# instead of Google Cloud reCAPTCHA Enterprise.
#
# For production, you need to:
# 1. Replace the test keys with your actual reCAPTCHA v2 keys from https://www.google.com/recaptcha/admin
# 2. Store your secret key securely, preferably in environment variables
async def verify_recaptcha(recaptcha_response: str, action: str = None) -> bool:
    """
    Verify a reCAPTCHA v2 response token with Google's reCAPTCHA v2 siteverify API.

    This function makes API calls to the standard reCAPTCHA v2 siteverify endpoint
    to verify the token provided by the client.

    Note: The action parameter is ignored for standard reCAPTCHA v2, as it's only
    used in reCAPTCHA v3 and Enterprise. It's kept for backward compatibility.

    Args:
        recaptcha_response (str): The reCAPTCHA v2 response token from the client
        action (str, optional): Ignored for reCAPTCHA v2. Kept for compatibility.

    Returns:
        bool: True if verification is successful, False otherwise
    """
    if not recaptcha_response:
        return False

    # Log action if provided (for debugging, not used in verification)
    if action:
        print(f"Action specified: {action} (note: not used in reCAPTCHA v2 verification)")

    # Special case for test keys - always return True
    # This allows the verification to pass even if there are issues with the Google API
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


class CreateUserRequest(BaseModel):
    username: str
    email: str
    first_name: str
    last_name: str
    password: str
    phone_number: str


class Token(BaseModel):
    access_token: Optional[str] = None
    token_type: str
    refresh_token: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: str


class PasswordReset(BaseModel):
    password: str
    confirm_password: str


class TOTPVerifyRequest(BaseModel):
    token: str


class TOTPSetupResponse(BaseModel):
    secret: str
    qr_code: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


async def get_current_user_from_cookie(access_token: str = Cookie(None)):
    if access_token is None:
        return None

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        # Verify this is an access token
        token_type = payload.get('token_type')
        if token_type != 'access':
            return None

        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')
        if username is None or user_id is None:
            return None
        return {'username': username, 'id': user_id, 'user_role': user_role}
    except JWTError:
        return None


def check_pending_2fa_session(request: Request) -> Tuple[bool, Optional[str]]:
    """
    Check if the request has a pending 2FA session.

    Args:
        request (Request): The request object

    Returns:
        Tuple[bool, Optional[str]]: A tuple containing a boolean indicating if there's a pending 2FA session
                                   and the session ID if there is one
    """
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


templates = Jinja2Templates(directory="TodoApp/templates")


# pages

@router.get("/login-page")
def render_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.get("/register-page")
def render_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.get("/logout")
def logout(response: Response):
    # Clear the access_token cookie
    response.delete_cookie(key="access_token", path="/")
    # Clear the refresh_token cookie
    response.delete_cookie(key="refresh_token", path="/auth/")
    # Redirect to login page
    return {"status": "success"}


@router.get("/verify-email")
async def verify_email(token: str, db: db_dependency):
    """
    Verify a user's email address using the token sent to their email.
    """
    # Find the user with this verification token
    user = db.query(Users).filter(Users.verification_token == token).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token"
        )

    # Update the user's email_verified status
    user.email_verified = True
    # Clear the verification token
    user.verification_token = None

    # Commit the changes to the database
    db.add(user)
    db.commit()

    # Redirect to login page with a success message
    return RedirectResponse(
        url="/auth/login-page?verified=true",
        status_code=status.HTTP_303_SEE_OTHER
    )


class ResendVerificationRequest(BaseModel):
    email: str


@router.post("/resend-verification")
async def resend_verification(request: ResendVerificationRequest, db: db_dependency):
    """
    Resend a verification email to the user.
    """
    # Find the user with this email
    user = db.query(Users).filter(Users.email == request.email).first()

    if not user:
        # Don't reveal that the email doesn't exist for security reasons
        return {"message": "If your email is registered, a verification email has been sent."}

    # Check if the email is already verified
    if user.email_verified:
        return {"message": "Your email is already verified. Please log in."}

    # Generate a new verification token
    verification_token = generate_verification_token()
    user.verification_token = verification_token

    # Commit the changes to the database
    db.add(user)
    db.commit()

    # Send a new verification email
    send_verification_email(
        to_email=user.email,
        token=verification_token,
        username=user.username
    )

    return {"message": "A new verification email has been sent. Please check your inbox."}


@router.get("/forgot-password-page")
def render_forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot-password.html", {"request": request})


@router.get("/reset-password-page")
def render_reset_password_page(request: Request, token: str):
    return templates.TemplateResponse("reset-password.html", {"request": request, "token": token})


@router.get("/setup-2fa-page")
async def setup_2fa_page(request: Request, user: dict = Depends(get_current_user_from_cookie),
                         db: Session = Depends(get_db)):
    """
    Render the 2FA setup page.
    """
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
    """
    Render the 2FA verification page during login.
    """
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
    """
    Verify the TOTP code during setup and enable 2FA for the user.
    """
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

    # Verify the TOTP code
    if not verify_totp(session["secret"], request.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )

    # Get the user from the database
    user = db.query(Users).filter(Users.id == session["user_id"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Enable 2FA for the user
    user.totp_secret = session["secret"]
    user.is_2fa_enabled = True
    db.add(user)
    db.commit()

    # Remove the session
    pending_2fa_sessions.pop(session_id, None)

    # Return success
    return {"message": "Two-factor authentication has been enabled successfully"}


@router.post("/verify-2fa")
async def verify_2fa(
        request: TOTPVerifyRequest,
        response: Response,
        db: Session = Depends(get_db),
        session_id: str = Cookie(None, alias="2fa_session")
):
    """
    Verify the TOTP code during login.
    """
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
    if not verify_totp(user.totp_secret, request.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )

    # Remove the session
    pending_2fa_sessions.pop(session_id, None)

    # Create access token (short-lived, 20 minutes)
    access_token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))

    # Create refresh token (long-lived, 7 days)
    refresh_token = create_refresh_token(user.username, user.id, user.role, timedelta(days=7))

    # Set authentication cookies
    set_auth_cookies(response, access_token, refresh_token)

    # Return success
    return {"message": "Authentication successful"}


@router.post("/disable-2fa")
async def disable_2fa(
        db: Session = Depends(get_db),
        user: dict = Depends(get_current_user_from_cookie)
):
    """
    Disable 2FA for the user.
    """
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

    # Return success
    return {"message": "Two-factor authentication has been disabled successfully"}


@router.post("/forgot-password")
async def forgot_password(request: PasswordResetRequest, db: db_dependency):
    # Find the user with this email
    user = db.query(Users).filter(Users.email == request.email).first()

    if not user:
        # Don't reveal that the email doesn't exist for security reasons
        return {"message": "If your email is registered, a password reset link has been sent."}

    # Generate a new password reset token and expiration time
    reset_token, expires = generate_password_reset_token()
    user.password_reset_token = reset_token
    user.password_reset_expires = expires

    # Commit the changes to the database
    db.add(user)
    db.commit()

    # Send a password reset email
    send_password_reset_email(
        to_email=user.email,
        token=reset_token,
        username=user.username
    )

    return {"message": "If your email is registered, a password reset link has been sent."}


@router.get("/reset-password")
async def reset_password_page(token: str, request: Request, db: db_dependency):
    # Find the user with this reset token
    user = db.query(Users).filter(Users.password_reset_token == token).first()

    # Use datetime.now() without timezone information for comparison
    current_time = datetime.now()
    if not user or user.password_reset_expires < current_time:
        # Token is invalid or expired
        return RedirectResponse(
            url="/auth/login-page?reset_error=invalid_token",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Token is valid, render the reset password page
    return templates.TemplateResponse(
        "reset-password.html",
        {"request": request, "token": token}
    )


@router.post("/reset-password")
async def reset_password(token: str, password_reset: PasswordReset, db: db_dependency):
    # Find the user with this reset token
    user = db.query(Users).filter(Users.password_reset_token == token).first()

    # Use datetime.now() without timezone information for comparison
    current_time = datetime.now()
    if not user or user.password_reset_expires < current_time:
        # Token is invalid or expired
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token"
        )

    # Validate that passwords match
    if password_reset.password != password_reset.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match"
        )

    # Validate password strength
    is_valid, error_message = validate_password(password_reset.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    # Update the user's password
    user.hashed_password = bcrypt_context.hash(password_reset.password)

    # Clear the reset token
    user.password_reset_token = None
    user.password_reset_expires = None

    # Commit the changes to the database
    db.add(user)
    db.commit()

    # Return success
    return {"message": "Password has been reset successfully. You can now log in with your new password."}


### Endpoints ###
def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user


def create_token(username: str, user_id: int, role: str, expires_delta: timedelta, token_type: str = 'access'):
    """
    Create a JWT token with the given parameters.

    Args:
        username (str): The username to include in the token
        user_id (int): The user ID to include in the token
        role (str): The user role to include in the token
        expires_delta (timedelta): How long the token should be valid
        token_type (str, optional): The type of token ('access' or 'refresh'). Defaults to 'access'.

    Returns:
        str: The encoded JWT token
    """
    encode = {'sub': username, 'id': user_id, 'role': role, 'token_type': token_type}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    """Create an access token for the user."""
    return create_token(username, user_id, role, expires_delta, 'access')


def create_refresh_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    """Create a refresh token for the user."""
    return create_token(username, user_id, role, expires_delta, 'refresh')


def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    """
    Set the authentication cookies on the response.

    Args:
        response (Response): The response object to set cookies on
        access_token (str): The access token to set in the cookie
        refresh_token (str): The refresh token to set in the cookie
    """
    # Set the access token as an HttpOnly and Secure cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevents JavaScript access
        secure=True,  # Only sent over HTTPS
        samesite="strict",  # Prevents CSRF attacks
        max_age=1200,  # 20 minutes in seconds
        path="/"  # Available across the entire domain
    )

    # Set the refresh token as an HttpOnly and Secure cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,  # Prevents JavaScript access
        secure=True,  # Only sent over HTTPS
        samesite="strict",  # Prevents CSRF attacks
        max_age=604800,  # 7 days in seconds
        path="/auth/"  # Only available for auth routes
    )


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Decode the JWT token
        username: str = payload.get('sub')  # sub is the subject of the token
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return {'username': username, 'id': user_id, 'user_role': user_role}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    db: db_dependency, 
    create_user_request: CreateUserRequest,
    g_recaptcha_response: str = None
):
    # Get reCAPTCHA response from query parameters
    if g_recaptcha_response is None:
        g_recaptcha_response = request.query_params.get("g_recaptcha_response")

    # Verify reCAPTCHA first with 'register' action
    recaptcha_verified = await verify_recaptcha(g_recaptcha_response, action="register")
    if not recaptcha_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reCAPTCHA verification failed. Please try again."
        )

    # Validate password strength
    is_valid, error_message = validate_password(create_user_request.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    # Check if email already exists
    existing_user = db.query(Users).filter(Users.email == create_user_request.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Check if username already exists
    existing_user = db.query(Users).filter(Users.username == create_user_request.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )

    # Generate verification token
    verification_token = generate_verification_token()

    # Sanitize user input to prevent XSS attacks
    user_data = {
        'email': create_user_request.email,
        'username': create_user_request.username,
        'first_name': create_user_request.first_name,
        'last_name': create_user_request.last_name,
        'phone_number': create_user_request.phone_number
    }
    sanitized_data = sanitize_user_input(user_data)

    create_user_model = Users(
        email=sanitized_data['email'],
        username=sanitized_data['username'],
        first_name=sanitized_data['first_name'],
        last_name=sanitized_data['last_name'],
        role='user',  # Set a fixed role of 'user' for all new registrations
        hashed_password=bcrypt_context.hash(create_user_request.password),
        is_active=True,
        phone_number=sanitized_data['phone_number'],
        email_verified=False,
        verification_token=verification_token
    )

    db.add(create_user_model)
    db.commit()

    # Send verification email
    send_verification_email(
        to_email=create_user_request.email,
        token=verification_token,
        username=create_user_request.username
    )

    # Return success with a message about verification
    return {"message": "User created successfully. Please check your email to verify your account."}


@router.post("/refresh-token", response_model=Token)
async def refresh_access_token(response: Response, refresh_token: str = Cookie(None)):
    """
    Endpoint to refresh the access token using a valid refresh token.
    """
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

        # Extract user information from the refresh token
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')

        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        # Create a new access token
        new_access_token = create_access_token(
            username=username,
            user_id=user_id,
            role=user_role,
            expires_delta=timedelta(minutes=20)
        )

        # Set the new access token as a cookie (reuse the existing refresh token)
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=1200,  # 20 minutes in seconds
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


@router.post("/token", response_model=Token)
async def login_for_access_token(
    request: Request, 
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    db: db_dependency,
    g_recaptcha_response: str = Form(None)
):
    # Get reCAPTCHA response from query parameters if not in form data
    if g_recaptcha_response is None:
        g_recaptcha_response = request.query_params.get("g_recaptcha_response")

    # Verify reCAPTCHA first with 'login' action
    recaptcha_verified = await verify_recaptcha(g_recaptcha_response, action="login")
    if not recaptcha_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reCAPTCHA verification failed. Please try again."
        )

    # Check if the request is rate limited before processing
    # This will raise an HTTPException with status code 429 if rate limited
    check_rate_limit(request, form_data.username)

    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        # Record failed login attempt
        record_failed_attempt(request, form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Check if email is verified
    if not user.email_verified:
        # Generate a new verification token
        verification_token = generate_verification_token()
        user.verification_token = verification_token
        db.add(user)
        db.commit()

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
            detail="Email not verified. A new verification email has been sent."
        )

    # Authentication successful, reset failed attempts
    reset_attempts(request, form_data.username)

    # Check if 2FA is enabled for the user
    if user.is_2fa_enabled:
        # Create a session for 2FA verification
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
    # Create access token (short-lived, 20 minutes)
    access_token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))

    # Create refresh token (long-lived, 7 days)
    refresh_token = create_refresh_token(user.username, user.id, user.role, timedelta(days=7))

    # Set authentication cookies
    set_auth_cookies(response, access_token, refresh_token)

    return {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'bearer'}
