from datetime import timedelta, datetime, timezone
import os
import secrets
import requests

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Annotated, Optional, Dict, Tuple

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

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set. Please set it in the .env file.")
ALGORITHM = os.environ.get('ALGORITHM', 'HS256')

# Get password pepper from environment or generate a secure one if not set
# The pepper adds an additional layer of security beyond the salt that bcrypt already uses
PASSWORD_PEPPER = os.environ.get('PASSWORD_PEPPER')
if not PASSWORD_PEPPER:
    # Generate a secure pepper and log a warning that it's not set in environment
    PASSWORD_PEPPER = secrets.token_hex(16)
    print("WARNING: PASSWORD_PEPPER environment variable is not set. Using a generated value.")
    print("For production, set a permanent PASSWORD_PEPPER in your .env file.")

# Set a higher work factor (12) for better security
# The work factor determines how computationally intensive the hashing will be
# Higher values are more secure but take longer to compute
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

# Helper functions for password hashing and verification with pepper
def hash_password(password: str) -> str:
    """
    Hash a password with bcrypt, adding a pepper before hashing.
    The pepper is a server-side secret that adds an additional layer of security.

    Args:
        password: The plaintext password to hash

    Returns:
        The hashed password
    """
    # Combine the password with the pepper before hashing
    peppered_password = f"{password}{PASSWORD_PEPPER}"
    return bcrypt_context.hash(peppered_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hashed password, adding the pepper before verification.

    Args:
        plain_password: The plaintext password to verify
        hashed_password: The hashed password to verify against

    Returns:
        True if the password matches, False otherwise
    """
    # Combine the password with the pepper before verification
    peppered_password = f"{plain_password}{PASSWORD_PEPPER}"
    return bcrypt_context.verify(peppered_password, hashed_password)
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

# Store pending 2FA sessions
pending_2fa_sessions: Dict[str, Dict] = {}

# Standard reCAPTCHA v2 configuration test keys
RECAPTCHA_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
# The secret key for your reCAPTCHA v2 test site key
RECAPTCHA_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"


async def verify_recaptcha(recaptcha_response: str, action: str = None) -> bool:
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
    # Find the user with this verification token
    user = db.query(Users).filter(Users.verification_token == token).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The verification link is invalid or has expired. Please request a new verification email from the login page."
        )

    # Update the user's email_verified status
    user.email_verified = True
    # Clear the verification token
    user.verification_token = None

    # Commit the changes to the database
    db.add(user)
    db.commit()

    # Redirect to the login page with a success message
    return RedirectResponse(
        url="/auth/login-page?verified=true",
        status_code=status.HTTP_303_SEE_OTHER
    )


class ResendVerificationRequest(BaseModel):
    email: str


@router.post("/resend-verification")
async def resend_verification(request: ResendVerificationRequest, db: db_dependency):
    # Find the user with this email
    user = db.query(Users).filter(Users.email == request.email).first()

    if not user:
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

    # Create an access token (short-lived, 20 minutes)
    access_token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))

    # Create a refresh token (long-lived, 7 days)
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
            detail="Your password reset link has expired or is invalid. Please request a new password reset link from the forgot password page."
        )

    # Validate that passwords match
    if password_reset.password != password_reset.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The passwords you entered don't match. Please make sure both password fields contain the same password."
        )

    # Validate password strength
    is_valid, error_message = validate_password(password_reset.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    # Update the user's password
    user.hashed_password = hash_password(password_reset.password)

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
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_token(username: str, user_id: int, role: str, expires_delta: timedelta, token_type: str = 'access'):
    encode = {'sub': username, 'id': user_id, 'role': role, 'token_type': token_type}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    return create_token(username, user_id, role, expires_delta, 'access')


def create_refresh_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    return create_token(username, user_id, role, expires_delta, 'refresh')


def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
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

    # Verify reCAPTCHA first with the 'register' action
    recaptcha_verified = await verify_recaptcha(g_recaptcha_response, action="register")
    if not recaptcha_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security verification failed. Please check the reCAPTCHA box and try again. If the problem persists, refresh the page."
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
            detail="This email address is already registered. Please use a different email or try logging in if you already have an account."
        )

    # Check if the username already exists
    existing_user = db.query(Users).filter(Users.username == create_user_request.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This username is already taken. Please choose a different username to continue registration."
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
        hashed_password=hash_password(create_user_request.password),
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

    # Create a refresh token (long-lived, 7 days)
    refresh_token = create_refresh_token(user.username, user.id, user.role, timedelta(days=7))

    # Set authentication cookies
    set_auth_cookies(response, access_token, refresh_token)

    return {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'bearer'}
