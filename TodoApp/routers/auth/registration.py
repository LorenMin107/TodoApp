"""
Registration module for the TodoApp application.

This module provides functionality for user registration and email verification.
"""

from fastapi import HTTPException, Request
from pydantic import BaseModel

from starlette import status
from starlette.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ...models import Users
from ...password_validator import validate_password
from ...email_utils import generate_verification_token, send_verification_email
from ...sanitize import sanitize_user_input
from ...cache import cache_invalidate_pattern

from . import router
from .token_manager import hash_password, db_dependency
from .login import verify_recaptcha

# Templates for rendering pages
templates = Jinja2Templates(directory="TodoApp/templates")


# Request models
class CreateUserRequest(BaseModel):
    username: str
    email: str
    first_name: str
    last_name: str
    password: str
    phone_number: str


class ResendVerificationRequest(BaseModel):
    email: str


# Routes
@router.get("/register-page")
def render_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


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
            detail="Security verification failed. Please check the reCAPTCHA box and try again. "
                   "If the problem persists, refresh the page."
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

    # Invalidate cache for this user
    cache_invalidate_pattern(f"auth:get_user_by_username:{user.username}")

    # Redirect to the login page with a success message
    return RedirectResponse(
        url="/auth/login-page?verified=true",
        status_code=status.HTTP_303_SEE_OTHER
    )


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

    # Invalidate cache for this user
    cache_invalidate_pattern(f"auth:get_user_by_username:{user.username}")

    # Send a new verification email
    send_verification_email(
        to_email=user.email,
        token=verification_token,
        username=user.username
    )

    return {"message": "A new verification email has been sent. Please check your inbox."}


# Register routes with the router
router.add_api_route("/register-page", render_register_page, methods=["GET"])
router.add_api_route("/", create_user, methods=["POST"], status_code=status.HTTP_201_CREATED)
router.add_api_route("/verify-email", verify_email, methods=["GET"])
router.add_api_route("/resend-verification", resend_verification, methods=["POST"])
