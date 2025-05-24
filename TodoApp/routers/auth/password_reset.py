"""
Password reset module for the TodoApp application.

This module provides functionality for requesting a password reset, verifying
the reset token, and setting a new password.
"""

from datetime import datetime

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from starlette.responses import RedirectResponse

from ...database import SessionLocal
from ...models import Users
from ...password_validator import validate_password
from ...email_utils import generate_password_reset_token, send_password_reset_email

from . import router
from .token_manager import hash_password, db_dependency

# Templates for rendering pages
templates = Jinja2Templates(directory="TodoApp/templates")

# Request models
class PasswordResetRequest(BaseModel):
    email: str

class PasswordReset(BaseModel):
    password: str
    confirm_password: str

# Routes
@router.get("/forgot-password-page")
def render_forgot_password_page(request: Request):
    """
    Render the forgot password page.

    Args:
        request: The request object

    Returns:
        The rendered forgot password page
    """
    return templates.TemplateResponse("forgot-password.html", {"request": request})

@router.get("/reset-password-page")
def render_reset_password_page(request: Request, token: str):
    """
    Render the reset password page.

    Args:
        request: The request object
        token: The password reset token

    Returns:
        The rendered reset password page
    """
    return templates.TemplateResponse("reset-password.html", {"request": request, "token": token})

@router.post("/forgot-password")
async def forgot_password(request: PasswordResetRequest, db: db_dependency):
    """
    Request a password reset.

    Args:
        request: The request containing the email address
        db: The database session

    Returns:
        A dictionary with a success message
    """
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
    """
    Verify a password reset token and render the reset password page.

    Args:
        token: The password reset token
        request: The request object
        db: The database session

    Returns:
        The rendered reset password page or a redirect to the login page with an error message
    """
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
    """
    Reset a user's password.

    Args:
        token: The password reset token
        password_reset: The new password data
        db: The database session

    Returns:
        A dictionary with a success message
    """
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

# Register routes with the router
router.add_api_route("/forgot-password-page", render_forgot_password_page, methods=["GET"])
router.add_api_route("/reset-password-page", render_reset_password_page, methods=["GET"])
router.add_api_route("/forgot-password", forgot_password, methods=["POST"])
router.add_api_route("/reset-password", reset_password_page, methods=["GET"])
router.add_api_route("/reset-password", reset_password, methods=["POST"])