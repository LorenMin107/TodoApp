"""
Authentication module for the TodoApp application.

This module provides authentication functionality including login, registration,
two-factor authentication, password reset, and token management.
"""

from fastapi import APIRouter

# Create a router for the auth module
router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# Import and re-export components from submodules
from .token_manager import (
    SECRET_KEY, ALGORITHM, 
    get_current_user, get_current_user_from_cookie,
    hash_password, verify_password,
    bcrypt_context
)

from .login import authenticate_user
from .two_factor import check_pending_2fa_session

# Import and register routes
from . import login, registration, two_factor, password_reset

# The router is exported and used in main.py