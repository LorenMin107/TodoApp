"""
Token management module for the TodoApp application.

This module provides functionality for creating, validating, and revoking JWT tokens
used for authentication and authorization.
"""

import os
import secrets
import hashlib
import uuid
from datetime import timedelta, datetime, timezone
from typing import Annotated, Dict

from fastapi import Depends, HTTPException, Request, Cookie
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from starlette import status

from ...database import SessionLocal
from ...models import RevokedToken

# Constants
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set. Please set it in the .env file.")
ALGORITHM = os.environ.get('ALGORITHM', 'HS256')

# Get password pepper from the environment or generate a secure one if not set
# The pepper adds another layer of security beyond the salt that bcrypt already uses
PASSWORD_PEPPER = os.environ.get('PASSWORD_PEPPER')
if not PASSWORD_PEPPER:
    # Generate a secure pepper and log a warning that it's not set in the environment
    PASSWORD_PEPPER = secrets.token_hex(16)
    print("WARNING: PASSWORD_PEPPER environment variable is not set. Using a generated value.")
    print("For production, set a permanent PASSWORD_PEPPER in your .env file.")

# Set a higher work factor (12) for better security
# The work factor determines how computationally intensive the hashing will be
# Higher values are more secure but take longer to compute
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

# Store pending 2FA sessions
pending_2fa_sessions: Dict[str, Dict] = {}

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

# Helper functions for password hashing and verification with pepper
def hash_password(password: str) -> str:
    """
    Hash a password with bcrypt, adding a pepper before hashing.
    The pepper is a server-side secret that adds another layer of security.

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

def hash_user_agent(user_agent: str) -> str:
    """
    Create a hash of the user agent string to use for token fingerprinting.

    Args:
        user_agent: The user agent strings from the request headers

    Returns:
        A hash of the user agent string
    """
    if not user_agent:
        return "unknown"

    # Create an SHA-256 hash of the user agent
    return hashlib.sha256(user_agent.encode()).hexdigest()

def create_token(username: str, user_id: int, role: str, expires_delta: timedelta, token_type: str = 'access', user_agent: str = None):
    """
    Create a JWT token with the given parameters.

    Args:
        username: The username of the user
        user_id: The ID of the user
        role: The role of the user
        expires_delta: How long the token should be valid for
        token_type: The type of token ('access' or 'refresh')
        user_agent: The user agent string from the request headers

    Returns:
        A tuple containing the token, the jti, and the expiration time
    """
    # Generate a unique token ID (jti)
    jti = str(uuid.uuid4())

    # Create the token payload
    encode = {
        'sub': username,
        'id': user_id,
        'role': role,
        'token_type': token_type,
        'jti': jti  # Include the unique token ID
    }

    # Add user agent fingerprint if provided
    if user_agent:
        encode['fgp'] = hash_user_agent(user_agent)

    # Set expiration time
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})

    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM), jti, expires

def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta, user_agent: str = None):
    """
    Create an access token with the given parameters.

    Args:
        username: The username of the user
        user_id: The ID of the user
        role: The role of the user
        expires_delta: How long the token should be valid for
        user_agent: The user agent string from the request headers

    Returns:
        A tuple containing the token, the jti, and the expiration time
    """
    return create_token(username, user_id, role, expires_delta, 'access', user_agent)

def create_refresh_token(username: str, user_id: int, role: str, expires_delta: timedelta, user_agent: str = None):
    """
    Create a refresh token with the given parameters.

    Args:
        username: The username of the user
        user_id: The ID of the user
        role: The role of the user
        expires_delta: How long the token should be valid for
        user_agent: The user agent string from the request headers

    Returns:
        A tuple containing the token, the jti, and the expiration time
    """
    return create_token(username, user_id, role, expires_delta, 'refresh', user_agent)

def is_token_revoked(jti: str, db: Session) -> bool:
    """
    Check if a token is revoked.

    Args:
        jti: The unique identifier of the token
        db: The database session

    Returns:
        True if the token is revoked, False otherwise
    """
    revoked_token = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
    return revoked_token is not None

def revoke_token(jti: str, expires_at: datetime, db: Session) -> None:
    """
    Revoke a token by adding it to the revoked tokens table.

    Args:
        jti: The unique identifier of the token
        expires_at: When the token would have expired
        db: The database session
    """
    revoked_token = RevokedToken(
        jti=jti,
        revoked_at=datetime.now(timezone.utc),
        expires_at=expires_at
    )
    db.add(revoked_token)
    db.commit()

    # Clean up expired tokens occasionally (1 in 10 chance)
    if secrets.randbelow(10) == 0:
        cleanup_expired_tokens(db)

def cleanup_expired_tokens(db: Session) -> None:
    """
    Remove expired tokens from the revoked tokens table.
    This helps prevent the database from growing too large.

    Args:
        db: The database session
    """
    current_time = datetime.now(timezone.utc)
    db.query(RevokedToken).filter(RevokedToken.expires_at < current_time).delete()
    db.commit()

def set_auth_cookies(response, access_token: str, refresh_token: str):
    """
    Set authentication cookies for the response.

    Args:
        response: The response object
        access_token: The access token to set as a cookie
        refresh_token: The refresh token to set as a cookie
    """
    # Set the access token as an HttpOnly and Secure cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevents JavaScript access
        secure=True,  # Only sent over HTTPS
        samesite="strict",  # Prevents CSRF attacks
        max_age=600,  # 10 minutes in seconds (reduced from 20 minutes)
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

async def get_current_user(request: Request, token: Annotated[str, Depends(oauth2_bearer)], db: Session = Depends(get_db)):
    """
    Get the current user from the JWT token.

    Args:
        request: The request object
        token: The JWT token
        db: The database session

    Returns:
        A dictionary containing the username, id, and user_role of the current user

    Raises:
        HTTPException: If the token is invalid or has been revoked
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Decode the JWT token

        # Get token identifier
        jti = payload.get('jti')
        if jti is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        # Check if the token is revoked
        if is_token_revoked(jti, db):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

        # Verify user agent fingerprint if present in token
        token_fingerprint = payload.get('fgp')
        if token_fingerprint:
            # Get a user agent from request
            user_agent = request.headers.get("user-agent", "")
            # Hash the current user agent
            current_fingerprint = hash_user_agent(user_agent)
            # Compare fingerprints
            if token_fingerprint != current_fingerprint:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    detail="Token was issued for a different device or browser"
                )

        username: str = payload.get('sub')  # sub is the subject of the token
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return {'username': username, 'id': user_id, 'user_role': user_role}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

async def get_current_user_from_cookie(request: Request, access_token: str = Cookie(None), db: Session = Depends(get_db)):
    """
    Get the current user from the access_token cookie.

    Args:
        request: The request object
        access_token: The access token cookie
        db: The database session

    Returns:
        A dictionary containing the username, id, and user_role of the current user, or None if the token is invalid
    """
    if access_token is None:
        return None

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])

        # Verify this is an access token
        token_type = payload.get('token_type')
        if token_type != 'access':
            return None

        # Get token identifier
        jti = payload.get('jti')
        if jti is None:
            return None

        # Check if the token is revoked
        if is_token_revoked(jti, db):
            return None

        # Verify user agent fingerprint if present in token
        token_fingerprint = payload.get('fgp')
        if token_fingerprint:
            # Get a user agent from request
            user_agent = request.headers.get("user-agent", "")
            # Hash the current user agent
            current_fingerprint = hash_user_agent(user_agent)
            # Compare fingerprints
            if token_fingerprint != current_fingerprint:
                return None

        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')
        if username is None or user_id is None:
            return None

        return {'username': username, 'id': user_id, 'user_role': user_role}
    except JWTError:
        return None
