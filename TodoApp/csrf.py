import secrets
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette import status
from typing import Optional

# Constants
CSRF_TOKEN_SECRET = secrets.token_hex(32)  # Generate a random secret for CSRF tokens
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_COOKIE_NAME = "csrf_token"
CSRF_TOKEN_EXPIRY_SECONDS = 3600  # 1 hour

# Security scheme for CSRF token in the header
csrf_scheme = HTTPBearer(auto_error=False)


def generate_csrf_token() -> str:
    return secrets.token_hex(32)


async def get_csrf_token_from_header(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(csrf_scheme),
) -> Optional[str]:
    if credentials:
        return credentials.credentials
    return None


async def get_csrf_token_from_cookie(request: Request) -> Optional[str]:
    return request.cookies.get(CSRF_COOKIE_NAME)


async def validate_csrf_token(
        request: Request,
        csrf_token_header: Optional[str] = Depends(get_csrf_token_from_header),
) -> bool:
    # Skip validation for GET, HEAD, OPTIONS requests as they should be safe
    if request.method.upper() in ("GET", "HEAD", "OPTIONS"):
        return True

    # Get token from a cookie
    csrf_token_cookie = await get_csrf_token_from_cookie(request)

    # For API endpoints, check header token against cookie token
    if csrf_token_header and csrf_token_cookie:
        if csrf_token_header == csrf_token_cookie:
            return True

    # For form submissions, check form field against cookie token
    form_data = await request.form()
    csrf_token_form = form_data.get("csrf_token")
    if csrf_token_form and csrf_token_cookie and csrf_token_form == csrf_token_cookie:
        return True

    # If we get here, CSRF validation failed
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="CSRF token validation failed",
    )


# Middleware to inject CSRF token into the request state for templates
async def csrf_middleware(request: Request, call_next):
    # Generate a new CSRF token if one doesn't exist
    csrf_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not csrf_token:
        csrf_token = generate_csrf_token()

    # Add the token to request state for templates
    request.state.csrf_token = csrf_token

    # Process the request
    response = await call_next(request)

    # Set the CSRF token cookie in the response if it doesn't exist
    if CSRF_COOKIE_NAME not in request.cookies:
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            httponly=True,  # Not accessible via JavaScript
            samesite="strict",  # Strict same-site policy
            max_age=CSRF_TOKEN_EXPIRY_SECONDS,
        )

    # Don't modify redirect responses that already have query parameters
    from starlette.responses import RedirectResponse
    if isinstance(response, RedirectResponse) and '?' in response.headers.get('location', ''):
        return response

    return response
