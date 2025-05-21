from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class CSPMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add Content Security Policy headers to all responses.

    Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate
    certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.
    """

    async def dispatch(self, request: Request, call_next):
        # Process the request
        response = await call_next(request)

        # Define CSP directives
        csp_directives = {
            # Allow resources from same origin
            "default-src": "'self'",
            # Allow styles from same origin and inline styles
            "style-src": "'self' 'unsafe-inline'",
            # Allow scripts from same origin and inline scripts (needed for CSRF token)
            "script-src": "'self' 'unsafe-inline'",
            # Allow images from same origin and data URIs (for QR codes)
            "img-src": "'self' data:",
            # Allow fonts from same origin
            "font-src": "'self'",
            # Restrict object sources
            "object-src": "'none'",
            # Restrict base URI
            "base-uri": "'self'",
            # Form submissions can only target same origin
            "form-action": "'self'",
            # Frame ancestors restricted to same origin (prevents clickjacking)
            "frame-ancestors": "'self'",
            # Block mixed content
            "block-all-mixed-content": "",
        }

        # Convert directives to string
        csp_header_value = "; ".join(
            f"{key} {value}" if value else key
            for key, value in csp_directives.items()
        )

        # Add CSP header to response
        response.headers["Content-Security-Policy"] = csp_header_value

        # Add X-Content-Type-Options header to prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Add X-Frame-Options header to prevent clickjacking
        response.headers["X-Frame-Options"] = "SAMEORIGIN"

        # Add Referrer-Policy header to control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response
