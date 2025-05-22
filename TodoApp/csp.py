from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        # Process the request
        response = await call_next(request)

        # Define CSP directives
        csp_directives = {
            # Allow resources from same origin
            "default-src": "'self'",
            # Allow styles from same origin and inline styles
            "style-src": "'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com",
            # Allow scripts from same origin, inline scripts, and Google reCAPTCHA
            "script-src": "'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com",
            # Allow images from same origin, data URIs, and Google reCAPTCHA
            "img-src": "'self' data: https://www.google.com https://www.gstatic.com",
            # Allow fonts from same origin and Google
            "font-src": "'self' https://www.gstatic.com",
            # Restrict object sources
            "object-src": "'none'",
            # Restrict base URI
            "base-uri": "'self'",
            # Form submissions can only target same origin
            "form-action": "'self'",
            # Frame ancestors restricted to same origin (prevents clickjacking)
            "frame-ancestors": "'self'",
            # Allow frames from Google reCAPTCHA
            "frame-src": "https://www.google.com",
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
