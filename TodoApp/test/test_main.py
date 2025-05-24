from fastapi.testclient import TestClient
from ..main import app
from fastapi import status

client = TestClient(app)

def test_return_health_check():
    response = client.get("/healthy")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "healthy"}

def test_security_headers():
    """Test that security headers are properly set in the response."""
    response = client.get("/healthy")

    # Check Content-Security-Policy header
    assert "Content-Security-Policy" in response.headers

    # Check X-Content-Type-Options header
    assert response.headers["X-Content-Type-Options"] == "nosniff"

    # Check X-Frame-Options header
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"

    # Check Referrer-Policy header
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    # Check Strict-Transport-Security header
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains; preload"

    # Check Permissions-Policy header
    assert "Permissions-Policy" in response.headers
    assert "camera=()" in response.headers["Permissions-Policy"]
    assert "microphone=()" in response.headers["Permissions-Policy"]
    assert "geolocation=()" in response.headers["Permissions-Policy"]

    # Check X-XSS-Protection header
    assert response.headers["X-XSS-Protection"] == "1; mode=block"

    # Check X-Content-Security-Policy header
    assert "X-Content-Security-Policy" in response.headers
