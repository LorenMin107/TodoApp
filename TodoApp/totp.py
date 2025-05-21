import pyotp
import qrcode
import io
import base64
from typing import Tuple

def generate_totp_secret() -> str:
    """
    Generate a new TOTP secret key.
    
    Returns:
        str: A base32-encoded secret key
    """
    return pyotp.random_base32()

def get_totp_uri(username: str, secret: str, issuer_name: str = "TodoApp") -> str:
    """
    Generate a TOTP URI for use with authenticator apps.
    
    Args:
        username (str): The username of the user
        secret (str): The TOTP secret key
        issuer_name (str, optional): The name of the issuer. Defaults to "TodoApp".
    
    Returns:
        str: A TOTP URI
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=issuer_name
    )

def generate_qr_code(totp_uri: str) -> str:
    """
    Generate a QR code image for the TOTP URI.
    
    Args:
        totp_uri (str): The TOTP URI
    
    Returns:
        str: A base64-encoded QR code image
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert the image to a base64-encoded string
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def verify_totp(secret: str, token: str) -> bool:
    """
    Verify a TOTP token.
    
    Args:
        secret (str): The TOTP secret key
        token (str): The TOTP token to verify
    
    Returns:
        bool: True if the token is valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def setup_totp(username: str) -> Tuple[str, str, str]:
    """
    Set up TOTP for a user.
    
    Args:
        username (str): The username of the user
    
    Returns:
        Tuple[str, str, str]: A tuple containing the secret key, URI, and QR code
    """
    secret = generate_totp_secret()
    uri = get_totp_uri(username, secret)
    qr_code = generate_qr_code(uri)
    
    return secret, uri, qr_code