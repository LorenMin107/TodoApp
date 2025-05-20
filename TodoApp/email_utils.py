import logging
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional
from dotenv import load_dotenv
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Email configuration
# In production, these should be set as environment variables
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
EMAIL_FROM = os.environ.get('EMAIL_FROM')
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://localhost:8000')

# Log email configuration for debugging
logger.info(f"Email Configuration:")
logger.info(f"SMTP_SERVER: {SMTP_SERVER}")
logger.info(f"SMTP_PORT: {SMTP_PORT}")
logger.info(f"SMTP_USERNAME: {SMTP_USERNAME}")
logger.info(f"EMAIL_FROM: {EMAIL_FROM}")
logger.info(f"APP_BASE_URL: {APP_BASE_URL}")
logger.info(f"SMTP_PASSWORD configured: {'Yes' if SMTP_PASSWORD else 'No'}")

def generate_verification_token() -> str:
    """Generate a secure random token for email verification."""
    return secrets.token_urlsafe(32)

def generate_password_reset_token() -> tuple:
    """
    Generate a secure random token for password reset and its expiration time.

    Returns:
        tuple: (token, expiration_time) where expiration_time is 1 hour from now
    """
    token = secrets.token_urlsafe(32)
    expires = datetime.now() + timedelta(hours=1)
    return token, expires

def send_email(to_email: str, subject: str, html_content: str, text_content: Optional[str] = None) -> bool:
    """
    Send an email using SMTP.

    Args:
        to_email: The recipient's email address
        subject: The email subject
        html_content: The HTML content of the email
        text_content: The plain text content of the email (optional)

    Returns:
        bool: True if the email was sent successfully, False otherwise
    """
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        # Log a warning that email sending is not configured
        print("Warning: SMTP credentials not configured. Email not sent.")
        return False

    # Create a multipart message
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = EMAIL_FROM
    message["To"] = to_email

    # Add plain text version (if provided)
    if text_content:
        message.attach(MIMEText(text_content, "plain"))

    # Add HTML version
    message.attach(MIMEText(html_content, "html"))

    try:
        # Connect to the SMTP server
        logger.info(f"Connecting to SMTP server {SMTP_SERVER}:{SMTP_PORT}")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)

        logger.info("Starting TLS connection")
        server.starttls()  # Secure the connection

        logger.info(f"Logging in with username: {SMTP_USERNAME}")
        server.login(SMTP_USERNAME, SMTP_PASSWORD)

        # Send the email
        logger.info(f"Sending email from {EMAIL_FROM} to {to_email}")
        server.sendmail(EMAIL_FROM, to_email, message.as_string())
        server.quit()
        logger.info("Email sent successfully")
        return True
    except Exception as e:
        # Log the error with detailed information
        logger.error(f"Error sending email: {e}")
        logger.error(f"Email configuration: SMTP_SERVER={SMTP_SERVER}, SMTP_PORT={SMTP_PORT}, SMTP_USERNAME={SMTP_USERNAME}, EMAIL_FROM={EMAIL_FROM}")
        return False

def send_verification_email(to_email: str, token: str, username: str) -> bool:
    """
    Send an email verification link to the user.

    Args:
        to_email: The user's email address
        token: The verification token
        username: The user's username

    Returns:
        bool: True if the email was sent successfully, False otherwise
    """
    logger.info(f"Preparing verification email for {username} ({to_email}) with token {token[:10]}...")

    verification_url = f"{APP_BASE_URL}/auth/verify-email?token={token}"
    logger.info(f"Verification URL: {verification_url}")

    subject = "Verify your TodoApp email address"

    # HTML content
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #4CAF50; color: white; padding: 10px; text-align: center; }}
            .content {{ padding: 20px; }}
            .button {{ display: inline-block; background-color: #4CAF50; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>TodoApp Email Verification</h1>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                <p>Thank you for registering with TodoApp. Please verify your email address by clicking the button below:</p>
                <p><a href="{verification_url}" class="button">Verify Email</a></p>
                <p>Or copy and paste this link into your browser:</p>
                <p>{verification_url}</p>
                <p>This link will expire in 24 hours.</p>
                <p>If you did not register for a TodoApp account, please ignore this email.</p>
                <p>Best regards,<br>The TodoApp Team</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Plain text content
    text_content = f"""
    Hello {username},

    Thank you for registering with TodoApp. Please verify your email address by clicking the link below:

    {verification_url}

    This link will expire in 24 hours.

    If you did not register for a TodoApp account, please ignore this email.

    Best regards,
    The TodoApp Team
    """

    result = send_email(to_email, subject, html_content, text_content)
    if result:
        logger.info(f"Verification email sent successfully to {to_email}")
    else:
        logger.error(f"Failed to send verification email to {to_email}")

    return result

def send_password_reset_email(to_email: str, token: str, username: str) -> bool:
    """
    Send a password reset link to the user.

    Args:
        to_email: The user's email address
        token: The password reset token
        username: The user's username

    Returns:
        bool: True if the email was sent successfully, False otherwise
    """
    logger.info(f"Preparing password reset email for {username} ({to_email}) with token {token[:10]}...")

    reset_url = f"{APP_BASE_URL}/auth/reset-password?token={token}"
    logger.info(f"Password reset URL: {reset_url}")

    subject = "Reset your TodoApp password"

    # HTML content
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #4CAF50; color: white; padding: 10px; text-align: center; }}
            .content {{ padding: 20px; }}
            .button {{ display: inline-block; background-color: #4CAF50; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>TodoApp Password Reset</h1>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                <p>We received a request to reset your password for your TodoApp account. Please click the button below to reset your password:</p>
                <p><a href="{reset_url}" class="button">Reset Password</a></p>
                <p>Or copy and paste this link into your browser:</p>
                <p>{reset_url}</p>
                <p>This link will expire in 1 hour.</p>
                <p>If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
                <p>Best regards,<br>The TodoApp Team</p>
            </div>
        </div>
    </body>
    </html>
    """

    # Plain text content
    text_content = f"""
    Hello {username},

    We received a request to reset your password for your TodoApp account. Please click the link below to reset your password:

    {reset_url}

    This link will expire in 1 hour.

    If you did not request a password reset, please ignore this email or contact support if you have concerns.

    Best regards,
    The TodoApp Team
    """

    result = send_email(to_email, subject, html_content, text_content)
    if result:
        logger.info(f"Password reset email sent successfully to {to_email}")
    else:
        logger.error(f"Failed to send password reset email to {to_email}")

    return result
