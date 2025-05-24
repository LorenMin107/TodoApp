"""
Admin initialization module for the TodoApp application.

This module provides functionality for initializing the admin user during application startup.
"""

import os
import secrets
import string
from sqlalchemy.orm import Session
from .models import Users
from .routers.auth.token_manager import hash_password

def initialize_admin_user(db: Session):
    """
    Initialize the admin user if it doesn't exist.
    
    Args:
        db: The database session
    """
    # Get admin email and password from environment variables
    admin_email = os.environ.get('SUPERADMIN_EMAIL')
    admin_password = os.environ.get('SUPERADMIN_PASSWORD')
    
    if not admin_email:
        print("WARNING: SUPERADMIN_EMAIL environment variable is not set. Skipping admin user creation.")
        return
    
    # Check if admin user already exists
    admin_user = db.query(Users).filter(Users.email == admin_email).first()
    
    if admin_user:
        # If admin user exists but doesn't have admin role, update it
        if admin_user.role != 'admin':
            print(f"Updating user {admin_email} to have admin role")
            admin_user.role = 'admin'
            db.add(admin_user)
            db.commit()
    else:
        # If admin user doesn't exist, create it
        print(f"Creating admin user {admin_email}")
        
        # If admin password is not set, generate a secure one
        if not admin_password:
            # Generate a secure password
            alphabet = string.ascii_letters + string.digits + string.punctuation
            admin_password = ''.join(secrets.choice(alphabet) for _ in range(16))
            print(f"Generated admin password: {admin_password}")
            print("Please save this password as it won't be shown again.")
        
        # Create admin user
        admin_user = Users(
            email=admin_email,
            username="admin",
            first_name="Admin",
            last_name="User",
            role='admin',
            hashed_password=hash_password(admin_password),
            is_active=True,
            email_verified=True,
            phone_number=""
        )
        
        db.add(admin_user)
        db.commit()
        print(f"Admin user {admin_email} created successfully")