from .database import Base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from datetime import datetime


class RevokedToken(Base):
    __tablename__ = 'revoked_tokens'

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True)  # JWT ID (unique identifier for the token)
    revoked_at = Column(DateTime)
    expires_at = Column(DateTime)  # When the token would have expired


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(String, index=True)  # Add index for role-based queries
    phone_number = Column(String)
    email_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True, index=True)  # Add index for verification token lookups
    password_reset_token = Column(String, nullable=True, index=True)  # Add index for password reset token lookups
    password_reset_expires = Column(DateTime, nullable=True)
    totp_secret = Column(String, nullable=True)
    is_2fa_enabled = Column(Boolean, default=False)


class Todos(Base):
    __tablename__ = 'todos'

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    priority = Column(Integer, index=True)  # Add index for priority-based filtering
    complete = Column(Boolean, default=False, index=True)  # Add index for completion status filtering
    owner_id = Column(Integer, ForeignKey('users.id'), index=True)  # Add index for owner-based filtering


class ActivityLog(Base):
    __tablename__ = 'activity_logs'

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)  # When the activity occurred
    user_id = Column(Integer, ForeignKey('users.id'), index=True)  # Who performed the action
    username = Column(String)  # Store username for easier querying
    action = Column(String, index=True)  # What action was performed (e.g., "login", "create_todo", "delete_todo")
    details = Column(String)  # Additional details about the action
