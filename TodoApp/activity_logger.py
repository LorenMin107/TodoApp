"""
Activity logging module for the TodoApp application.

This module provides functionality for logging user activities.
"""

from sqlalchemy.orm import Session
from .models import ActivityLog

def log_activity(db: Session, user_id: int, username: str, action: str, details: str = ""):
    """
    Log a user activity.
    
    Args:
        db: The database session
        user_id: The ID of the user who performed the action
        username: The username of the user who performed the action
        action: The action that was performed (e.g., "login", "create_todo", "delete_todo")
        details: Additional details about the action
    """
    activity_log = ActivityLog(
        user_id=user_id,
        username=username,
        action=action,
        details=details
    )
    
    db.add(activity_log)
    db.commit()