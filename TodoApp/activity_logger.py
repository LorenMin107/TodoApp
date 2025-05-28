"""
Activity logging module for the TodoApp application.

This module provides functionality for logging user activities.
"""

from sqlalchemy.orm import Session
from .models import ActivityLog

def log_activity(db: Session, user_id: int, username: str, action: str, details: str = ""):
    activity_log = ActivityLog(
        user_id=user_id,
        username=username,
        action=action,
        details=details
    )
    
    db.add(activity_log)
    db.commit()