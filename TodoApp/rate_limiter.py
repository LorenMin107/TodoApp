from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException
from starlette import status

# Configuration
MAX_FAILED_ATTEMPTS = 5  # Maximum number of failed attempts allowed
LOCKOUT_PERIOD = 15  # Lockout period in minutes

failed_attempts: Dict[str, List[datetime]] = {}

def get_identifier(request: Request, username: str = None) -> str:
    client_ip = request.client.host if request.client else "unknown"
    if username:
        return f"{client_ip}:{username}"
    return client_ip

def record_failed_attempt(request: Request, username: str = None) -> None:
    identifier = get_identifier(request, username)
    now = datetime.now()
    
    # Initialize the list if this is the first attempt
    if identifier not in failed_attempts:
        failed_attempts[identifier] = []
    
    # Add the current timestamp to the list of failed attempts
    failed_attempts[identifier].append(now)
    
    # Clean up old attempts (older than the lockout period)
    cleanup_old_attempts()

def cleanup_old_attempts() -> None:
    now = datetime.now()
    cutoff_time = now - timedelta(minutes=LOCKOUT_PERIOD)
    
    for identifier in list(failed_attempts.keys()):
        # Filter out attempts that are older than the cutoff time
        failed_attempts[identifier] = [
            attempt for attempt in failed_attempts[identifier]
            if attempt > cutoff_time
        ]
        
        # Remove the identifier if there are no recent attempts
        if not failed_attempts[identifier]:
            del failed_attempts[identifier]

def is_rate_limited(request: Request, username: str = None) -> Tuple[bool, int]:
    identifier = get_identifier(request, username)
    cleanup_old_attempts()
    
    # If no failed attempts, not rate limited
    if identifier not in failed_attempts:
        return False, MAX_FAILED_ATTEMPTS
    
    # Count recent failed attempts
    recent_attempts = len(failed_attempts[identifier])
    
    # If fewer than max attempts, not rate limited
    if recent_attempts < MAX_FAILED_ATTEMPTS:
        return False, MAX_FAILED_ATTEMPTS - recent_attempts
    
    # Calculate time until lockout expires
    oldest_recent_attempt = min(failed_attempts[identifier])
    lockout_expiry = oldest_recent_attempt + timedelta(minutes=LOCKOUT_PERIOD)
    seconds_remaining = max(0, int((lockout_expiry - datetime.now()).total_seconds()))
    
    # Rate limited
    return True, seconds_remaining

def check_rate_limit(request: Request, username: str = None) -> None:
    is_limited, value = is_rate_limited(request, username)
    
    if is_limited:
        # If rate limited, value is seconds remaining
        minutes_remaining = value // 60
        seconds_remaining = value % 60
        time_str = f"{minutes_remaining}m {seconds_remaining}s"
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Please try again in {time_str}."
        )
    
    # If not rate limited, value is remaining attempts
    return value

def reset_attempts(request: Request, username: str = None) -> None:
    identifier = get_identifier(request, username)
    if identifier in failed_attempts:
        del failed_attempts[identifier]