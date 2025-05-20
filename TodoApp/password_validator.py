import re
from typing import Dict, List, Tuple, Union

def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validates a password against the following criteria:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character

    Args:
        password: The password to validate

    Returns:
        A tuple containing:
        - A boolean indicating whether the password is valid
        - A string containing an error message if the password is invalid, or an empty string if it's valid
    """
    # Check minimum length
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    # Check for uppercase letters
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    # Check for lowercase letters
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    # Check for numbers
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"

    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    # All checks passed
    return True, ""

def get_password_strength_requirements() -> List[str]:
    """
    Returns a list of password strength requirements.

    Returns:
        A list of strings describing the password requirements
    """
    return [
        "At least 8 characters long",
        "Contains at least one uppercase letter",
        "Contains at least one lowercase letter",
        "Contains at least one number",
        "Contains at least one special character"
    ]