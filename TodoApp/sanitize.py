import html
import re
from typing import Any, Dict, Optional

def sanitize_html(text: Optional[str]) -> str:
    if text is None:
        return ""
    
    # Escape HTML special characters
    return html.escape(text)

def sanitize_js(text: Optional[str]) -> str:
    if text is None:
        return ""
    
    # First escape HTML special characters
    text = html.escape(text)
    
    # Also escape JavaScript-specific characters
    text = text.replace("\\", "\\\\")  # Escape backslashes
    text = text.replace("'", "\\'")    # Escape single quotes
    text = text.replace('"', '\\"')    # Escape double quotes
    text = text.replace("\n", "\\n")   # Escape newlines
    text = text.replace("\r", "\\r")   # Escape carriage returns
    text = text.replace("\t", "\\t")   # Escape tabs
    text = text.replace("<script", "&lt;script")  # Additional protection against script tags
    
    return text

def sanitize_attribute(text: Optional[str]) -> str:
    if text is None:
        return ""
    
    # Escape HTML special characters
    text = html.escape(text)
    
    # Remove any JavaScript event handlers (on*)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    
    return text

def sanitize_url(url: Optional[str]) -> str:
    if url is None:
        return ""
    
    # Remove whitespace
    url = url.strip()
    
    # Check for JavaScript: protocol and other potentially dangerous protocols
    if re.match(r'^(javascript|data|vbscript|file):', url, re.IGNORECASE):
        return ""
    
    # For relative URLs, return them as is
    if not re.match(r'^[a-z]+:', url, re.IGNORECASE):
        return url
    
    # For absolute URLs, ensure they use http or https
    if not re.match(r'^https?:', url, re.IGNORECASE):
        return ""
    
    return url

def sanitize_todo_input(todo_data: Dict[str, Any]) -> Dict[str, Any]:
    sanitized_data = dict(todo_data)
    
    if 'title' in sanitized_data and sanitized_data['title'] is not None:
        sanitized_data['title'] = sanitize_html(sanitized_data['title'])
    
    if 'description' in sanitized_data and sanitized_data['description'] is not None:
        sanitized_data['description'] = sanitize_html(sanitized_data['description'])
    
    return sanitized_data

def sanitize_user_input(user_data: Dict[str, Any]) -> Dict[str, Any]:
    sanitized_data = dict(user_data)
    
    # Sanitize user fields that might be displayed in the UI
    for field in ['username', 'email', 'first_name', 'last_name', 'role', 'phone_number']:
        if field in sanitized_data and sanitized_data[field] is not None:
            sanitized_data[field] = sanitize_html(sanitized_data[field])
    
    return sanitized_data

def sanitize_error_message(message: Optional[str]) -> str:
    if message is None:
        return ""
    
    return sanitize_js(sanitize_html(message))