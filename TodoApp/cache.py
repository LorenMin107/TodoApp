"""
Cache module for the TodoApp application.

This module provides a simple in-memory caching mechanism with TTL (time-to-live)
support for caching frequently accessed database queries.
"""

import time
import threading
import logging
from typing import Any, Dict, Optional, Tuple, Callable
from functools import wraps

# Set up logging
logger = logging.getLogger(__name__)

# Cache storage
_cache: Dict[str, Tuple[Any, float]] = {}
_cache_lock = threading.RLock()

# Default TTL in seconds (5 minutes)
DEFAULT_TTL = 300


def cache_clear():
    with _cache_lock:
        _cache.clear()
    logger.debug("Cache cleared")


def cache_get(key: str) -> Optional[Any]:
    with _cache_lock:
        if key in _cache:
            value, expiry = _cache[key]
            if expiry > time.time():
                logger.debug(f"Cache hit for key: {key}")
                return value
            else:
                # Remove expired entry
                del _cache[key]
                logger.debug(f"Cache expired for key: {key}")
    
    logger.debug(f"Cache miss for key: {key}")
    return None


def cache_set(key: str, value: Any, ttl: int = DEFAULT_TTL):
    with _cache_lock:
        expiry = time.time() + ttl
        _cache[key] = (value, expiry)
    logger.debug(f"Cache set for key: {key}, TTL: {ttl}s")


def cache_delete(key: str):
    with _cache_lock:
        if key in _cache:
            del _cache[key]
            logger.debug(f"Cache deleted for key: {key}")


def cache_invalidate_pattern(pattern: str):
    with _cache_lock:
        keys_to_delete = [k for k in _cache.keys() if pattern in k]
        for key in keys_to_delete:
            del _cache[key]
    
    if keys_to_delete:
        logger.debug(f"Cache invalidated for pattern: {pattern}, {len(keys_to_delete)} keys deleted")


def cached(key_prefix: str, ttl: int = DEFAULT_TTL):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create a cache key from the function name, args, and kwargs
            key_parts = [key_prefix, func.__name__]
            
            # Add args to key
            for arg in args:
                key_parts.append(str(arg))
            
            # Add kwargs to key (sorted for consistency)
            for k, v in sorted(kwargs.items()):
                key_parts.append(f"{k}={v}")
            
            cache_key = ":".join(key_parts)
            
            # Try to get from cache
            cached_value = cache_get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Call the function and cache the result
            result = func(*args, **kwargs)
            cache_set(cache_key, result, ttl)
            return result
        
        return wrapper
    
    return decorator


def async_cached(key_prefix: str, ttl: int = DEFAULT_TTL):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Create a cache key from the function name, args, and kwargs
            key_parts = [key_prefix, func.__name__]
            
            # Add args to key
            for arg in args:
                key_parts.append(str(arg))
            
            # Add kwargs to key (sorted for consistency)
            for k, v in sorted(kwargs.items()):
                key_parts.append(f"{k}={v}")
            
            cache_key = ":".join(key_parts)
            
            # Try to get from cache
            cached_value = cache_get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Call the function and cache the result
            result = await func(*args, **kwargs)
            cache_set(cache_key, result, ttl)
            return result
        
        return wrapper
    
    return decorator


# Periodic cache cleanup
def _cleanup_cache():
    """Remove expired entries from the cache."""
    current_time = time.time()
    with _cache_lock:
        keys_to_delete = [k for k, (_, expiry) in _cache.items() if expiry <= current_time]
        for key in keys_to_delete:
            del _cache[key]
    
    if keys_to_delete:
        logger.debug(f"Cache cleanup: {len(keys_to_delete)} expired entries removed")


def start_cache_cleanup(interval: int = 60):
    def cleanup_thread():
        while True:
            time.sleep(interval)
            _cleanup_cache()
    
    thread = threading.Thread(target=cleanup_thread, daemon=True)
    thread.start()
    logger.debug(f"Cache cleanup thread started with interval: {interval}s")


# Start the cache cleanup thread when the module is imported
start_cache_cleanup()