"""
Timezone utilities for the NmapWebUI application.
This module provides functions for timezone conversion and formatting.
"""
import pytz
from datetime import datetime
from flask import current_app, g
from flask_login import current_user

# List of common timezones for the timezone selection dropdown
COMMON_TIMEZONES = [
    'UTC',
    'Africa/Cairo',
    'Africa/Johannesburg',
    'Africa/Lagos',
    'America/Argentina/Buenos_Aires',
    'America/Bogota',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'America/Mexico_City',
    'America/New_York',
    'America/Sao_Paulo',
    'America/Toronto',
    'Asia/Bangkok',
    'Asia/Dubai',
    'Asia/Hong_Kong',
    'Asia/Jakarta',
    'Asia/Kolkata',
    'Asia/Manila',
    'Asia/Seoul',
    'Asia/Shanghai',
    'Asia/Singapore',
    'Asia/Tokyo',
    'Australia/Melbourne',
    'Australia/Perth',
    'Australia/Sydney',
    'Europe/Amsterdam',
    'Europe/Berlin',
    'Europe/Istanbul',
    'Europe/London',
    'Europe/Madrid',
    'Europe/Moscow',
    'Europe/Paris',
    'Europe/Rome',
    'Pacific/Auckland',
    'Pacific/Honolulu',
]

def get_user_timezone():
    """
    Get the current user's timezone or the default timezone.
    """
    try:
        if current_user and current_user.is_authenticated:
            return current_user.timezone or 'UTC'
    except Exception:
        # Handle case when current_user is not available or has no timezone
        pass
    return 'UTC'

def convert_utc_to_local(utc_dt, timezone_str=None):
    """
    Convert a UTC datetime to the user's local timezone.
    
    Args:
        utc_dt (datetime): The UTC datetime to convert
        timezone_str (str, optional): The timezone to convert to. 
                                     If None, uses the current user's timezone.
    
    Returns:
        datetime: The datetime in the specified timezone
    """
    try:
        if not utc_dt:
            return None
        
        # Ensure the datetime is timezone-aware
        if utc_dt.tzinfo is None:
            utc_dt = pytz.UTC.localize(utc_dt)
        
        # Get the target timezone
        if timezone_str is None:
            timezone_str = get_user_timezone()
        
        # Validate the timezone string
        if timezone_str not in pytz.all_timezones:
            timezone_str = 'UTC'
        
        # Convert to the target timezone
        target_tz = pytz.timezone(timezone_str)
        return utc_dt.astimezone(target_tz)
    except Exception as e:
        # Log the error and return the original datetime
        print(f"Error converting UTC to local time: {str(e)}")
        return utc_dt

def convert_local_to_utc(local_dt, timezone_str=None):
    """
    Convert a local datetime to UTC.
    
    Args:
        local_dt (datetime): The local datetime to convert
        timezone_str (str, optional): The timezone of the local datetime.
                                     If None, uses the current user's timezone.
    
    Returns:
        datetime: The datetime in UTC
    """
    if not local_dt:
        return None
    
    # Get the source timezone
    if timezone_str is None:
        timezone_str = get_user_timezone()
    
    # Make the datetime timezone-aware if it isn't already
    source_tz = pytz.timezone(timezone_str)
    if local_dt.tzinfo is None:
        local_dt = source_tz.localize(local_dt)
    
    # Convert to UTC
    return local_dt.astimezone(pytz.UTC)

def format_datetime(dt, format_str='%Y-%m-%d %H:%M:%S', timezone_str=None):
    """
    Format a datetime in the user's timezone.
    
    Args:
        dt (datetime): The datetime to format (assumed to be in UTC if no tzinfo)
        format_str (str): The format string to use
        timezone_str (str, optional): The timezone to use for display.
                                     If None, uses the current user's timezone.
    
    Returns:
        str: The formatted datetime string
    """
    try:
        if not dt:
            return ''
        
        # Handle string datetime input
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except ValueError:
                return dt
        
        # Convert to the user's timezone
        local_dt = convert_utc_to_local(dt, timezone_str)
        
        # Format the datetime
        return local_dt.strftime(format_str)
    except Exception as e:
        # Log the error and return a fallback string
        print(f"Error formatting datetime: {str(e)}")
        if isinstance(dt, datetime):
            try:
                return dt.isoformat()
            except:
                pass
        return str(dt) if dt else ''

def get_current_time_in_user_timezone(timezone_str=None):
    """
    Get the current time in the user's timezone.
    
    Args:
        timezone_str (str, optional): The timezone to use.
                                     If None, uses the current user's timezone.
    
    Returns:
        datetime: The current time in the specified timezone
    """
    # Get the current UTC time
    now_utc = datetime.now(pytz.UTC)
    
    # Convert to the user's timezone
    return convert_utc_to_local(now_utc, timezone_str)

def get_timezone_display_name(timezone_str):
    """
    Get a user-friendly display name for a timezone.
    
    Args:
        timezone_str (str): The timezone string (e.g., 'America/New_York')
    
    Returns:
        str: A user-friendly display name (e.g., 'America/New_York (UTC-05:00)')
    """
    try:
        tz = pytz.timezone(timezone_str)
        offset = datetime.now(tz).strftime('%z')
        hours = offset[0:3]
        minutes = offset[3:5]
        offset_str = f"UTC{hours}:{minutes}"
        return f"{timezone_str} ({offset_str})"
    except:
        return timezone_str
