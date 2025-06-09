import json
import datetime
import pytz
from flask_login import current_user
# Assuming timezone_utils.py and its functions are correct and available
from app.utils.timezone_utils import convert_utc_to_local, get_user_timezone

# Filter implementations

def _from_json_impl(value):
    """Convert a JSON string to a Python object"""
    if not value:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None

def _format_datetime_impl(value, date_format='%Y-%m-%d %H:%M:%S', target_timezone=None):
    """Format a datetime object in the user's timezone"""
    if value is None:
        return ""
    
    # Convert string to datetime if needed
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value)
        except ValueError:
            return value # Return original string if parsing fails
    
    if not isinstance(value, datetime.datetime): # Ensure it's a datetime object
        return "" # Or handle as an error

    # Make sure datetime is timezone-aware; assume UTC if naive
    if value.tzinfo is None:
        value = pytz.UTC.localize(value)
    
    # Determine target timezone string
    tz_str_to_use = target_timezone
    if tz_str_to_use is None: # If no specific timezone passed to filter, use user's default
        tz_str_to_use = get_user_timezone() # This function should handle g, current_user, or default to UTC

    try:
        final_pytz = pytz.timezone(tz_str_to_use)
    except pytz.UnknownTimeZoneError:
        final_pytz = pytz.UTC # Fallback to UTC if provided timezone string is invalid

    localized_dt = value.astimezone(final_pytz)
    return localized_dt.strftime(date_format)

def _format_timestamp_impl(value, date_format='%Y-%m-%d %H:%M:%S'):
    """Format a timestamp (seconds since epoch) as a datetime"""
    if value is None:
        return ""
    try:
        # Timestamps are typically UTC
        dt = datetime.datetime.fromtimestamp(float(value), tz=pytz.UTC)
        # Reuse _format_datetime_impl; it will handle user's timezone via get_user_timezone() if target_timezone is None
        return _format_datetime_impl(dt, date_format=date_format)
    except (ValueError, TypeError):
        return ""

def _timeago_impl(value):
    """Format a datetime as a relative time string (e.g., '3 hours ago')"""
    if value is None:
        return ""
    
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value)
        except ValueError:
            return value # Return original string if parsing fails

    if not isinstance(value, datetime.datetime):
        return ""

    # Make sure datetime is timezone-aware; assume UTC if naive
    if value.tzinfo is None:
        value = pytz.UTC.localize(value)
    
    user_tz_str = get_user_timezone() # Get user's timezone string (e.g., 'Asia/Jakarta', 'UTC')
    try:
        user_pytz = pytz.timezone(user_tz_str)
    except pytz.UnknownTimeZoneError:
        user_pytz = pytz.UTC # Fallback

    # Convert the input value (which is UTC or has its own tz) to user's local timezone for comparison with 'now'
    value_in_user_tz = value.astimezone(user_pytz)
    now_in_user_tz = datetime.datetime.now(user_pytz)
    
    diff = now_in_user_tz - value_in_user_tz
    seconds = diff.total_seconds()

    if seconds < 0: # Future date
        # For future dates, just format it normally using the user's timezone
        return _format_datetime_impl(value_in_user_tz, date_format='%Y-%m-%d %H:%M')

    if seconds < 60:
        return "just now"
    elif seconds < 3600: # Less than 1 hour
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    elif seconds < 86400: # Less than 1 day
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif seconds < 2592000: # Less than 30 days (approx)
        days = int(seconds / 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
    else: # Older than 30 days, show date
        return _format_datetime_impl(value_in_user_tz, date_format='%Y-%m-%d')

def register_filters(app):
    """Register custom filters directly with the app's Jinja environment"""
    app.jinja_env.filters['from_json'] = _from_json_impl
    app.jinja_env.filters['format_timestamp'] = _format_timestamp_impl
    app.jinja_env.filters['timeago'] = _timeago_impl
    app.jinja_env.filters['format_datetime'] = _format_datetime_impl
    # The context processor 'inject_now' that was here has been removed.
    # The 'inject_timezone_info' context processor in app/__init__.py is responsible
    # for providing 'user_timezone', 'timezone_display', and localized 'now' to templates.
