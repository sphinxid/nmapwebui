import json
from flask import Blueprint, current_app, g
from flask_login import current_user
import datetime
import pytz
from app.utils.timezone_utils import convert_utc_to_local, get_user_timezone

filters_bp = Blueprint('filters', __name__)

@filters_bp.app_template_filter('from_json')
def from_json(value):
    """Convert a JSON string to a Python object"""
    if not value:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None

@filters_bp.app_template_filter('format_timestamp')
def format_timestamp(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a timestamp (seconds since epoch) as a datetime"""
    if value is None:
        return ""
    
    try:
        dt = datetime.datetime.fromtimestamp(float(value), tz=pytz.UTC)
        return format_datetime(dt, format)
    except (ValueError, TypeError):
        return ""

@filters_bp.app_template_filter('timeago')
def timeago(value):
    """Format a datetime as a relative time string (e.g., '3 hours ago')"""
    if value is None:
        return ""
    
    # Convert string to datetime if needed
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value)
        except ValueError:
            return value
    
    # Make sure datetime is timezone-aware
    if value.tzinfo is None:
        # Assume UTC for naive datetimes
        value = pytz.UTC.localize(value)
    
    # Convert to user's timezone
    local_dt = convert_utc_to_local(value)
    
    # Get current time in user's timezone
    now = datetime.datetime.now(pytz.timezone(get_user_timezone()))
    
    # Calculate the time difference
    diff = now - local_dt
    
    # Format the relative time
    seconds = diff.total_seconds()
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
    else:
        return local_dt.strftime('%Y-%m-%d %H:%M:%S')

@filters_bp.app_template_filter('format_datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S', timezone=None):
    """Format a datetime object in the user's timezone"""
    if value is None:
        return ""
        
    # Convert string to datetime if needed
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value)
        except ValueError:
            return value
    
    # Make sure datetime is timezone-aware
    if value.tzinfo is None:
        # Assume UTC for naive datetimes
        value = pytz.UTC.localize(value)
    
    # Convert to user's timezone if not specified
    if timezone is None:
        timezone = get_user_timezone()
    
    # Convert to the target timezone
    local_dt = convert_utc_to_local(value, timezone)
    
    # Format the datetime
    return local_dt.strftime(format)

def register_filters(app):
    """Register custom filters with the app"""
    app.register_blueprint(filters_bp)
    
    # Add context processor for current date/time
    @app.context_processor
    def inject_now():
        # Get the user's timezone
        tz = 'UTC'
        try:
            if current_user.is_authenticated:
                tz = current_user.timezone
        except Exception:
            # Handle case when current_user is not available
            pass
        
        # Get current time in UTC and user's timezone
        now_utc = datetime.datetime.now(pytz.UTC)
        now_local = convert_utc_to_local(now_utc, tz)
        
        # Get timezone display name
        timezone_offset = now_local.strftime('%z')
        timezone_display = f"{tz} (UTC{timezone_offset})"
        
        return {
            'now_utc': now_utc,
            'now': now_local,
            'user_timezone': tz,
            'timezone_display': timezone_display
        }
