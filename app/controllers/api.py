from flask import Blueprint, jsonify, request, current_app
from flask_login import current_user
import datetime
import pytz
from app.utils.timezone_utils import convert_utc_to_local, get_user_timezone

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/format_date', methods=['GET'])
def format_date():
    """
    Format a date in the user's timezone
    
    Query parameters:
    - date: The date to format (ISO format)
    - format: The format to use (strftime format)
    """
    date_str = request.args.get('date')
    format_str = request.args.get('format', '%Y-%m-%d %H:%M:%S')
    
    if not date_str:
        return 'Invalid date', 400
    
    try:
        # Parse the date
        if date_str.isdigit():
            # Unix timestamp
            dt = datetime.datetime.fromtimestamp(float(date_str), tz=pytz.UTC)
        else:
            # ISO format
            dt = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = pytz.UTC.localize(dt)
        
        # Get the user's timezone
        user_timezone = get_user_timezone()
        
        # Convert to the user's timezone
        local_dt = convert_utc_to_local(dt, user_timezone)
        
        # Format the date
        formatted_date = local_dt.strftime(format_str)
        
        return formatted_date
    except Exception as e:
        current_app.logger.error(f"Error formatting date: {str(e)}")
        return str(e), 400

@api_bp.route('/current_time', methods=['GET'])
def current_time():
    """Get the current time in the user's timezone"""
    user_timezone = get_user_timezone()
    now_utc = datetime.datetime.now(pytz.UTC)
    now_local = convert_utc_to_local(now_utc, user_timezone)
    
    return jsonify({
        'utc': now_utc.isoformat(),
        'local': now_local.isoformat(),
        'timezone': user_timezone,
        'formatted': now_local.strftime('%Y-%m-%d %H:%M:%S')
    })
