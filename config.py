import os
from datetime import timedelta
from dotenv import load_dotenv

class Config:

    load_dotenv()
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

    NMAP_WORKER_POOL_SIZE = int(os.environ.get('NMAP_WORKER_POOL_SIZE', 2))
    
    # SQLAlchemy configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:////home/firman/coding/python/nmapwebui/instance/app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # Nmap configuration
    NMAP_REPORTS_DIR = os.environ.get('NMAP_REPORTS_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'reports'))
    
    # Ensure reports directory exists
    os.makedirs(NMAP_REPORTS_DIR, exist_ok=True)
    
    # Predefined Nmap scan profiles
    NMAP_SCAN_PROFILES = {
        'quick_scan': '-T4 -F',
        'intense_scan': '-T4 -A -v',
        'intense_scan_Pn': '-T4 -A -v -Pn',
        'ping_scan': '-sn',
        'port_scan': '-p 1-1000',
        'service_scan': '-sV',
        'os_detection': '-O',
        'comprehensive': '-T4 -A -v -p- -Pn'
    }
    
    # APScheduler configuration
    SCHEDULER_API_ENABLED = True
    SCHEDULER_TIMEZONE = 'UTC'
    
    # Timezone configuration
    DEFAULT_TIMEZONE = 'UTC'
    TIMEZONE_DISPLAY_FORMAT = '%Y-%m-%d %H:%M:%S %Z'
    
    # Available timezones (can be overridden in instance config)
    # This is a subset of common timezones for the dropdown
    AVAILABLE_TIMEZONES = [
        'UTC',
        'Africa/Cairo',
        'Africa/Johannesburg',
        'America/Chicago',
        'America/Los_Angeles',
        'America/New_York',
        'America/Sao_Paulo',
        'Asia/Bangkok',
        'Asia/Dubai',
        'Asia/Hong_Kong',
        'Asia/Jakarta',
        'Asia/Kolkata',
        'Asia/Seoul',
        'Asia/Shanghai',
        'Asia/Singapore',
        'Asia/Tokyo',
        'Australia/Melbourne',
        'Australia/Sydney',
        'Europe/Amsterdam',
        'Europe/Berlin',
        'Europe/London',
        'Europe/Madrid',
        'Europe/Moscow',
        'Europe/Paris',
        'Europe/Rome',
        'Pacific/Auckland',
        'Pacific/Honolulu',
    ]
