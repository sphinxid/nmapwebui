from app import create_app, celery
import os
import pytz
from datetime import datetime
from app.utils.timezone_utils import convert_local_to_utc

# Create a Flask application context
app = create_app()

# Set the broker URL explicitly
celery.conf.update(
    broker_url=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    result_backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    imports=['app.tasks.nmap_tasks'],
    enable_utc=True,  # Ensure Celery uses UTC for all timestamps
    timezone='UTC'    # Default timezone for Celery
)

# This ensures that the Celery worker loads the tasks
from app.tasks.nmap_tasks import run_nmap_scan

# Add a task to handle timezone-aware scheduling
@celery.task(name='app.tasks.schedule_in_timezone')
def schedule_in_timezone(task_name, args=None, kwargs=None, eta=None, user_timezone=None):
    """
    Schedule a task to run at a specific time in the user's timezone.
    
    Args:
        task_name (str): The name of the task to schedule
        args (list): Positional arguments for the task
        kwargs (dict): Keyword arguments for the task
        eta (datetime): The time to run the task in the user's timezone
        user_timezone (str): The user's timezone
    
    Returns:
        AsyncResult: The result of the scheduled task
    """
    args = args or []
    kwargs = kwargs or {}
    
    # Convert the ETA from user's timezone to UTC if needed
    if eta and user_timezone:
        # Make sure eta is timezone-aware
        if eta.tzinfo is None:
            local_tz = pytz.timezone(user_timezone)
            eta = local_tz.localize(eta)
        
        # Convert to UTC for Celery
        eta_utc = convert_local_to_utc(eta, user_timezone)
    else:
        eta_utc = eta
    
    # Get the task by name
    task = celery.tasks[task_name]
    
    # Schedule the task with the UTC time
    return task.apply_async(args=args, kwargs=kwargs, eta=eta_utc)
