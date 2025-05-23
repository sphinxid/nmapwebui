from app import db, scheduler, celery
from app.models.task import ScanTask, ScanRun
from app.models.user import User
from app.tasks.nmap_tasks import run_nmap_scan
from datetime import datetime, timedelta
import json
import pytz
import logging
from sqlalchemy.exc import OperationalError
from app.utils.timezone_utils import convert_local_to_utc, get_user_timezone

# Set up logging
logger = logging.getLogger(__name__)

def make_timezone_aware(dt):
    """
    Make a datetime timezone-aware if it isn't already
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return pytz.UTC.localize(dt)
    return dt

def check_missed_scheduled_runs():
    """
    Check for scheduled tasks that should have run but haven't
    and create scan runs for them
    """
    try:
        logger.info("Checking for missed scheduled runs...")
        
        # Get all scheduled tasks
        scheduled_tasks = ScanTask.query.filter_by(is_scheduled=True).all()
        now_utc = datetime.now(pytz.UTC)
        
        for task in scheduled_tasks:
            try:
                # Get the job to determine the scheduled time
                job_id = f"scan_task_{task.id}"
                job = scheduler.get_job(job_id)
                
                if not job or not job.next_run_time:
                    logger.warning(f"Task {task.id} has no valid schedule, skipping check")
                    continue
                
                # Get the most recent scan run for this task
                latest_scan = ScanRun.query.filter_by(task_id=task.id).order_by(ScanRun.created_at.desc()).first()
                
                # Calculate when the task should have last run
                if task.schedule_type == 'daily':
                    # For daily tasks, check if it ran today
                    schedule_data = task.get_schedule_data()
                    hour = schedule_data.get('hour', 0)
                    minute = schedule_data.get('minute', 0)
                    
                    # Create a datetime for today's scheduled run
                    today_scheduled = now_utc.replace(hour=hour, minute=minute, second=0, microsecond=0)
                    
                    # If the scheduled time is in the future, use yesterday's time
                    if today_scheduled > now_utc:
                        today_scheduled = today_scheduled - timedelta(days=1)
                    
                    should_have_run_after = today_scheduled - timedelta(hours=1)  # Allow 1 hour leeway
                    
                elif task.schedule_type == 'weekly':
                    # For weekly tasks, check if it ran this week on the scheduled day
                    schedule_data = task.get_schedule_data()
                    day_of_week = schedule_data.get('day_of_week', 0)  # Monday is 0
                    hour = schedule_data.get('hour', 0)
                    minute = schedule_data.get('minute', 0)
                    
                    # Calculate days since the scheduled day this week
                    days_diff = now_utc.weekday() - day_of_week
                    if days_diff < 0:  # Scheduled day is later this week
                        days_diff += 7  # Check last week
                    
                    # Create a datetime for this week's scheduled run
                    this_week_scheduled = now_utc - timedelta(days=days_diff)
                    this_week_scheduled = this_week_scheduled.replace(hour=hour, minute=minute, second=0, microsecond=0)
                    
                    should_have_run_after = this_week_scheduled - timedelta(hours=1)  # Allow 1 hour leeway
                    
                elif task.schedule_type == 'monthly':
                    # For monthly tasks, check if it ran this month on the scheduled day
                    schedule_data = task.get_schedule_data()
                    day = schedule_data.get('day', 1)  # Default to 1st day of month
                    hour = schedule_data.get('hour', 0)
                    minute = schedule_data.get('minute', 0)
                    
                    # If today is before the scheduled day this month, check last month
                    if now_utc.day < day:
                        # Last month
                        if now_utc.month == 1:  # January
                            month = 12
                            year = now_utc.year - 1
                        else:
                            month = now_utc.month - 1
                            year = now_utc.year
                    else:
                        # This month
                        month = now_utc.month
                        year = now_utc.year
                    
                    # Create a datetime for this month's scheduled run
                    try:
                        this_month_scheduled = now_utc.replace(year=year, month=month, day=day, 
                                                              hour=hour, minute=minute, second=0, microsecond=0)
                    except ValueError:
                        # Handle case where day is invalid for the month (e.g., Feb 30)
                        # Use the last day of the month
                        if month == 2:
                            day = 28  # Simplified, doesn't handle leap years
                        elif month in [4, 6, 9, 11]:
                            day = 30
                        else:
                            day = 31
                        this_month_scheduled = now_utc.replace(year=year, month=month, day=day, 
                                                              hour=hour, minute=minute, second=0, microsecond=0)
                    
                    should_have_run_after = this_month_scheduled - timedelta(hours=1)  # Allow 1 hour leeway
                    
                elif task.schedule_type == 'interval':
                    # For interval tasks, check based on the last run and interval
                    schedule_data = task.get_schedule_data()
                    hours = schedule_data.get('hours', 24)  # Default to daily
                    
                    if latest_scan and latest_scan.started_at:
                        # Calculate when it should have run next after the last run
                        # Make sure started_at is timezone-aware
                        if latest_scan.started_at.tzinfo is None:
                            latest_started_at = pytz.UTC.localize(latest_scan.started_at)
                        else:
                            latest_started_at = latest_scan.started_at
                        should_have_run_after = latest_started_at + timedelta(hours=hours) - timedelta(hours=1)  # Allow 1 hour leeway
                    else:
                        # If never run, use creation time as reference
                        if task.created_at.tzinfo is None:
                            # Convert naive datetime to aware
                            task_created_at = pytz.UTC.localize(task.created_at)
                        else:
                            task_created_at = task.created_at
                        should_have_run_after = task_created_at + timedelta(hours=hours) - timedelta(hours=1)
                else:
                    # Unknown schedule type
                    logger.warning(f"Unknown schedule type {task.schedule_type} for task {task.id}, skipping check")
                    continue
                
                # Make sure both datetimes are timezone-aware for comparison
                latest_scan_time = None
                if latest_scan and latest_scan.started_at:
                    if latest_scan.started_at.tzinfo is None:
                        # Convert naive datetime to aware
                        latest_scan_time = pytz.UTC.localize(latest_scan.started_at)
                    else:
                        latest_scan_time = latest_scan.started_at
                
                # Check if the task should have run but hasn't
                if not latest_scan or (latest_scan_time and latest_scan_time < should_have_run_after):
                    logger.info(f"Task {task.id} ({task.name}) should have run at {should_have_run_after} but hasn't. Creating a scan run.")
                    
                    # Check if there's already a queued or running scan for this task
                    existing_scan = ScanRun.query.filter(
                        ScanRun.task_id == task.id,
                        ScanRun.status.in_(['queued', 'running'])
                    ).first()
                    
                    if existing_scan:
                        logger.warning(f"Task {task.id} already has a {existing_scan.status} scan (ID: {existing_scan.id}), skipping")
                        continue
                    
                    # Create a new scan run for the missed schedule
                    scan_run = ScanRun(
                        task_id=task.id,
                        status='queued',
                        created_at=datetime.now(pytz.UTC),  # Current time as creation time
                        started_at=should_have_run_after  # Use the missed time as priority
                    )
                    db.session.add(scan_run)
                    db.session.commit()
                    
                    logger.info(f"Created scan run {scan_run.id} for missed schedule of task {task.id}")
                    
                    # Queue the task for processing
                    run_nmap_scan.apply_async(args=[scan_run.id], countdown=0)
                    logger.info(f"Queued Nmap scan for run {scan_run.id} (missed schedule)")
                else:
                    logger.info(f"Task {task.id} ({task.name}) has already run after {should_have_run_after}, no action needed")
                    
            except Exception as e:
                logger.error(f"Error checking missed runs for task {task.id}: {str(e)}")
        
        return True
    except Exception as e:
        logger.error(f"Error checking missed scheduled runs: {str(e)}")
        return False

def initialize_scheduled_tasks():
    """
    Initialize all scheduled tasks from the database
    """
    try:
        # Get all scheduled tasks
        scheduled_tasks = ScanTask.query.filter_by(is_scheduled=True).all()
        
        logger.info(f"Found {len(scheduled_tasks)} scheduled tasks to initialize")
        
        for task in scheduled_tasks:
            try:
                # Check if the task is already scheduled
                job_id = f"scan_task_{task.id}"
                job = scheduler.get_job(job_id)
                
                # For interval tasks, only schedule if the job doesn't exist
                # This prevents constant rescheduling of interval tasks
                if task.schedule_type == 'interval' and job is not None:
                    logger.info(f"Task {task.id} ({task.name}) is already scheduled as an interval task, skipping")
                    continue
                
                result = schedule_task(task)
                if result:
                    logger.info(f"Successfully scheduled task {task.id}: {task.name}")
                else:
                    logger.warning(f"Failed to schedule task {task.id}: {task.name}")
            except Exception as e:
                logger.error(f"Error scheduling task {task.id}: {str(e)}")
        
        # Check for missed scheduled runs
        check_missed_scheduled_runs()
            
        return True
    except OperationalError:
        # Database might not be initialized yet
        logger.warning("Database not initialized yet, skipping scheduler initialization")
        return False
    except Exception as e:
        logger.error(f"Unexpected error initializing scheduled tasks: {str(e)}")
        return False

def schedule_task(task):
    """
    Schedule a task based on its schedule configuration
    All scheduling is done in UTC, but the task's schedule data may be in the user's timezone
    """
    if not task.is_scheduled or not task.schedule_type or not task.schedule_data:
        return False
    
    schedule_data = task.get_schedule_data()
    job_id = f"scan_task_{task.id}"
    
    # Get the user's timezone for conversion
    user = User.query.get(task.user_id)
    user_timezone = user.timezone if user else 'UTC'
    
    # Remove existing job if it exists
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    
    if task.schedule_type == 'daily':
        hour = schedule_data.get('hour', 0)
        minute = schedule_data.get('minute', 0)
        
        # Convert from user timezone to UTC for scheduling
        if user_timezone != 'UTC':
            # Create a datetime in user's timezone
            user_dt = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
            user_tz = pytz.timezone(user_timezone)
            user_dt = user_tz.localize(user_dt)
            
            # Convert to UTC
            utc_dt = user_dt.astimezone(pytz.UTC)
            hour = utc_dt.hour
            minute = utc_dt.minute
        
        scheduler.add_job(
            func=create_scheduled_scan_run,
            trigger='cron',
            hour=hour,
            minute=minute,
            id=job_id,
            args=[task.id]
        )
        
    elif task.schedule_type == 'weekly':
        day_of_week = schedule_data.get('day_of_week', 0)  # Monday is 0
        hour = schedule_data.get('hour', 0)
        minute = schedule_data.get('minute', 0)
        
        # Convert from user timezone to UTC for scheduling
        if user_timezone != 'UTC':
            # Create a datetime in user's timezone (using next occurrence of day_of_week)
            today = datetime.now()
            days_ahead = day_of_week - today.weekday()
            if days_ahead < 0:  # Target day already happened this week
                days_ahead += 7
            
            next_day = today + timedelta(days=days_ahead)
            user_dt = next_day.replace(hour=hour, minute=minute, second=0, microsecond=0)
            user_tz = pytz.timezone(user_timezone)
            user_dt = user_tz.localize(user_dt)
            
            # Convert to UTC
            utc_dt = user_dt.astimezone(pytz.UTC)
            # The day might change when converting to UTC
            day_of_week = utc_dt.weekday()
            hour = utc_dt.hour
            minute = utc_dt.minute
        
        scheduler.add_job(
            func=create_scheduled_scan_run,
            trigger='cron',
            day_of_week=day_of_week,
            hour=hour,
            minute=minute,
            id=job_id,
            args=[task.id]
        )
        
    elif task.schedule_type == 'monthly':
        day = schedule_data.get('day', 1)  # First day of month
        hour = schedule_data.get('hour', 0)
        minute = schedule_data.get('minute', 0)
        
        # Convert from user timezone to UTC for scheduling
        if user_timezone != 'UTC':
            # Create a datetime in user's timezone
            today = datetime.now()
            # Use current month's day or next month if day has passed
            if today.day > day:
                if today.month == 12:
                    next_month = today.replace(year=today.year+1, month=1, day=day)
                else:
                    next_month = today.replace(month=today.month+1, day=day)
                user_dt = next_month
            else:
                user_dt = today.replace(day=day)
            
            user_dt = user_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
            user_tz = pytz.timezone(user_timezone)
            user_dt = user_tz.localize(user_dt)
            
            # Convert to UTC
            utc_dt = user_dt.astimezone(pytz.UTC)
            # The day might change when converting to UTC
            day = utc_dt.day
            hour = utc_dt.hour
            minute = utc_dt.minute
        
        scheduler.add_job(
            func=create_scheduled_scan_run,
            trigger='cron',
            day=day,
            hour=hour,
            minute=minute,
            id=job_id,
            args=[task.id]
        )
        
    elif task.schedule_type == 'interval':
        hours = schedule_data.get('hours', 24)  # Default to daily
        
        scheduler.add_job(
            func=create_scheduled_scan_run,
            trigger='interval',
            hours=hours,
            id=job_id,
            args=[task.id]
        )
    
    return True

def unschedule_task(task_id):
    """
    Remove a scheduled task
    """
    job_id = f"scan_task_{task_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        return True
    return False

def create_scheduled_scan_run(task_id):
    """
    Create a scan run for a scheduled task and start it
    """
    try:
        from app import create_app
        app = create_app()
        scan_run_id = None
        
        with app.app_context():
            logger.info(f"Creating scheduled scan run for task {task_id}")
            
            task = ScanTask.query.get(task_id)
            if not task:
                logger.error(f"Task {task_id} not found")
                return None
            
            # Check if task is still scheduled
            if not task.is_scheduled:
                logger.warning(f"Task {task_id} is no longer scheduled, skipping run")
                return None
            
            # Check if there's already a queued or running scan for this task
            existing_scan = ScanRun.query.filter(
                ScanRun.task_id == task.id,
                ScanRun.status.in_(['queued', 'running'])
            ).first()
            
            if existing_scan:
                logger.warning(f"Task {task_id} already has a {existing_scan.status} scan (ID: {existing_scan.id}), skipping")
                return None
            
            # Get the job to determine the scheduled time
            job_id = f"scan_task_{task_id}"
            job = scheduler.get_job(job_id)
            
            # Create a new scan run
            scan_run = ScanRun(
                task_id=task.id,
                status='queued',
                created_at=datetime.now(pytz.UTC)
            )
            
            # Store the next run time in the started_at field to use for prioritization
            # This will ensure tasks are processed in order of their scheduled time
            if job and job.next_run_time:
                # Use the scheduled time as the priority timestamp
                scan_run.started_at = job.next_run_time
                logger.info(f"Setting priority time for scan run to scheduled time: {job.next_run_time}")
            else:
                # If no next run time is available, use current time
                scan_run.started_at = datetime.now(pytz.UTC)
                logger.info(f"Setting priority time for scan run to current time: {scan_run.started_at}")
            
            db.session.add(scan_run)
            db.session.commit()
            
            scan_run_id = scan_run.id
            logger.info(f"Created scan run {scan_run_id} for task {task_id} with priority time {scan_run.started_at}")
            
            # Instead of directly running the task, let the task processor handle it
            # This ensures that the max_concurrent_tasks setting is respected
            logger.info(f"Scan run {scan_run_id} created and queued. It will be processed by the task processor.")
            # We don't call run_nmap_scan directly anymore - the task processor will handle it
        
        return scan_run_id
    except Exception as e:
        logger.error(f"Error creating scheduled scan run for task {task_id}: {str(e)}")
        return None


def schedule_with_timezone(task_name, args, eta, user_timezone):
    """
    Schedule a task to run at a specific time in the user's timezone
    
    Args:
        task_name (str): The name of the task to schedule
        args (list): Arguments for the task
        eta (datetime): The time to run the task in the user's timezone
        user_timezone (str): The user's timezone
    """
    # Make sure eta is timezone-aware
    if eta.tzinfo is None:
        local_tz = pytz.timezone(user_timezone)
        eta = local_tz.localize(eta)
    
    # Convert to UTC for Celery
    eta_utc = convert_local_to_utc(eta, user_timezone)
    
    # Get the task by name
    task = celery.tasks[task_name]
    
    # Schedule the task with the UTC time
    return task.apply_async(args=args, eta=eta_utc)
