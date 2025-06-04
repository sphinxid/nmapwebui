from app import db, scheduler, celery
from app.models.task import ScanTask, ScanRun
from app.models.user import User
from app.tasks.nmap_tasks import run_nmap_scan
from datetime import datetime, timedelta
import json
import pytz
import logging
import calendar
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

def get_all_scheduled_tasks_info():
    """Get information about all scheduled tasks for display"""
    try:
        logger.info(f"Current UTC time: {datetime.now(pytz.UTC)}")
        logger.info("All scheduled tasks and their next run times:")

        # Get all scheduled tasks
        scheduled_tasks = ScanTask.query.filter_by(is_scheduled=True).all()

        for task in scheduled_tasks:
            job_id = f"scan_task_{task.id}"
            job = scheduler.get_job(job_id)

            next_run = "Not scheduled"
            if job and job.next_run_time:
                next_run = job.next_run_time

            logger.info(f"  Task ID: {task.id}, Name: {task.name}, Next run: {next_run}")

        return True
    except Exception as e:
        logger.error(f"Error getting scheduled tasks info: {str(e)}")
        return False

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

                # For interval tasks, also check the one-time setup job and metadata job
                if task.schedule_type == 'interval':
                    one_time_job_id = f"one_time_setup_{job_id}"
                    one_time_job = scheduler.get_job(one_time_job_id)
                    meta_job_id = f"meta_{job_id}"
                    meta_job = scheduler.get_job(meta_job_id)

                    # Use the metadata job if it exists
                    if meta_job and meta_job.next_run_time:
                        job = meta_job
                    # Use the one-time job if it exists
                    elif one_time_job and one_time_job.next_run_time:
                        job = one_time_job

                if not job or not job.next_run_time:
                    logger.warning(f"Task {task.id} has no valid schedule, skipping check")
                    continue

                # Get the most recent scan run for this task
                latest_scan = ScanRun.query.filter_by(task_id=task.id).order_by(ScanRun.created_at.desc()).first()

                # Calculate when the task should have last run
                if task.schedule_type == 'daily':
                    schedule_data = task.get_schedule_data()
                    user_hour = schedule_data.get('hour', 0)
                    user_minute = schedule_data.get('minute', 0)

                    # Get the user's timezone
                    user = User.query.get(task.user_id)
                    user_timezone_str = user.timezone if user and user.timezone else 'UTC'
                    user_tz = pytz.timezone(user_timezone_str)

                    # Create a datetime for today's scheduled run in user's timezone, then convert to UTC
                    # Use a naive datetime first, then localize, then convert
                    naive_today_user_time = datetime(now_utc.year, now_utc.month, now_utc.day, user_hour, user_minute, 0)
                    localized_user_time_today = user_tz.localize(naive_today_user_time, is_dst=None)
                    utc_scheduled_today = localized_user_time_today.astimezone(pytz.UTC)

                    # If the calculated UTC scheduled time for today is in the future relative to now_utc,
                    # it means today's run hasn't occurred yet (or is happening now).
                    # So, we should check against yesterday's scheduled time.
                    if utc_scheduled_today > now_utc:
                        naive_yesterday_user_time = datetime(now_utc.year, now_utc.month, now_utc.day, user_hour, user_minute, 0) - timedelta(days=1)
                        localized_user_time_yesterday = user_tz.localize(naive_yesterday_user_time, is_dst=None)
                        utc_reference_schedule_time = localized_user_time_yesterday.astimezone(pytz.UTC)
                    else:
                        utc_reference_schedule_time = utc_scheduled_today

                    should_have_run_after = utc_reference_schedule_time - timedelta(hours=1)  # Allow 1 hour leeway
                    logger.debug(f"Task {task.id} (Daily): User schedule {user_hour:02d}:{user_minute:02d} {user_timezone_str}. Ref UTC schedule for check: {utc_reference_schedule_time}. Should have run after: {should_have_run_after}")

                elif task.schedule_type == 'weekly':
                    schedule_data = task.get_schedule_data()
                    user_day_of_week = schedule_data.get('day_of_week', 0)  # Monday is 0
                    user_hour = schedule_data.get('hour', 0)
                    user_minute = schedule_data.get('minute', 0)

                    user = User.query.get(task.user_id)
                    user_timezone_str = user.timezone if user and user.timezone else 'UTC'
                    user_tz = pytz.timezone(user_timezone_str)

                    # Determine the date of the last target weekday in UTC
                    current_utc_weekday = now_utc.weekday()
                    days_ago = current_utc_weekday - user_day_of_week
                    if days_ago < 0:
                        days_ago += 7
                    target_date_on_or_before_now_utc = now_utc.date() - timedelta(days=days_ago)

                    # Create naive datetime in user's local time for that target date
                    naive_user_time_on_target_date = datetime(
                        target_date_on_or_before_now_utc.year,
                        target_date_on_or_before_now_utc.month,
                        target_date_on_or_before_now_utc.day,
                        user_hour, user_minute, 0
                    )
                    localized_user_time = user_tz.localize(naive_user_time_on_target_date, is_dst=None)
                    utc_reference_schedule_time = localized_user_time.astimezone(pytz.UTC)

                    if utc_reference_schedule_time > now_utc:
                        # The calculated UTC time is in the future, so check the previous week's slot
                        target_date_prev_week_utc = target_date_on_or_before_now_utc - timedelta(days=7)
                        naive_user_time_prev_week = datetime(
                            target_date_prev_week_utc.year,
                            target_date_prev_week_utc.month,
                            target_date_prev_week_utc.day,
                            user_hour, user_minute, 0
                        )
                        localized_user_time_prev_week = user_tz.localize(naive_user_time_prev_week, is_dst=None)
                        utc_reference_schedule_time = localized_user_time_prev_week.astimezone(pytz.UTC)

                    should_have_run_after = utc_reference_schedule_time - timedelta(hours=1)
                    logger.debug(f"Task {task.id} (Weekly): User DoW:{user_day_of_week} {user_hour:02d}:{user_minute:02d} {user_timezone_str}. Ref UTC: {utc_reference_schedule_time}. Should run after: {should_have_run_after}")

                elif task.schedule_type == 'monthly':
                    schedule_data = task.get_schedule_data()
                    user_day_of_month = schedule_data.get('day', 1)
                    user_hour = schedule_data.get('hour', 0)
                    user_minute = schedule_data.get('minute', 0)

                    user = User.query.get(task.user_id)
                    user_timezone_str = user.timezone if user and user.timezone else 'UTC'
                    user_tz = pytz.timezone(user_timezone_str)

                    ref_date_utc = now_utc.date()
                    current_year, current_month = ref_date_utc.year, ref_date_utc.month

                    # Attempt to create naive user datetime for the user's day in the current month
                    try:
                        _, last_day_current_month = calendar.monthrange(current_year, current_month)
                        actual_day_current_month = min(user_day_of_month, last_day_current_month)
                        naive_user_time_current_month = datetime(
                            current_year, current_month, actual_day_current_month,
                            user_hour, user_minute, 0
                        )
                    except ValueError: # Should be caught by min with last_day_current_month
                        logger.error(f"Task {task.id} (Monthly): Error creating date for current month {current_year}-{current_month}-{user_day_of_month}. Skipping.")
                        continue

                    localized_user_time_current_month = user_tz.localize(naive_user_time_current_month, is_dst=None)
                    utc_ref_current_month = localized_user_time_current_month.astimezone(pytz.UTC)

                    if utc_ref_current_month > now_utc:
                        # Scheduled time for this month (in UTC) is future; check last month.
                        last_month_year = current_year if current_month > 1 else current_year - 1
                        last_month = current_month - 1 if current_month > 1 else 12

                        try:
                            _, last_day_last_month = calendar.monthrange(last_month_year, last_month)
                            actual_day_last_month = min(user_day_of_month, last_day_last_month)
                            naive_user_time_last_month = datetime(
                                last_month_year, last_month, actual_day_last_month,
                                user_hour, user_minute, 0
                            )
                        except ValueError:
                            logger.error(f"Task {task.id} (Monthly): Error creating date for last month {last_month_year}-{last_month}-{user_day_of_month}. Skipping.")
                            continue

                        localized_user_time_last_month = user_tz.localize(naive_user_time_last_month, is_dst=None)
                        utc_reference_schedule_time = localized_user_time_last_month.astimezone(pytz.UTC)
                    else:
                        utc_reference_schedule_time = utc_ref_current_month

                    should_have_run_after = utc_reference_schedule_time - timedelta(hours=1)
                    logger.debug(f"Task {task.id} (Monthly): User Day:{user_day_of_month} {user_hour:02d}:{user_minute:02d} {user_timezone_str}. Ref UTC: {utc_reference_schedule_time}. Should run after: {should_have_run_after}")

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
                    # Pass the task.id as the second argument (scan_task_id_for_lock)
                    run_nmap_scan.apply_async(args=[scan_run.id, task.id], countdown=0)
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

                # If job exists, the task is already scheduled
                if job is not None:
                    logger.info(f"Task {task.id} ({task.name}) is already scheduled, skipping")
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
    """
    if not task.is_scheduled or not task.schedule_type or not task.schedule_data:
        return False

    job_id = f"scan_task_{task.id}"
    schedule_data = task.get_schedule_data()

    # Get the user's timezone
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
            # Create a datetime in user's timezone using a fixed reference date
            # Using a fixed date (today) ensures consistent conversion
            today_utc = datetime.now(pytz.UTC)
            user_tz = pytz.timezone(user_timezone)

            # Create a timezone-aware datetime in user's timezone
            user_dt = user_tz.localize(
                datetime(today_utc.year, today_utc.month, today_utc.day, hour, minute, 0)
            )

            # Convert to UTC
            utc_dt = user_dt.astimezone(pytz.UTC)
            hour = utc_dt.hour
            minute = utc_dt.minute

            logger.info(f"Converted daily schedule from {user_timezone} {hour}:{minute} to UTC {utc_dt.hour}:{utc_dt.minute}")

        scheduler.add_job(
            func=create_scheduled_scan_run,
            trigger='cron',
            hour=hour,
            minute=minute,
            id=job_id,
            args=[task.id],
            misfire_grace_time=3600  # Allow 1 hour for misfires
        )

    elif task.schedule_type == 'weekly':
        day_of_week = schedule_data.get('day_of_week', 0)  # Monday is 0
        hour = schedule_data.get('hour', 0)
        minute = schedule_data.get('minute', 0)

        # Convert from user timezone to UTC for scheduling
        if user_timezone != 'UTC':
            # Find the next occurrence of the specified day of week
            today_utc = datetime.now(pytz.UTC)
            days_ahead = day_of_week - today_utc.weekday()
            if days_ahead < 0:  # Target day already happened this week
                days_ahead += 7

            next_day = today_utc + timedelta(days=days_ahead)
            user_tz = pytz.timezone(user_timezone)

            # Create a timezone-aware datetime in user's timezone
            user_dt = user_tz.localize(
                datetime(next_day.year, next_day.month, next_day.day, hour, minute, 0)
            )

            # Convert to UTC
            utc_dt = user_dt.astimezone(pytz.UTC)
            # The day might change when converting to UTC
            day_of_week = utc_dt.weekday()
            hour = utc_dt.hour
            minute = utc_dt.minute

            logger.info(f"Converted weekly schedule from {user_timezone} day {day_of_week}, {hour}:{minute} to UTC day {utc_dt.weekday()}, {utc_dt.hour}:{utc_dt.minute}")

        scheduler.add_job(
            func=create_scheduled_scan_run,
            trigger='cron',
            day_of_week=day_of_week,
            hour=hour,
            minute=minute,
            id=job_id,
            args=[task.id],
            misfire_grace_time=3600  # Allow 1 hour for misfires
        )

    elif task.schedule_type == 'monthly':
        day = schedule_data.get('day', 1)  # First day of month
        hour = schedule_data.get('hour', 0)
        minute = schedule_data.get('minute', 0)

        # Convert from user timezone to UTC for scheduling
        if user_timezone != 'UTC':
            # Use the next occurrence of the specified day in the month
            today_utc = datetime.now(pytz.UTC)

            # Determine the target month
            if today_utc.day > day:  # If the day has passed in the current month
                if today_utc.month == 12:
                    target_year = today_utc.year + 1
                    target_month = 1
                else:
                    target_year = today_utc.year
                    target_month = today_utc.month + 1
            else:
                target_year = today_utc.year
                target_month = today_utc.month

            user_tz = pytz.timezone(user_timezone)

            # Create a timezone-aware datetime in user's timezone
            user_dt = user_tz.localize(
                datetime(target_year, target_month, day, hour, minute, 0)
            )

            # Convert to UTC
            utc_dt = user_dt.astimezone(pytz.UTC)
            # The day might change when converting to UTC
            day = utc_dt.day
            hour = utc_dt.hour
            minute = utc_dt.minute
            month = utc_dt.month  # The month might also change

            logger.info(f"Converted monthly schedule from {user_timezone} day {day}, {hour}:{minute} to UTC day {utc_dt.day}, {utc_dt.hour}:{utc_dt.minute}")

            # If the day changes when converting to UTC, we need to use a different approach
            # Use day='last' if the original day was the last day of the month
            days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            if day == days_in_month[target_month]:  # Last day of the month
                scheduler.add_job(
                    func=create_scheduled_scan_run,
                    trigger='cron',
                    day='last',  # Last day of the month
                    hour=hour,
                    minute=minute,
                    id=job_id,
                    args=[task.id],
                    misfire_grace_time=3600  # Allow 1 hour for misfires
                )
                return True

        scheduler.add_job(
            func=create_scheduled_scan_run,
            trigger='cron',
            day=day,
            hour=hour,
            minute=minute,
            id=job_id,
            args=[task.id],
            misfire_grace_time=3600  # Allow 1 hour for misfires
        )

    elif task.schedule_type == 'interval':
        hours = schedule_data.get('hours', 24)  # Default to daily

        # Calculate the first run time to be 'interval' from now (in UTC)
        now_utc = datetime.now(pytz.UTC)
        start_date_utc = now_utc + timedelta(hours=hours)

        scheduler.add_job(
            func=create_scheduled_scan_run,
            trigger='interval',
            hours=hours,
            id=job_id,
            args=[task.id],
            start_date=start_date_utc,  # Set the explicit start date
            misfire_grace_time=3600  # Allow 1 hour for misfires
        )

        logger.info(f"Interval task {job_id} scheduled to start at {start_date_utc} and repeat every {hours} hours")


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

    Args:
        task_id: The ID of the task to run
    """
    try:
        from app import create_app
        app = create_app()
        scan_run_id = None

        with app.app_context():
            logger.info(f"Creating scheduled scan run for task {task_id}")

            # Always execute the task
            pass

            # For SQLite, we'll use a different approach to prevent race conditions
            # Instead of row-level locking, we'll use a unique constraint check

            # First, get the task without locking
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

            # Check if this task has run recently (for interval tasks)
            # This helps prevent multiple runs within the same interval period
            if task.schedule_type == 'interval':
                # Get the most recent completed scan run
                recent_scan = ScanRun.query.filter(
                    ScanRun.task_id == task.id,
                    ScanRun.status == 'completed'
                ).order_by(ScanRun.completed_at.desc()).first()

                if recent_scan and recent_scan.completed_at:
                    # Get the interval hours from schedule data
                    schedule_data = task.get_schedule_data()
                    interval_hours = schedule_data.get('hours', 24)

                    # Calculate the minimum time between runs
                    min_time_between_runs = timedelta(hours=interval_hours * 0.9)  # 90% of the interval
                    now = datetime.now(pytz.UTC)

                    # Make sure completed_at is timezone-aware
                    completed_at = recent_scan.completed_at
                    if completed_at.tzinfo is None:
                        # If it's naive, assume it's in UTC
                        completed_at = pytz.UTC.localize(completed_at)

                    time_since_last_run = now - completed_at

                    if time_since_last_run < min_time_between_runs:
                        logger.warning(f"Task {task_id} ran too recently ({time_since_last_run} ago), skipping this run")
                        return None

            # Create a new scan run with a unique constraint on task_id and status
            # This will help prevent duplicate runs
            now = datetime.now(pytz.UTC)

            # Create a unique identifier for this scheduled run
            # This helps prevent duplicate runs even with SQLite's limited locking
            run_identifier = f"{task.id}_{now.strftime('%Y%m%d%H%M%S')}_{id(task)}"

            scan_run = ScanRun(
                task_id=task.id,
                status='queued',
                created_at=now
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

            # Try to add and commit in a try block to catch any unique constraint violations
            try:
                db.session.add(scan_run)
                db.session.commit()

                scan_run_id = scan_run.id
                logger.info(f"Created scan run {scan_run_id} for task {task_id} with priority time {scan_run.started_at}")

                # Instead of directly running the task, let the task processor handle it
                # This ensures that the max_concurrent_tasks setting is respected
                logger.info(f"Scan run {scan_run_id} created and queued. It will be processed by the task processor.")

                return scan_run_id
            except OperationalError as oe:
                if 'UNIQUE constraint failed' in str(oe):
                    logger.warning(f"Task {task_id} already has a queued or running scan, skipping")
                    db.session.rollback()
                    return None
                else:
                    logger.warning(f"Database error while processing task {task_id}: {str(oe)}")
                    db.session.rollback()
                    return None

        return scan_run_id
    except Exception as e:
        logger.error(f"Error creating scheduled scan run for task {task_id}: {str(e)}")
        if 'db' in locals() and db.session.is_active:
            db.session.rollback()
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
