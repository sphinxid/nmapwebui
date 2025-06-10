from flask import current_app, g
from app import _current_flask_app
from app import db  # Scheduler will be imported locally in functions
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
    from app import scheduler
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
    from app import scheduler # Keep local import for scheduler to avoid circularity if scheduler itself needs app context early
    """
    Check for scheduled tasks that should have run but haven't
    and create scan runs for them
    """
    if _current_flask_app is None:
        logger.error("CRITICAL: Flask app instance (_current_flask_app) is None. Cannot create app context for check_missed_scheduled_runs.")
        return # Or raise an exception

    with _current_flask_app.app_context():
        try:
            logger.info(f"--- Starting check_missed_scheduled_runs at {datetime.now(pytz.UTC)} ---")

            # Get all scheduled tasks
            scheduled_tasks = ScanTask.query.filter_by(is_scheduled=True).all() # Only check enabled tasks
            now_utc = datetime.now(pytz.UTC)
            logger.info(f"Current UTC time for check: {now_utc}")

            if not scheduled_tasks:
                logger.info("No active scheduled tasks found to check for missed runs.")
                return

            logger.info(f"Found {len(scheduled_tasks)} active scheduled tasks to evaluate.")

            for task in scheduled_tasks:
                logger.info(f"Evaluating task ID: {task.id}, Name: {task.name}, Type: {task.schedule_type}")
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
                    utc_reference_schedule_time = None # Initialize before specific type logic

                    if task.schedule_type == 'daily':
                        schedule_data = task.get_schedule_data()
                        user_hour = schedule_data.get('hour', 0)
                        user_minute = schedule_data.get('minute', 0)

                        user = User.query.get(task.user_id)
                        user_timezone_str = user.timezone if user and user.timezone else 'UTC'
                        user_tz = pytz.timezone(user_timezone_str)
                        logger.debug(f"[Task {task.id}] Daily: User's raw schedule: Hour={user_hour}, Minute={user_minute}, Timezone='{user_timezone_str}'.")

                        naive_today_user_time = datetime(now_utc.year, now_utc.month, now_utc.day, user_hour, user_minute, 0)
                        localized_user_time_today = user_tz.localize(naive_today_user_time, is_dst=None)
                        utc_scheduled_today = localized_user_time_today.astimezone(pytz.UTC)
                        logger.debug(f"[Task {task.id}] Calculated UTC for today's schedule ({user_hour:02d}:{user_minute:02d} {user_timezone_str}): {utc_scheduled_today}")

                        if utc_scheduled_today > now_utc:
                            naive_yesterday_user_time = naive_today_user_time - timedelta(days=1)
                            localized_user_time_yesterday = user_tz.localize(naive_yesterday_user_time, is_dst=None)
                            utc_reference_schedule_time = localized_user_time_yesterday.astimezone(pytz.UTC)
                            logger.debug(f"[Task {task.id}] Today's schedule {utc_scheduled_today} is in the future. Using yesterday's ({utc_reference_schedule_time}) as reference for missed run.")
                        else:
                            utc_reference_schedule_time = utc_scheduled_today
                            logger.debug(f"[Task {task.id}] Today's schedule {utc_scheduled_today} is in the past or now. Using it as reference for missed run.")

                    elif task.schedule_type == 'weekly':
                        schedule_data = task.get_schedule_data()
                        user_day_of_week = schedule_data.get('day_of_week', 0)
                        user_hour = schedule_data.get('hour', 0)
                        user_minute = schedule_data.get('minute', 0)

                        user = User.query.get(task.user_id)
                        user_timezone_str = user.timezone if user and user.timezone else 'UTC'
                        user_tz = pytz.timezone(user_timezone_str)

                        current_utc_weekday = now_utc.weekday()
                        days_ago = current_utc_weekday - user_day_of_week
                        if days_ago < 0:
                            days_ago += 7
                        target_date_on_or_before_now_utc = now_utc.date() - timedelta(days=days_ago)

                        naive_user_time_on_target_date = datetime(
                            target_date_on_or_before_now_utc.year, target_date_on_or_before_now_utc.month, target_date_on_or_before_now_utc.day,
                            user_hour, user_minute, 0
                        )
                        localized_user_time = user_tz.localize(naive_user_time_on_target_date, is_dst=None)
                        utc_reference_schedule_time = localized_user_time.astimezone(pytz.UTC)

                        if utc_reference_schedule_time > now_utc:
                            target_date_prev_week_utc = target_date_on_or_before_now_utc - timedelta(days=7)
                            naive_user_time_prev_week = datetime(
                                target_date_prev_week_utc.year, target_date_prev_week_utc.month, target_date_prev_week_utc.day,
                                user_hour, user_minute, 0
                            )
                            localized_user_time_prev_week = user_tz.localize(naive_user_time_prev_week, is_dst=None)
                            utc_reference_schedule_time = localized_user_time_prev_week.astimezone(pytz.UTC)
                        logger.debug(f"Task {task.id} (Weekly): User DoW:{user_day_of_week} {user_hour:02d}:{user_minute:02d} {user_timezone_str}. Ref UTC: {utc_reference_schedule_time}.")

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

                        try:
                            _, last_day_current_month = calendar.monthrange(current_year, current_month)
                            actual_day_current_month = min(user_day_of_month, last_day_current_month)
                            naive_user_time_current_month = datetime(
                                current_year, current_month, actual_day_current_month,
                                user_hour, user_minute, 0
                            )
                        except ValueError:
                            logger.error(f"Task {task.id} (Monthly): Error creating date for current month {current_year}-{current_month}-{user_day_of_month}. Skipping.")
                            continue

                        localized_user_time_current_month = user_tz.localize(naive_user_time_current_month, is_dst=None)
                        utc_ref_current_month = localized_user_time_current_month.astimezone(pytz.UTC)

                        if utc_ref_current_month > now_utc:
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
                        logger.debug(f"Task {task.id} (Monthly): User Day:{user_day_of_month} {user_hour:02d}:{user_minute:02d} {user_timezone_str}. Ref UTC: {utc_reference_schedule_time}.")

                    elif task.schedule_type == 'interval':
                        utc_reference_schedule_time = job.next_run_time if job.next_run_time else now_utc # Best guess for reference
                        logger.debug(f"Task {task.id} (Interval): Ref UTC from job.next_run_time: {utc_reference_schedule_time}.")

                    else:
                        logger.warning(f"Task {task.id} has unknown schedule type '{task.schedule_type}'. Skipping.")
                        continue
                    
                    if utc_reference_schedule_time is None: # Should be set by one of the branches above
                        logger.error(f"Task {task.id}: utc_reference_schedule_time was not set. Skipping.")
                        continue

                    last_run_time_utc = None
                    if latest_scan and latest_scan.created_at:
                        last_run_time_utc = make_timezone_aware(latest_scan.created_at)
                    
                    logger.debug(f"[Task {task.id}] Last run (UTC): {last_run_time_utc}. Reference schedule time (UTC): {utc_reference_schedule_time}")

                    if task.schedule_type == 'interval':
                        if job.next_run_time and job.next_run_time < now_utc:
                            logger.info(f"[Task {task.id}] INTERVAL MISSED RUN DETECTED. Job next_run_time: {job.next_run_time} < Current time: {now_utc}. Queuing new scan run.")
                            create_scheduled_scan_run(task.id)
                        else:
                            logger.info(f"[Task {task.id}] Interval task appears to be on schedule. Next run: {job.next_run_time}. Current: {now_utc}.")
                    elif last_run_time_utc is None or last_run_time_utc < utc_reference_schedule_time:
                        max_age_for_missed_run = timedelta(days=2)
                        if task.schedule_type == 'weekly': max_age_for_missed_run = timedelta(days=8)
                        if task.schedule_type == 'monthly': max_age_for_missed_run = timedelta(days=32)

                        if now_utc - utc_reference_schedule_time < max_age_for_missed_run:
                            logger.info(f"[Task {task.id}] MISSED RUN DETECTED. Last run: {last_run_time_utc}, Expected around: {utc_reference_schedule_time}. Queuing new scan run.")
                            create_scheduled_scan_run(task.id)
                        else:
                            logger.warning(f"[Task {task.id}] Missed run detected (Expected around: {utc_reference_schedule_time}), but it's too old ({now_utc - utc_reference_schedule_time} > {max_age_for_missed_run}). Skipping.")
                    else:
                        logger.info(f"[Task {task.id}] Task appears to have run as scheduled or more recently. Last run: {last_run_time_utc}, Expected around: {utc_reference_schedule_time}. Skipping.")
                
                except Exception as e:
                    logger.error(f"Error processing task {task.id} ('{task.name}') in check_missed_scheduled_runs: {str(e)}", exc_info=True)
                    continue

            logger.info(f"--- Finished check_missed_scheduled_runs at {datetime.now(pytz.UTC)} ---")

        except OperationalError:
            logger.warning("Database not initialized yet, skipping check for missed runs")
        except Exception as e:
            logger.error(f"Unexpected error in check_missed_scheduled_runs: {str(e)}", exc_info=True)
            return False # Maintain previous behavior, though consider if scheduler should handle this

def initialize_scheduled_tasks():
    from app import scheduler
    """
    Initialize all scheduled tasks from the database at application startup.
    Also, schedule a periodic check for missed runs.
    """
    logger.info("Initializing scheduled tasks...")
    try:
        # Get all tasks that are marked as scheduled
        tasks_to_schedule = ScanTask.query.filter_by(is_scheduled=True).all()
        for task in tasks_to_schedule:
            logger.info(f"Scheduling task: {task.id} - {task.name}")
            schedule_task(task) # schedule_task already imports scheduler locally

        logger.info("Performing initial check for missed scheduled runs at startup...")
        check_missed_scheduled_runs() # check_missed_scheduled_runs already imports scheduler locally

        # Schedule the check_missed_scheduled_runs to run periodically
        # This job will detect any runs missed while the app was running.
        scheduler.add_job(
            func=check_missed_scheduled_runs,
            trigger='interval',
            seconds=10, # Check every 10 seconds
            id='periodic_missed_run_checker',
            replace_existing=True,
            misfire_grace_time=300 # Allow 5 minutes for misfires
        )
        logger.info("Scheduled periodic check for missed runs (every 10 seconds).")

        logger.info("Scheduled tasks initialization complete.")
    except Exception as e:
        logger.error(f"Error during scheduled tasks initialization: {str(e)}", exc_info=True)

def schedule_task(task):
    from app import scheduler
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
        job = scheduler.get_job(job_id)
        if job:
            logger.info(f"Scheduled daily task {job_id} with next run time: {job.next_run_time} (UTC)")
        else:
            logger.error(f"Failed to schedule daily task {job_id} or retrieve job details.")

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
        job = scheduler.get_job(job_id)
        if job:
            logger.info(f"Scheduled weekly task {job_id} with next run time: {job.next_run_time} (UTC)")
        else:
            logger.error(f"Failed to schedule weekly task {job_id} or retrieve job details.")

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
        job = scheduler.get_job(job_id)
        if job:
            logger.info(f"Scheduled monthly task {job_id} with next run time: {job.next_run_time} (UTC)")
        else:
            logger.error(f"Failed to schedule monthly task {job_id} or retrieve job details.")

    elif task.schedule_type == 'one-time':
        run_datetime_str = schedule_data.get('run_datetime_str') # Expected format: 'YYYY-MM-DD HH:MM:SS'
        if not run_datetime_str:
            logger.error(f"'run_datetime_str' not provided for one-time task {task.id}")
            return False

        try:
            # Parse as naive datetime first
            naive_run_dt = datetime.strptime(run_datetime_str, '%Y-%m-%d %H:%M:%S')

            # Convert from user timezone to UTC
            user_tz = pytz.timezone(user_timezone)
            user_aware_dt = user_tz.localize(naive_run_dt)
            utc_run_dt = user_aware_dt.astimezone(pytz.UTC)

            logger.info(f"One-time task {task.id}: Original '{run_datetime_str}' in {user_timezone}, converted to UTC: {utc_run_dt}")

            scheduler.add_job(
                func=create_scheduled_scan_run,
                trigger='date',
                run_date=utc_run_dt,
                id=job_id,
                args=[task.id],
                misfire_grace_time=3600  # Allow 1 hour for misfires
            )
            job = scheduler.get_job(job_id)
            if job:
                logger.info(f"Scheduled one-time task {job_id} for: {job.next_run_time} (UTC)")
            else:
                logger.error(f"Failed to schedule one-time task {job_id} or retrieve job details.")

        except ValueError as ve:
            logger.error(f"Error parsing 'run_datetime_str' for one-time task {task.id}: {ve}. Expected format 'YYYY-MM-DD HH:MM:SS'.")
            return False
        except Exception as e:
            logger.error(f"Error scheduling one-time task {task.id}: {e}")
            return False

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
        job = scheduler.get_job(job_id)
        if job:
            logger.info(f"Scheduled interval task {job_id} with first run time: {job.next_run_time} (UTC)")
        else:
            logger.error(f"Failed to schedule interval task {job_id} or retrieve job details.")

    return True

def unschedule_task(task_id):
    from app import scheduler
    """
    Remove a scheduled task
    """
    job_id = f"scan_task_{task_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        return True
    return False

def create_scheduled_scan_run(task_id):
    from app import scheduler
    """
    Create a scan run for a scheduled task and start it

    Args:
        task_id: The ID of the task to run
    """
    try:
        logger.info(f"Creating scheduled scan run for task {task_id}")

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
            logger.warning(f"Task {task_id} already has a {existing_scan.status} scan (ID: {existing_scan.id}), not creating a new one for missed schedule.")
            return None

        # Create a new scan run
        scan_run = ScanRun(
            task_id=task.id,
            status='queued',
            created_at=datetime.now(pytz.UTC),
            # started_at will be set when the task processor picks it up
        )
        try:
            db.session.add(scan_run)
            db.session.commit()
            scan_run_id = scan_run.id # Get the ID after commit
            logger.info(f"Created scan run {scan_run.id} for scheduled task {task.id}")
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
