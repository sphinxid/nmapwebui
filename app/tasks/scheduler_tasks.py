from flask import current_app, g
from app import _current_flask_app
from app import db  # Scheduler will be imported locally in functions
from app.models.task import ScanTask, ScanRun, TaskLock
from app.models.settings import SystemSettings
from app.models.user import User
from app.tasks.nmap_tasks import run_nmap_scan
from datetime import datetime, timedelta
import json
import pytz
import logging
import calendar
import psutil
import sys
from sqlalchemy.exc import OperationalError, IntegrityError
from sqlalchemy import inspect
from app.utils.timezone_utils import convert_local_to_utc, get_user_timezone

# Set up logging
logger = logging.getLogger(__name__)

def _is_scan_process_running(pid, scan_engine='nmap'):
    """Check if a process with the given PID is running and is a scan process (nmap)"""
    if pid is None:
        return False
    try:
        process = psutil.Process(pid)
        process_cmdline = ' '.join(process.cmdline()).lower()
        process_name = process.name().lower()
        return 'nmap' in process_name or 'nmap' in process_cmdline
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False

def _extract_scan_pids(scan_engine='nmap'):
    """Find running scan processes (nmap, masscan, or both) and return their PIDs"""
    try:
        scan_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.name().lower()
                proc_cmdline = ' '.join(proc.cmdline()).lower() if proc.cmdline() else ''
                if (scan_engine == 'nmap') and \
                   ('nmap' in proc_name or 'nmap' in proc_cmdline):
                    scan_processes.append({'pid': proc.pid, 'engine': 'nmap'})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return scan_processes
    except Exception as e:
        logger.error(f"Error checking for scan processes: {str(e)}")
        return []

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
            try:
                if job and hasattr(job, 'next_run_time') and job.next_run_time:
                    next_run = job.next_run_time
            except Exception as e:
                logger.error(f"Error accessing next_run_time for task {task.id}: {str(e)}")
                print(f"ERROR: Error accessing next_run_time for task {task.id}: {str(e)}", file=sys.stdout)
                sys.stdout.flush()

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
                        try:
                            if meta_job and hasattr(meta_job, 'next_run_time') and meta_job.next_run_time:
                                job = meta_job
                                logger.info(f"Using metadata job for task {task.id}")
                            # Use the one-time job if it exists
                            elif one_time_job and hasattr(one_time_job, 'next_run_time') and one_time_job.next_run_time:
                                job = one_time_job
                                logger.info(f"Using one-time job for task {task.id}")
                        except Exception as e:
                            logger.error(f"Error checking job schedule for task {task.id}: {str(e)}")
                            print(f"ERROR: Error checking job schedule for task {task.id}: {str(e)}", file=sys.stdout)
                            sys.stdout.flush()

                    # Safely check job next_run_time with proper attribute verification
                    has_valid_schedule = False
                    try:
                        has_valid_schedule = job and hasattr(job, 'next_run_time') and job.next_run_time is not None
                    except Exception as e:
                        logger.error(f"Error checking next_run_time for task {task.id}: {str(e)}")
                        print(f"ERROR: Error checking next_run_time for task {task.id}: {str(e)}", file=sys.stdout)
                        sys.stdout.flush()
                        
                    if not has_valid_schedule:
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
                        try:
                            # Safely access next_run_time with attribute checking
                            if hasattr(job, 'next_run_time') and job.next_run_time is not None:
                                utc_reference_schedule_time = job.next_run_time
                                logger.debug(f"Task {task.id} (Interval): Ref UTC from job.next_run_time: {utc_reference_schedule_time}.")
                            else:
                                utc_reference_schedule_time = now_utc
                                logger.debug(f"Task {task.id} (Interval): Using current time as reference since next_run_time is not available.")
                                print(f"SCHEDULED_TASK: Task {task.id} (Interval) - next_run_time attribute not available, using current time", file=sys.stdout)
                                sys.stdout.flush()
                        except Exception as e:
                            # Use current time as fallback and log the error
                            utc_reference_schedule_time = now_utc
                            logger.error(f"Task {task.id} (Interval): Error accessing job.next_run_time: {str(e)}. Using current time.")
                            print(f"ERROR: Task {task.id} (Interval) - Error accessing job.next_run_time: {str(e)}", file=sys.stdout)
                            sys.stdout.flush()

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
                        try:
                            # Safely check if this is a missed run using proper attribute checking
                            if hasattr(job, 'next_run_time') and job.next_run_time and job.next_run_time < now_utc:
                                logger.info(f"[Task {task.id}] INTERVAL MISSED RUN DETECTED. Job next_run_time: {job.next_run_time} < Current time: {now_utc}. Queuing new scan run.")
                                print(f"TASK_EVENT: [Task {task.id}] INTERVAL MISSED RUN DETECTED. Queuing new scan run.", file=sys.stdout)
                                sys.stdout.flush()
                                create_scheduled_scan_run(task.id)
                            else:
                                next_run_str = job.next_run_time if hasattr(job, 'next_run_time') and job.next_run_time else "Unknown"
                                logger.info(f"[Task {task.id}] Interval task appears to be on schedule. Next run: {next_run_str}. Current: {now_utc}.")
                        except Exception as e:
                            logger.error(f"[Task {task.id}] Error checking interval schedule: {str(e)}")
                            print(f"ERROR: [Task {task.id}] Error checking interval schedule: {str(e)}", file=sys.stdout)
                            sys.stdout.flush()
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

def cleanup_zombie_scan_runs():
    """Checks for 'running' or 'starting' scan tasks whose nmap/masscan processes are no longer active and marks them as 'failed'."""
    if _current_flask_app is None:
        logger.error("CRITICAL: Flask app instance (_current_flask_app) is None in cleanup_zombie_scan_runs.")
        return

    with _current_flask_app.app_context():
        logger.info("Starting NmapWebUI Zombie Task Cleanup job...")
        now_utc = datetime.now(pytz.UTC)
        zombie_count = 0

        # Get all running and starting scan runs
        # Added a filter for tasks started more than a minute ago to give them time to register a PID
        # or for very short scans to complete.
        time_threshold_for_pid_check = now_utc - timedelta(minutes=1)
        scans_to_check = ScanRun.query.filter(
            ScanRun.status.in_(['starting', 'running']),
            ScanRun.started_at < time_threshold_for_pid_check
        ).all()

        if not scans_to_check:
            logger.info("No running/starting scan tasks found that meet zombie check criteria.")
            return

        logger.info(f"Found {len(scans_to_check)} running/starting scan task(s) to check for zombie status.")

        for scan in scans_to_check:
            logger.info(f"Checking ScanRun ID: {scan.id}, Status: {scan.status}, Started: {scan.started_at}, Nmap PID: {scan.nmap_pid}")
            
            run_time = now_utc - scan.started_at.replace(tzinfo=pytz.UTC) # Ensure started_at is offset-aware for comparison
            
            scan_engine = 'nmap' # Default
            try:
                if scan.task and hasattr(scan.task, 'scan_engine') and scan.task.scan_engine:
                    scan_engine = scan.task.scan_engine
                logger.debug(f"ScanRun {scan.id} using engine: {scan_engine}")
            except Exception as e:
                logger.warning(f"Could not determine scan engine for ScanRun {scan.id}: {e}")

            is_zombie = False
            if scan.nmap_pid is not None:
                if not _is_scan_process_running(scan.nmap_pid, scan_engine):
                    logger.warning(f"ZOMBIE DETECTED: ScanRun {scan.id} (Engine: {scan_engine}, PID: {scan.nmap_pid}) process is not running.")
                    is_zombie = True
                else:
                    logger.info(f"ScanRun {scan.id} (Engine: {scan_engine}, PID: {scan.nmap_pid}) process is still running.")
            else: # No PID stored
                # Grace period for tasks that might not have registered a PID yet or are very short-lived
                # This is now partially handled by the time_threshold_for_pid_check in the initial query
                # but we can add a specific grace for PID-less runs if status is 'running'
                grace_period_no_pid = timedelta(minutes=2) # If it's 'running' for 2 mins without PID, it's suspicious
                if scan.status == 'running' and run_time > grace_period_no_pid:
                    logger.warning(f"ZOMBIE DETECTED: ScanRun {scan.id} is 'running' for {run_time} without a stored PID (threshold: {grace_period_no_pid}).")
                    is_zombie = True
                elif scan.status == 'starting': # If 'starting' for too long, also suspicious
                    if run_time > grace_period_no_pid: # Using same grace for 'starting'
                         logger.warning(f"ZOMBIE DETECTED: ScanRun {scan.id} is 'starting' for {run_time} without a stored PID (threshold: {grace_period_no_pid}).")
                         is_zombie = True
                    else:
                        logger.info(f"ScanRun {scan.id} is 'starting' without PID but within grace period ({run_time} < {grace_period_no_pid}). Monitoring.")
                else: # 'running' but within grace_period_no_pid
                    logger.info(f"ScanRun {scan.id} is 'running' without PID but within grace period ({run_time} < {grace_period_no_pid}). Monitoring.")

            if is_zombie:
                zombie_count += 1
                scan.status = 'failed'
                scan.error_message = f"Zombie task detected: {scan_engine} process (PID: {scan.nmap_pid if scan.nmap_pid else 'N/A'}) not found or task stuck in starting/running without PID."
                scan.completed_at = datetime.now(pytz.UTC)
                try:
                    db.session.commit()
                    logger.info(f"Marked ScanRun {scan.id} as FAILED (zombie task). Attempting to release lock.")
                    
                    lock_key_to_delete = f"lock:run_nmap_scan:task_id_{scan.task_id}"
                    task_lock_entry = db.session.get(TaskLock, lock_key_to_delete)
                    if task_lock_entry:
                        db.session.delete(task_lock_entry)
                        db.session.commit()
                        logger.info(f"Successfully deleted task lock: {lock_key_to_delete} for zombie ScanRun {scan.id}.")
                    else:
                        logger.info(f"No task lock found with key: {lock_key_to_delete} for zombie ScanRun {scan.id}.")
                except Exception as e_commit_lock:
                    logger.error(f"Error committing zombie status or deleting lock for ScanRun {scan.id}: {e_commit_lock}")
                    if db.session.is_active:
                        db.session.rollback()
            else:
                logger.info(f"ScanRun {scan.id} appears to be running normally or is not yet considered a zombie.")
        
        logger.info(f"Zombie Task Cleanup job finished. Found and processed {zombie_count} zombie task(s).")

def initialize_scheduled_tasks():
    """Initializes all scheduled tasks from the database and the periodic missed run checker."""
    from app import scheduler, db
    logger.info("Initializing scheduled tasks...")

    try:
        inspector = inspect(db.engine)
        # Check if the 'scan_tasks' table exists. This prevents errors on first-time setup.
        if not inspector.has_table(ScanTask.__tablename__):
            logger.info(f"Table '{ScanTask.__tablename__}' not found. Skipping scheduled tasks initialization. This is expected during initial database setup.")
            return
    except Exception as e:
        logger.error(f"Error while checking for table existence during scheduler initialization: {e}", exc_info=True)
        # If we can't even inspect the DB, it's safer not to proceed.
        return

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
            replace_existing=True, coalesce=True, max_instances=1,
            misfire_grace_time=300 # Allow 5 minutes for misfires
        )
        logger.info("Scheduled periodic check for missed runs (every 10 seconds).")

        # Add the periodic zombie task cleanup job
        scheduler.add_job(func=cleanup_zombie_scan_runs, trigger='interval', minutes=1, id='periodic_zombie_cleanup', replace_existing=True, coalesce=True, max_instances=1)
        logger.info("Scheduled periodic_zombie_cleanup to run every 1 minute.")

        logger.info("Scheduled tasks initialization complete.")
    except OperationalError as e:
        # This is a fallback. The check above should prevent this, but we keep it for safety.
        logger.warning(f"Caught an OperationalError during scheduled task initialization. The database might not be fully ready. Error: {e}")
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

    # Using replace_existing=True, coalesce=True, max_instances=1 in add_job() handles job updates atomically.

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
            misfire_grace_time=3600,  # Allow 1 hour for misfires
            replace_existing=True, coalesce=True, max_instances=1
        )
        try:
            # Safely get job and its next_run_time with error handling
            job = scheduler.get_job(job_id)
            if job:
                # Use hasattr to safely check for attribute existence
                if hasattr(job, 'next_run_time'):
                    logger.info(f"Scheduled daily task {job_id} with next run time: {job.next_run_time} (UTC)")
                else:
                    # Safely log without accessing the attribute
                    logger.info(f"Scheduled daily task {job_id} successfully, next run time attribute not available")
                    print(f"SCHEDULED_TASK: Daily task {job_id} scheduled successfully but next_run_time attribute is not available", file=sys.stdout)
                    sys.stdout.flush()
            else:
                logger.error(f"Failed to schedule daily task {job_id} or retrieve job details.")
        except Exception as e:
            logger.error(f"Error checking daily job status for {job_id}: {str(e)}")
            print(f"ERROR: Error checking daily job status for {job_id}: {str(e)}", file=sys.stdout)
            sys.stdout.flush()

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
            misfire_grace_time=3600,  # Allow 1 hour for misfires
            replace_existing=True, coalesce=True, max_instances=1
        )
        try:
            # Safely get job and its next_run_time with error handling
            job = scheduler.get_job(job_id)
            if job:
                # Use hasattr to safely check for attribute existence
                if hasattr(job, 'next_run_time'):
                    logger.info(f"Scheduled weekly task {job_id} with next run time: {job.next_run_time} (UTC)")
                else:
                    # Safely log without accessing the attribute
                    logger.info(f"Scheduled weekly task {job_id} successfully, next run time attribute not available")
                    print(f"SCHEDULED_TASK: Weekly task {job_id} scheduled successfully but next_run_time attribute is not available", file=sys.stdout)
                    sys.stdout.flush()
            else:
                logger.error(f"Failed to schedule weekly task {job_id} or retrieve job details.")
        except Exception as e:
            logger.error(f"Error checking weekly job status for {job_id}: {str(e)}")
            print(f"ERROR: Error checking weekly job status for {job_id}: {str(e)}", file=sys.stdout)
            sys.stdout.flush()

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
                    misfire_grace_time=3600,  # Allow 1 hour for misfires
                    replace_existing=True, coalesce=True, max_instances=1
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
            misfire_grace_time=3600,  # Allow 1 hour for misfires
            replace_existing=True, coalesce=True, max_instances=1
        )
        try:
            # Safely get job and its next_run_time with error handling
            job = scheduler.get_job(job_id)
            if job:
                # Use hasattr to safely check for attribute existence
                if hasattr(job, 'next_run_time'):
                    logger.info(f"Scheduled monthly task {job_id} with next run time: {job.next_run_time} (UTC)")
                else:
                    # Safely log without accessing the attribute
                    logger.info(f"Scheduled monthly task {job_id} successfully, next run time attribute not available")
                    print(f"SCHEDULED_TASK: Monthly task {job_id} scheduled successfully but next_run_time attribute is not available", file=sys.stdout)
                    sys.stdout.flush()
            else:
                logger.error(f"Failed to schedule monthly task {job_id} or retrieve job details.")
        except Exception as e:
            logger.error(f"Error checking monthly job status for {job_id}: {str(e)}")
            print(f"ERROR: Error checking monthly job status for {job_id}: {str(e)}", file=sys.stdout)
            sys.stdout.flush()

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
                misfire_grace_time=3600,  # Allow 1 hour for misfires
                replace_existing=True, coalesce=True, max_instances=1
            )
            try:
                # Safely get job and its next_run_time with error handling
                job = scheduler.get_job(job_id)
                if job:
                    # Use hasattr to safely check for attribute existence
                    if hasattr(job, 'next_run_time'):
                        logger.info(f"Scheduled one-time task {job_id} for: {job.next_run_time} (UTC)")
                    else:
                        # Safely log without accessing the attribute
                        logger.info(f"Scheduled one-time task {job_id} successfully, next run time attribute not available")
                        print(f"SCHEDULED_TASK: One-time task {job_id} scheduled successfully but next_run_time attribute is not available", file=sys.stdout)
                        sys.stdout.flush()
                else:
                    logger.error(f"Failed to schedule one-time task {job_id} or retrieve job details.")
            except Exception as e:
                logger.error(f"Error checking one-time job status for {job_id}: {str(e)}")
                print(f"ERROR: Error checking one-time job status for {job_id}: {str(e)}", file=sys.stdout)
                sys.stdout.flush()

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
            misfire_grace_time=3600,  # Allow 1 hour for misfires
            replace_existing=True, coalesce=True, max_instances=1
        )

        logger.info(f"Interval task {job_id} scheduled to start at {start_date_utc} and repeat every {hours} hours")
        
        try:
            # Safely get job and its next_run_time with error handling
            job = scheduler.get_job(job_id)
            if job:
                # Use hasattr to safely check for attribute existence
                if hasattr(job, 'next_run_time'):
                    logger.info(f"Scheduled interval task {job_id} with first run time: {job.next_run_time} (UTC)")
                else:
                    # Safely log without accessing the attribute
                    logger.info(f"Scheduled interval task {job_id} successfully, next run time attribute not available")
                    print(f"SCHEDULED_TASK: Interval task {job_id} scheduled successfully but next_run_time attribute is not available", file=sys.stdout)
                    sys.stdout.flush()
            else:
                logger.error(f"Failed to schedule interval task {job_id} or retrieve job details.")
        except Exception as e:
            logger.error(f"Error checking job status for {job_id}: {str(e)}")
            print(f"ERROR: Error checking job status for {job_id}: {str(e)}", file=sys.stdout)
            sys.stdout.flush()

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
    if _current_flask_app is None:
        error_msg = f"CRITICAL: Flask app instance (_current_flask_app) is None. Cannot create app context for create_scheduled_scan_run (task_id: {task_id})."
        logger.error(error_msg)
        print(f"CRITICAL ERROR: {error_msg}", file=sys.stdout)
        sys.stdout.flush()
        return None # Or raise an exception

    with _current_flask_app.app_context():
        lock_key = f"lock:create_run:task_{task_id}"
        lock_acquired = False
        try:
            # Attempt to acquire the lock by creating a TaskLock entry
            new_lock_entry = TaskLock(lock_key=lock_key)
            try:
                print(f"SCHEDULED_TASK: [Task {task_id}] Attempting to acquire task lock {lock_key}", file=sys.stdout)
                sys.stdout.flush()
                db.session.add(new_lock_entry)
                db.session.commit()
                lock_acquired = True
                lock_info = f"Acquired lock {lock_key} for task {task_id}. Proceeding to create scan run."
                logger.info(lock_info)
                print(f"SCHEDULED_TASK: {lock_info}", file=sys.stdout)
                sys.stdout.flush()
            except IntegrityError: # Specific to SQLAlchemy, handles underlying DB unique constraint errors
                db.session.rollback() # Rollback the failed session
                lock_warning = f"Could not acquire lock {lock_key} for task {task_id} (already held). Another worker is likely processing it. Skipping."
                logger.info(lock_warning)
                print(f"WARNING: {lock_warning}", file=sys.stdout)
                sys.stdout.flush()
                return None
            except Exception as e_lock_acquire: # Catch other potential errors during lock acquisition
                db.session.rollback()
                lock_error = f"Error acquiring lock {lock_key} for task {task_id}: {e_lock_acquire}"
                logger.error(lock_error)
                print(f"ERROR: {lock_error}", file=sys.stdout)
                sys.stdout.flush()
                return None

            task_info = f"Creating scheduled scan run for task {task_id}"
            logger.info(task_info)
            print(f"SCHEDULED_TASK: {task_info}", file=sys.stdout)
            sys.stdout.flush()

            # First, get the task
            task = ScanTask.query.get(task_id)
            if not task:
                task_not_found = f"Task {task_id} not found"
                logger.error(task_not_found)
                print(f"ERROR: {task_not_found}", file=sys.stdout)
                sys.stdout.flush()
                return None

            # Check if task is still scheduled
            if not task.is_scheduled:
                not_scheduled = f"Task {task_id} is no longer scheduled, skipping run"
                logger.warning(not_scheduled)
                print(f"WARNING: {not_scheduled}", file=sys.stdout)
                sys.stdout.flush()
                return None

            # Check if there's already a queued or running scan for this task
            print(f"SCHEDULED_TASK: [Task {task_id}] Checking for existing queued or running scans", file=sys.stdout)
            sys.stdout.flush()
            existing_scan = ScanRun.query.filter(
                ScanRun.task_id == task.id,
                ScanRun.status.in_(['queued', 'running'])
            ).first()

            if existing_scan:
                duplicate_msg = f"Task {task_id} already has a {existing_scan.status} scan (ID: {existing_scan.id}), not creating a new one for missed schedule."
                logger.warning(duplicate_msg)
                print(f"WARNING: {duplicate_msg}", file=sys.stdout)
                sys.stdout.flush()
                return None

            # Create a new scan run
            print(f"SCHEDULED_TASK: [Task {task_id}] Creating new scan run with status 'queued'", file=sys.stdout)
            sys.stdout.flush()
            scan_run = ScanRun(
                task_id=task.id,
                status='queued',
                created_at=datetime.now(pytz.UTC),
                # started_at will be set when the task processor picks it up
            )
            try:
                db.session.add(scan_run)
                print(f"SCHEDULED_TASK: [Task {task_id}] Committing new scan run to database", file=sys.stdout)
                sys.stdout.flush()
                db.session.commit()
                scan_run_id = scan_run.id # Get the ID after commit
                created_msg = f"Created scan run {scan_run.id} for scheduled task {task.id}"
                logger.info(created_msg)
                print(f"SCHEDULED_TASK: {created_msg}", file=sys.stdout)
                queued_msg = f"Scan run {scan_run_id} created and queued. It will be processed by the task processor."
                logger.info(queued_msg)
                print(f"SCHEDULED_TASK: {queued_msg}", file=sys.stdout)
                sys.stdout.flush()
                return scan_run_id
            except OperationalError as oe:
                    if 'UNIQUE constraint failed' in str(oe):
                        unique_error = f"Task {task_id} already has a queued or running scan, skipping"
                        logger.warning(unique_error)
                        print(f"WARNING: {unique_error}", file=sys.stdout)
                        sys.stdout.flush()
                        db.session.rollback()
                        return None
                    else:
                        db_error = f"Database error while processing task {task_id}: {str(oe)}"
                        logger.warning(db_error)
                        print(f"ERROR: {db_error}", file=sys.stdout)
                        sys.stdout.flush()
                        db.session.rollback()
                        return None

        except Exception as e:
            error_msg = f"Error creating scheduled scan run for task {task_id}: {str(e)}"
            logger.error(error_msg)
            print(f"ERROR: {error_msg}", file=sys.stdout)
            # Print stack trace to STDOUT for debugging
            import traceback
            print(f"EXCEPTION TRACE: [Task {task_id}]\n{traceback.format_exc()}", file=sys.stdout)
            sys.stdout.flush()
            if 'db' in locals() and db.session.is_active:
                db.session.rollback()
            return None
        finally:
            if lock_acquired:
                try:
                    print(f"SCHEDULED_TASK: [Task {task_id}] Attempting to release lock {lock_key}", file=sys.stdout)
                    sys.stdout.flush()
                    lock_to_release = db.session.get(TaskLock, lock_key) # Use db.session.get for primary key lookup
                    if lock_to_release:
                        db.session.delete(lock_to_release)
                        db.session.commit()
                        release_msg = f"Released lock {lock_key} for task {task_id}."
                        logger.info(release_msg)
                        print(f"SCHEDULED_TASK: {release_msg}", file=sys.stdout)
                        sys.stdout.flush()
                    else:
                        not_found_msg = f"Attempted to release lock {lock_key} but it was not found in the database."
                        logger.warning(not_found_msg)
                        print(f"WARNING: {not_found_msg}", file=sys.stdout)
                        sys.stdout.flush()
                except Exception as e_lock_release:
                    release_error = f"Error releasing lock {lock_key} for task {task_id}: {e_lock_release}"
                    logger.error(release_error)
                    print(f"ERROR: {release_error}", file=sys.stdout)
                    sys.stdout.flush()
                    if db.session.is_active:
                        db.session.rollback()
