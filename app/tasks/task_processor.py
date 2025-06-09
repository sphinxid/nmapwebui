"""
Task processor module for handling queued tasks
"""
from app import db, create_app # Removed scheduler, celery shared_task, celery_config
from app.models.task import ScanRun, ScanTask
from app.models.settings import SystemSettings
from app.worker_manager import submit_nmap_scan
from config import Config # Import Config
import logging
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)

def process_queued_tasks():
    """
    Process queued tasks based on the maximum concurrent tasks setting
    This function is meant to be called periodically by Celery
    """
    app = create_app()

    with app.app_context():
        try:
            # Get the maximum concurrent tasks setting from SystemSettings
            max_concurrent_tasks_from_ui = SystemSettings.get_int('max_concurrent_tasks', 4)
            # Get the actual pool size from config
            actual_pool_size = Config.NMAP_WORKER_POOL_SIZE # This is now an int

            # Effective max concurrent tasks is the lower of the two
            max_concurrent_tasks = min(max_concurrent_tasks_from_ui, actual_pool_size)
            logger.info(f"UI 'max_concurrent_tasks' setting: {max_concurrent_tasks_from_ui}, Actual pool size: {actual_pool_size}. Effective max concurrent tasks: {max_concurrent_tasks}")

            # Count currently running tasks
            running_tasks_count = ScanRun.query.filter(
                ScanRun.status == 'running'
            ).count()

            # If we're already at or over the limit, don't start any new tasks
            if running_tasks_count >= max_concurrent_tasks:
                logger.info("Already running %s tasks (limit: %s). No new tasks will be started.", running_tasks_count, max_concurrent_tasks)
                return

            # Calculate how many new tasks we can start
            available_slots = max_concurrent_tasks - running_tasks_count

            # Get all queued tasks
            queued_tasks_query = ScanRun.query.filter(ScanRun.status == 'queued')

            # Get the queued tasks directly - we'll prioritize based on started_at
            # which is now set to the scheduled run time for scheduled tasks
            queued_tasks_all = queued_tasks_query.order_by(ScanRun.started_at.asc()).all()

            # Log all queued tasks and their priority times
            if queued_tasks_all:
                logger.info("All queued tasks and their priority times:")
                for i, task in enumerate(queued_tasks_all):
                    scan_task = ScanTask.query.get(task.task_id)
                    is_scheduled = scan_task.is_scheduled if scan_task else False
                    task_type = "Scheduled" if is_scheduled else "Regular"
                    logger.info("  %s. %s Task - ScanRun ID: %s, Task ID: %s, Priority Time: %s", i+1, task_type, task.id, task.task_id, task.started_at)

            # We don't need to join with ScanTask anymore since we're using started_at for prioritization
            # which is already set correctly for scheduled tasks

            # Current time in UTC
            now_utc = datetime.now(pytz.UTC)
            logger.info("Current UTC time: %s", now_utc.strftime('%Y-%m-%d %H:%M:%S'))

            # Tasks are already sorted by started_at which contains the priority time
            # Limit to available slots
            queued_tasks = queued_tasks_all[:available_slots]

            # Log final task selection
            if queued_tasks:
                logger.info("Final task selection (limited to %s slots):", available_slots)
                for i, task in enumerate(queued_tasks):
                    scan_task = ScanTask.query.get(task.task_id)
                    is_scheduled = scan_task.is_scheduled if scan_task else False
                    task_type = "Scheduled" if is_scheduled else "Regular"
                    logger.info("  %s. %s Task - ScanRun ID: %s, Task ID: %s, Priority Time: %s", i+1, task_type, task.id, task.task_id, task.started_at)
            else:
                logger.info("No tasks selected for execution")

            # Start each task
            for task in queued_tasks:
                logger.info("Starting queued task: ScanRun ID %s for Task ID %s", task.id, task.task_id)

                # Update the task status to 'running' in the database
                task.status = 'running'
                task.started_at = datetime.utcnow()
                db.session.commit()

                submission_successful = submit_nmap_scan(scan_run_id=task.id, scan_task_id_for_lock=task.task_id)
                if not submission_successful:
                    logger.error("Failed to submit ScanRun %s (ScanTask %s) to worker pool from task processor.", task.id, task.task_id)
                    # Revert status to queued if submission failed, so it can be retried
                    task.status = 'queued'
                    # Potentially add an error counter or specific error status to avoid immediate re-pick
                    # For now, just reverting status.
                    db.session.commit() # Commit status revert
                else:
                    logger.info("ScanRun %s (ScanTask %s) submitted to worker pool by task processor.", task.id, task.task_id)


            # Logging for successfully submitted tasks will be handled per task now
            # The original log message might be misleading as tasks are submitted, not necessarily 'started' by this function directly.
            # We can add a summary log if needed after the loop.
            processed_count = sum(1 for t in queued_tasks if t.status == 'running') # Count tasks whose status was changed to running
            if processed_count > 0:
                current_running_after_processing = ScanRun.query.filter(ScanRun.status == 'running').count()
                logger.info("Processed %s queued tasks. %s/%s concurrent tasks now running or submitted.", processed_count, current_running_after_processing, max_concurrent_tasks)

        except Exception as e:
            logger.error("Error processing queued tasks: %s", str(e))
            