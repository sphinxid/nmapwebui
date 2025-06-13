import multiprocessing
import logging
import atexit
import sys
import os
from functools import partial
from datetime import datetime
import pytz # For timezone-aware ended_at, if used

from app.tasks.nmap_tasks import run_nmap_scan
from config import Config
from app import _current_flask_app, db # Assuming _current_flask_app is accessible from app package
from app.models.task import ScanRun

logger = logging.getLogger(__name__)

# Determine pool size (can be made configurable later via Flask app config)
DEFAULT_POOL_SIZE = Config.NMAP_WORKER_POOL_SIZE

try:
    cpu_count = multiprocessing.cpu_count()
    # Use half the CPU cores, minimum 1, but let's stick to a default or configured value for simplicity first.
    # pool_size = max(1, cpu_count // 2)
    pool_size = DEFAULT_POOL_SIZE # Placeholder, ideally from app.config
except NotImplementedError:
    pool_size = DEFAULT_POOL_SIZE

WORKER_POOL = None

def initialize_worker_pool():
    """Initializes the global worker pool."""
    global WORKER_POOL
    if WORKER_POOL is None:
        logger.info("Initializing worker pool with %s processes.", pool_size)
        print(f"WORKER_POOL: Initializing worker pool with {pool_size} processes", file=sys.stdout)
        sys.stdout.flush()
        
        # Set daemon=False explicitly to prevent "daemonic processes are not allowed to have children" error
        # This ensures the pool processes can spawn nmap child processes
        ctx = multiprocessing.get_context('spawn')  # Use 'spawn' context for better cross-platform compatibility
        WORKER_POOL = ctx.Pool(processes=pool_size)
        
        logger.info("Worker pool initialized.")
        print(f"WORKER_POOL: Worker pool initialized successfully", file=sys.stdout)
        sys.stdout.flush()

def shutdown_worker_pool():
    """Shuts down the global worker pool gracefully."""
    global WORKER_POOL
    if WORKER_POOL is not None:
        logger.info("Shutting down worker pool...")
        WORKER_POOL.close()  # No more tasks
        WORKER_POOL.join()   # Wait for current tasks to complete
        WORKER_POOL = None
        logger.info("Worker pool shut down.")

# Register shutdown_worker_pool to be called at Python interpreter exit.
# This is a best-effort cleanup. For robust production setups (e.g., with Gunicorn),
# managing the pool lifecycle via server hooks might be more appropriate.
atexit.register(shutdown_worker_pool)


def scan_success_callback(scan_run_id, result_from_run_nmap_scan):
    logger.info(f"Scan success callback triggered for scan_run_id: {scan_run_id}, result: {result_from_run_nmap_scan}")
    
    if not _current_flask_app:
        logger.error(f"CRITICAL: Cannot update ScanRun {scan_run_id}: _current_flask_app is None in scan_success_callback.")
        return

    with _current_flask_app.app_context():
        try:
            scan_run = db.session.get(ScanRun, scan_run_id)
            if not scan_run:
                logger.error(f"ScanRun {scan_run_id} not found in scan_success_callback.")
                return

            if result_from_run_nmap_scan is None:  # Lock acquisition failure (decorator returned None)
                if scan_run.status in ['queued', 'starting', 'running']:
                    scan_run.status = 'failed'
                    scan_run.error_message = "Task skipped: Could not acquire execution lock (already running or recently completed)."
                    scan_run.ended_at = datetime.now(pytz.UTC) # Or use timezone.utc if Python 3.9+
                    db.session.commit()
                    logger.info(f"Updated ScanRun {scan_run_id} to '{scan_run.status}' due to lock acquisition failure.")
                else:
                    logger.info(f"ScanRun {scan_run_id} already in terminal state '{scan_run.status}'. No update from lock failure callback.")
            
            elif isinstance(result_from_run_nmap_scan, dict):
                task_status = result_from_run_nmap_scan.get('status')
                task_message = result_from_run_nmap_scan.get('message')

                if task_status == 'completed':
                    # run_nmap_scan should have already set this. Log for confirmation.
                    logger.info(f"ScanRun {scan_run_id} reported as 'completed' by the task function. Current DB status: {scan_run.status}.")
                    if scan_run.status != 'completed':
                        logger.warning(f"ScanRun {scan_run_id} DB status is '{scan_run.status}', but task returned 'completed'. Re-aligning.")
                        scan_run.status = 'completed'
                        if scan_run.ended_at is None: # Set ended_at if not already set
                             scan_run.ended_at = datetime.now(pytz.UTC)
                        # scan_run.error_message = None # Clear error if it was completed
                        db.session.commit()

                elif task_status == 'failed':
                    logger.warning(f"ScanRun {scan_run_id} reported as 'failed' by the task function. DB status: {scan_run.status}. Message: {task_message}")
                    if scan_run.status not in ['failed', 'completed']: # Avoid overwriting a 'completed' status if some race occurred
                        scan_run.status = 'failed'
                        if task_message:
                            scan_run.error_message = str(task_message)[:500] # Ensure it fits, use model's length
                        if scan_run.ended_at is None:
                            scan_run.ended_at = datetime.now(pytz.UTC)
                        db.session.commit()
                        logger.info(f"Updated ScanRun {scan_run_id} to 'failed' based on task function's 'failed' return. Message: {task_message}")
                    else:
                        logger.info(f"ScanRun {scan_run_id} already in terminal state '{scan_run.status}' or task reported failure for already completed task. No update from task's 'failed' return.")
                else:
                    logger.warning(f"ScanRun {scan_run_id} received an unexpected status '{task_status}' in result dictionary: {result_from_run_nmap_scan}")
            
            else:
                logger.error(f"ScanRun {scan_run_id} received an unexpected result type in scan_success_callback: {type(result_from_run_nmap_scan)}. Result: {result_from_run_nmap_scan}")

        except Exception as e:
            logger.error(f"Error in scan_success_callback for ScanRun {scan_run_id}: {e}", exc_info=True)
            if db.session.is_active:
                db.session.rollback()

def scan_error_callback(scan_run_id, exception):
    logger.error(f"Scan error callback triggered for scan_run_id: {scan_run_id} due to: {exception}", exc_info=True)
    if not _current_flask_app:
        logger.error(f"CRITICAL: Cannot update ScanRun {scan_run_id}: _current_flask_app is None in scan_error_callback.")
        return

    with _current_flask_app.app_context():
        try:
            scan_run = db.session.get(ScanRun, scan_run_id) # Use db.session.get
            if scan_run:
                scan_run.status = 'failed'
                scan_run.error_message = f"Worker process error: {str(exception)[:450]}" # Truncate error to fit field
                scan_run.ended_at = datetime.now(pytz.UTC)
                db.session.commit()
                logger.info(f"Updated ScanRun {scan_run_id} to 'failed' due to worker exception.")
            else:
                logger.error(f"ScanRun {scan_run_id} not found in scan_error_callback.")
        except Exception as e:
            logger.error(f"Error in scan_error_callback handling for ScanRun {scan_run_id}: {e}")
            if db.session.is_active:
                db.session.rollback()

def submit_nmap_scan(scan_run_id, scan_task_id_for_lock):
    """Submits an Nmap scan task to the worker pool.
    
    In our single-worker-pool architecture, only the primary worker has an initialized pool.
    Non-primary workers will update the scan status to indicate it needs to be run by the primary worker.
    """
    # Get current process ID for logging
    process_id = os.getpid()
    
    # Check if this worker has an initialized worker pool (only primary worker should)
    if WORKER_POOL is None:
        logger.warning(f"Worker PID={process_id} has no worker pool initialized (non-primary worker).")
        print(f"WORKER_POOL_WARN: Worker PID={process_id} has no worker pool (non-primary worker)", file=sys.stdout)
        sys.stdout.flush()
        
        # Update the scan run status to indicate it needs to be picked up by primary worker
        # This allows the primary worker's scheduler to find and run this task
        from app import _current_flask_app, db
        from app.models.task import ScanRun
        
        if _current_flask_app:
            with _current_flask_app.app_context():
                try:
                    scan_run = db.session.get(ScanRun, scan_run_id)
                    if scan_run:
                        scan_run.status = 'queued'  # Mark as queued for the scheduler to pick up
                        scan_run.last_error = f"Redirected to primary worker pool (PID={process_id} is non-primary)"
                        db.session.commit()
                        logger.info(f"Scan run {scan_run_id} marked as queued for pickup by primary worker")
                        print(f"WORKER_POOL_INFO: Scan run {scan_run_id} marked as queued for primary worker", file=sys.stdout)
                        sys.stdout.flush()
                        return True
                    else:
                        logger.error(f"ScanRun {scan_run_id} not found in submit_nmap_scan from non-primary worker.")
                        return False
                except Exception as e:
                    logger.error(f"Error updating scan run {scan_run_id} status: {str(e)}")
                    if db.session.is_active:
                        db.session.rollback()
                    return False
        return False
    
    # Primary worker with initialized pool
    try:
        logger.info(f"Worker PID={process_id} submitting nmap scan for scan_run_id: {scan_run_id} to worker pool.")
        print(f"WORKER_POOL_INFO: Worker PID={process_id} submitting scan {scan_run_id} to pool", file=sys.stdout)
        sys.stdout.flush()
        
        # apply_async is non-blocking. Use callbacks to handle results/errors.
        success_cb = partial(scan_success_callback, scan_run_id)
        error_cb = partial(scan_error_callback, scan_run_id)

        WORKER_POOL.apply_async(
            run_nmap_scan, 
            args=(scan_run_id, scan_task_id_for_lock),
            callback=success_cb,
            error_callback=error_cb
        )
        logger.info(f"Nmap scan for scan_run_id: {scan_run_id} submitted successfully with callbacks.")
        return True
    except Exception as e:
        # This catch is for errors during submission to the pool itself.
            # Errors within run_nmap_scan are handled inside that function.
            logger.error("Failed to submit nmap scan for scan_run_id %s to worker pool: %s", scan_run_id, e)
            # Consider how to report this failure, e.g., update ScanRun status directly if possible,
            # but that would require app context here.
            return False
    else:
        logger.error("Worker pool is not available. Cannot submit task.")
        return False

# It's generally better to call initialize_worker_pool() explicitly during app startup.
# For example, in your Flask app factory (create_app in app/__init__.py):
# if not app.testing and not app.config.get('WORKER_POOL_INITIALIZED'):
#     from . import worker_manager
#     worker_manager.initialize_worker_pool()
#     app.config['WORKER_POOL_INITIALIZED'] = True
