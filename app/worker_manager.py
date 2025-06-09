import multiprocessing
import logging
import atexit
from app.tasks.nmap_tasks import run_nmap_scan
from config import Config

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
        # Note: If tasks require specific Flask app context or DB setup not handled
        # within the task function itself, an initializer function for the pool might be needed.
        # run_nmap_scan creates its own app context, which is good.
        WORKER_POOL = multiprocessing.Pool(processes=pool_size)
        logger.info("Worker pool initialized.")

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

def submit_nmap_scan(scan_run_id, scan_task_id_for_lock):
    """Submits an Nmap scan task to the worker pool."""
    # WORKER_POOL is expected to be initialized by create_app in app/__init__.py
    if WORKER_POOL is None:
        logger.error("Worker pool is not initialized. Cannot submit task. Check application startup.")
        return False
    
    # No 'global WORKER_POOL' needed here if we are only reading it.
    # However, if initialize_worker_pool could be called, it would modify the global.
    # Since we removed the internal init, direct read is fine.
    if WORKER_POOL:
        try:
            logger.info("Submitting nmap scan for scan_run_id: %s (task_id_for_lock: %s) to worker pool.", scan_run_id, scan_task_id_for_lock)
            # apply_async is non-blocking and returns an AsyncResult object (not used here yet)
            WORKER_POOL.apply_async(run_nmap_scan, args=(scan_run_id, scan_task_id_for_lock))
            logger.info("Nmap scan for scan_run_id: %s submitted successfully.", scan_run_id)
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
