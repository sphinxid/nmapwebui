from flask import Flask, render_template, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import os
import sys
import pytz
import atexit
import signal
import time
from datetime import datetime
from config import Config
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
import logging as std_logging
import psutil

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
scheduler = BackgroundScheduler(timezone=pytz.UTC)
_current_flask_app = None

# Event listener to set PRAGMAs for SQLite connections
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    # Check if the connection is for SQLite. 
    # dbapi_connection.__class__.__module__ might be 'sqlite3' or similar.
    # A more direct check might be connection_record.dialect.name == 'sqlite'
    # However, connection_record might not be fully populated for all event types or early connections.
    # Assuming sqlite3 for now based on typical usage.
    if hasattr(dbapi_connection, 'execute') and 'sqlite3' in str(type(dbapi_connection)).lower():
        try:
            cursor = dbapi_connection.cursor()
            std_logging.info("Attempting to set PRAGMA journal_mode=WAL and busy_timeout=5000 for SQLite connection.")
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA busy_timeout = 5000;") # 5 seconds
            cursor.close()
            std_logging.info("Successfully set PRAGMA journal_mode=WAL and busy_timeout=5000.")
        except Exception as e:
            std_logging.error(f"Failed to set SQLite PRAGMAs: {e}")

def create_app(config_class=Config, instance_path=None):
    global _current_flask_app
    app = Flask(__name__, instance_path=instance_path) if instance_path else Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Assign the app instance to the global variable before scheduler setup
    _current_flask_app = app
    
    # Configure login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Configure APScheduler with SQLAlchemyJobStore and start it
    if not scheduler.running:
        jobstores = {
            'default': SQLAlchemyJobStore(url=app.config['SQLALCHEMY_DATABASE_URI'])
        }
        scheduler.configure(jobstores=jobstores)
        
        # Determine if this is the primary worker by checking environment variables or process ID
        # This implementation uses a more reliable file locking mechanism with process ID tracking
        is_primary_worker = False  # Default to False, set to True only if confirmed as primary worker
        worker_id = os.environ.get('GUNICORN_WORKER_ID', os.environ.get('WORKER_ID'))
        process_id = os.getpid()
        
        app.logger.info(f"Worker initialization: PID={process_id}, Environment Worker ID={worker_id}")
        print(f"WORKER_INIT: PID={process_id}, Environment Worker ID={worker_id}", file=sys.stdout)
        sys.stdout.flush()
        
        # A more robust approach using PID-based locking
        import tempfile
        import fcntl
        import random
        
        # Use an absolute path for the lock file to ensure consistency across workers
        LOCK_DIR = "/tmp" if os.path.exists("/tmp") else tempfile.gettempdir()
        LOCK_FILE = os.path.join(LOCK_DIR, 'nmapwebui_scheduler.lock')
        
        # Add a slight random delay to prevent race conditions between workers
        time.sleep(random.uniform(0.1, 0.5))
        
        app.logger.info(f"Using lock file for scheduler coordination: {LOCK_FILE}")
        print(f"SCHEDULER_LOCK: Using lock file: {LOCK_FILE}", file=sys.stdout)
        sys.stdout.flush()
        
        lock_file = None
        try:
            # Check if file exists and read PID if it does
            if os.path.exists(LOCK_FILE):
                try:
                    with open(LOCK_FILE, 'r') as f:
                        existing_pid = int(f.read().strip())
                        
                        # Check if process with this PID still exists
                        if psutil.pid_exists(existing_pid):
                            app.logger.info(f"Found existing scheduler lock owned by PID {existing_pid}, this worker will not run scheduler")
                            print(f"SCHEDULER_INFO: Found existing lock by PID {existing_pid}, worker {process_id} will not run scheduler", file=sys.stdout)
                            sys.stdout.flush()
                            is_primary_worker = False
                        else:
                            app.logger.info(f"Found stale lock file from PID {existing_pid} which is no longer running")
                            print(f"SCHEDULER_INFO: Removing stale lock from PID {existing_pid}", file=sys.stdout)
                            sys.stdout.flush()
                            # Process doesn't exist, remove the stale lock
                            os.unlink(LOCK_FILE)
                except Exception as e:
                    app.logger.error(f"Error reading lock file: {e}, will attempt to acquire new lock")
                    print(f"SCHEDULER_ERROR: Error reading lock file: {e}", file=sys.stdout)
                    sys.stdout.flush()
                    # If we can't read the file, try to remove it and create a new one
                    if os.path.exists(LOCK_FILE):
                        os.unlink(LOCK_FILE)
            
            # If we don't have a valid lock file, try to create it
            if not os.path.exists(LOCK_FILE):
                lock_file = open(LOCK_FILE, 'w')
                try:
                    # Use non-blocking exclusive lock
                    fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    
                    # Write PID to lock file
                    lock_file.write(str(process_id))
                    lock_file.flush()
                    
                    is_primary_worker = True
                    app.logger.info(f"Acquired scheduler lock file, this worker (PID={process_id}) will run the scheduler")
                    print(f"SCHEDULER_LOCK: Worker PID={process_id} acquired lock and will run scheduler", file=sys.stdout)
                    sys.stdout.flush()
                    
                    # Clean up the lock file when the app exits
                    def release_lock():
                        try:
                            if lock_file:
                                fcntl.flock(lock_file, fcntl.LOCK_UN)
                                lock_file.close()
                                
                                # Only remove the lock file if it contains our PID
                                if os.path.exists(LOCK_FILE):
                                    with open(LOCK_FILE, 'r') as f:
                                        if str(process_id) == f.read().strip():
                                            os.unlink(LOCK_FILE)
                                            app.logger.info(f"Released scheduler lock file for PID={process_id}")
                                            print(f"SCHEDULER_INFO: Released scheduler lock for PID={process_id}", file=sys.stdout)
                                            sys.stdout.flush()
                        except Exception as e:
                            app.logger.error(f"Error releasing scheduler lock: {e}")
                            print(f"SCHEDULER_ERROR: Error releasing lock: {e}", file=sys.stdout)
                            sys.stdout.flush()
                    
                    atexit.register(release_lock)
                except IOError as e:
                    # Another worker got the lock first
                    app.logger.info(f"Failed to acquire lock file, another worker has the lock: {e}")
                    print(f"SCHEDULER_INFO: Worker PID={process_id} failed to acquire lock: {e}", file=sys.stdout)
                    sys.stdout.flush()
                    is_primary_worker = False
                    if lock_file:
                        lock_file.close()
        except Exception as e:
            app.logger.error(f"Error setting up scheduler lock: {e}")
            print(f"SCHEDULER_ERROR: Error setting up lock: {e}", file=sys.stdout)
            sys.stdout.flush()
        
        # Only start the scheduler in the primary worker
        if is_primary_worker:
            app.logger.info("Starting APScheduler in this worker process")
            try:
                # Initialize APScheduler
                scheduler.start()
                app.logger.info("APScheduler successfully started")
                
                # Create a flag to track if shutdown has already been initiated
                # This prevents duplicate shutdown calls and race conditions
                scheduler_shutdown_initiated = False
                
                # Register scheduler shutdown function
                def shutdown_scheduler():
                    nonlocal scheduler_shutdown_initiated
                    
                    # Prevent duplicate shutdown calls
                    if scheduler_shutdown_initiated:
                        app.logger.info("Scheduler shutdown already in progress, skipping duplicate call")
                        return
                        
                    scheduler_shutdown_initiated = True
                    
                    try:
                        app.logger.info("Shutting down APScheduler...")
                        print(f"SCHEDULER_SHUTDOWN: Worker PID={process_id} shutting down APScheduler", file=sys.stdout)
                        sys.stdout.flush()
                        
                        # Use a more graceful shutdown approach
                        # First pause the scheduler to prevent new job submissions
                        if scheduler.running:
                            scheduler.pause()
                            app.logger.info("APScheduler paused, waiting for running jobs to complete")
                            print(f"SCHEDULER_SHUTDOWN: Worker PID={process_id} paused APScheduler", file=sys.stdout)
                            sys.stdout.flush()
                        
                            # Now shutdown with wait=True but with a timeout handled manually
                            # This allows currently running jobs to finish (within reason)
                            timeout_seconds = 5  # Maximum time to wait for jobs to complete
                            start_time = time.time()
                            
                            # Set a shutdown timeout to avoid hanging indefinitely
                            scheduler.shutdown(wait=False)  # Start shutdown process without blocking
                            
                            # Wait for scheduler to finish but with a timeout
                            while scheduler.running and (time.time() - start_time) < timeout_seconds:
                                time.sleep(0.1)  # Short sleep to avoid CPU spinning
                                
                            if scheduler.running:
                                app.logger.warning("APScheduler shutdown timed out after waiting")
                                print(f"SCHEDULER_WARNING: Worker PID={process_id} APScheduler shutdown timed out", file=sys.stdout)
                            else:
                                app.logger.info("APScheduler shutdown complete")
                                print(f"SCHEDULER_SHUTDOWN: Worker PID={process_id} APScheduler shutdown complete", file=sys.stdout)
                        else:
                            app.logger.info("APScheduler not running, no need to shut down")
                            print(f"SCHEDULER_INFO: Worker PID={process_id} APScheduler not running", file=sys.stdout)
                            
                        sys.stdout.flush()
                    except Exception as e:
                        app.logger.error(f"Error during scheduler shutdown: {e}")
                        print(f"SCHEDULER_ERROR: Worker PID={process_id} APScheduler shutdown error: {str(e)}", file=sys.stdout)
                        sys.stdout.flush()
                
                # Register shutdown_scheduler with atexit for normal termination
                atexit.register(shutdown_scheduler)
                
                # Define a signal handler to shut down APScheduler when Gunicorn signals termination
                # This ensures we run our shutdown routine BEFORE the rest of the termination process
                def sigterm_handler(sig_num, frame):
                    app.logger.info(f"Received signal {sig_num}, shutting down APScheduler first")
                    print(f"SCHEDULER_SIGNAL: Worker PID={process_id} received signal {sig_num}, initiating early shutdown", file=sys.stdout)
                    sys.stdout.flush()
                    
                    # Execute scheduler shutdown routine first
                    shutdown_scheduler()
                    
                    # Continue with default signal handling after scheduler is shut down
                    # This allows a clean shutdown by not raising an exception here
                    
                # Register our handler for SIGTERM (sent by Gunicorn during graceful shutdown)
                signal.signal(signal.SIGTERM, sigterm_handler)
            except Exception as e:
                app.logger.error(f"Failed to start APScheduler: {e}")
        else:
            app.logger.info("APScheduler not started in this worker to avoid conflicts")


        # Initialize the worker pool (if not testing) - only on the primary worker
        if not app.testing:
            from . import worker_manager # Import here to avoid circular dependencies at top level
            
            # Only initialize worker pool on the primary scheduler worker
            if is_primary_worker:
                app.logger.info(f"Primary worker (PID={process_id}) initializing nmap worker pool")
                print(f"WORKER_POOL_INIT: Primary worker PID={process_id} initializing nmap worker pool", file=sys.stdout)
                sys.stdout.flush()
                worker_manager.initialize_worker_pool()
                app.logger.info(f"Primary worker (PID={process_id}) completed worker pool initialization")
                print(f"WORKER_POOL_INIT: Primary worker PID={process_id} completed worker pool initialization", file=sys.stdout)
                sys.stdout.flush()
            else:
                app.logger.info(f"Worker PID={process_id} is NOT the primary worker, skipping worker pool initialization")
                print(f"WORKER_POOL_INFO: Worker PID={process_id} is NOT the primary worker, skipping worker pool initialization", file=sys.stdout)
                sys.stdout.flush()

            # Ensure SQLite PRAGMAs are set up for the main engine by making an initial connection if needed.
            with app.app_context():
                if 'sqlite' in db.engine.url.drivername:
                    try:
                        with db.engine.connect() as connection:
                            connection.execute(text("SELECT 1")) # A simple query to ensure a connection is made
                        app.logger.info("SQLite PRAGMAs (WAL, busy_timeout) are configured via event listener. Tested main engine connection.")
                    except Exception as e:
                        app.logger.error(f"Error during initial SQLite PRAGMA setup test for main engine: {e}")

            # Add job for processing queued tasks
            from app.tasks.task_processor import process_queued_tasks
            if not scheduler.get_job('process_queued_nmap_tasks'):
                scheduler.add_job(
                    id='process_queued_nmap_tasks',
                    func=process_queued_tasks,
                    trigger='interval',
                    seconds=15,  # Run every 15 seconds
                    replace_existing=True, coalesce=True, max_instances=1
                )
            else:
                pass

            # Initialize scheduled tasks from the database, only when scheduler is first started and only by the primary worker
            # Import here to avoid circular imports
            if is_primary_worker:
                from app.tasks.scheduler_tasks import initialize_scheduled_tasks
                app.logger.info("Primary worker is initializing scheduled tasks...")
                print(f"SCHEDULER_INIT: Worker PID={process_id} is initializing scheduled tasks", file=sys.stdout)
                sys.stdout.flush()
                try:
                    with app.app_context(): # Ensure app context for DB operations within initialize_scheduled_tasks
                        initialize_scheduled_tasks()
                    app.logger.info("Scheduled tasks initialization complete.")
                    print(f"SCHEDULER_INIT: Worker PID={process_id} completed scheduled tasks initialization", file=sys.stdout)
                    sys.stdout.flush()
                except Exception as e:
                    app.logger.error(f"CRITICAL: Failed to initialize scheduled tasks during app startup: {str(e)}", exc_info=True)
                    print(f"SCHEDULER_ERROR: Worker PID={process_id} failed to initialize scheduled tasks: {str(e)}", file=sys.stdout)
                    sys.stdout.flush()
            else:
                app.logger.info(f"Worker PID={process_id} is NOT the primary scheduler, skipping task initialization")
                print(f"SCHEDULER_INFO: Worker PID={process_id} is NOT the primary scheduler, skipping task initialization", file=sys.stdout)
                sys.stdout.flush()
        
    # Register blueprints
    from app.controllers.auth import auth_bp
    from app.controllers.main import main_bp
    from app.controllers.targets import targets_bp
    from app.controllers.tasks import tasks_bp
    from app.controllers.reports import reports_bp
    from app.controllers.admin import admin_bp
    from app.controllers.profile import profile_bp
    from app.controllers.api import api_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(tasks_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(api_bp)
    
    # Register custom template filters
    from app.utils.filters import register_filters
    register_filters(app)
    
    # Register context processors for timezone information
    @app.context_processor
    def inject_timezone_info():
        """Inject timezone information into all templates"""
        tz = 'UTC'
        try:
            if current_user and current_user.is_authenticated:
                # Get the timezone directly from the database to ensure it's up to date
                from app.models.user import User
                user = User.query.get(current_user.id)
                if user and user.timezone:
                    tz = user.timezone
        
        except Exception as e:
            # Handle case when current_user is not available
            pass
        
        try:
            # Get current time in the user's timezone
            tz_obj = pytz.timezone(tz)
            now = datetime.now(tz_obj)
            
            # Format the timezone offset in a more readable way
            timezone_offset = now.strftime('%z')
            offset_hours = timezone_offset[0:3]
            offset_minutes = timezone_offset[3:5]
            
            # Only include minutes in the display if they're not zero
            if offset_minutes == '00':
                formatted_offset = f"{offset_hours}"
            else:
                formatted_offset = f"{offset_hours}:{offset_minutes}"
            
            timezone_display = f"UTC{formatted_offset}"
            
            return {
                'now': now,
                'user_timezone': tz,
                'timezone_display': timezone_display
            }
        except Exception as e:
            return {
                'user_timezone': 'UTC',
                'timezone_display': 'UTC'
            }
    
    # Ensure instance folders exist
    os.makedirs(app.config['NMAP_REPORTS_DIR'], exist_ok=True)
    
    # Add error handlers
    register_error_handlers(app)
    
    # Register CLI commands
    from cli_commands import register_commands
    register_commands(app)
    
    return app

def register_error_handlers(app):
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

# Import models to ensure they are registered with SQLAlchemy
from app.models import user, target, task, report
