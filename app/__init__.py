from flask import Flask, render_template, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import os
import pytz
import atexit
from datetime import datetime
from config import Config
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
import logging as std_logging

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
    
        # Initialize APScheduler
        scheduler.start()

        # Register scheduler shutdown
        # wait=False ensures atexit doesn't block indefinitely if jobs are stuck
        atexit.register(lambda: scheduler.shutdown(wait=False))

        # Initialize the worker pool (if not testing)
        if not app.testing:
            from . import worker_manager # Import here to avoid circular dependencies at top level
            worker_manager.initialize_worker_pool()

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

            # Initialize scheduled tasks from the database, only when scheduler is first started
            # Import here to avoid circular imports
            from app.tasks.scheduler_tasks import initialize_scheduled_tasks
            app.logger.info("Attempting to initialize scheduled tasks...")
            try:
                with app.app_context(): # Ensure app context for DB operations within initialize_scheduled_tasks
                    initialize_scheduled_tasks()
                app.logger.info("Scheduled tasks initialization attempt complete.")
            except Exception as e:
                app.logger.error(f"CRITICAL: Failed to initialize scheduled tasks during app startup: {str(e)}", exc_info=True)
        
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
