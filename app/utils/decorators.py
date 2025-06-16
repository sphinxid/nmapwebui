from functools import wraps
from flask import flash, redirect, url_for, current_app # current_app is already here
from flask_login import current_user
import functools
import logging
import os
# import redis # Removed
import inspect
from sqlalchemy.exc import IntegrityError # Added

from app import db, create_app # Assuming db and create_app are exposed from your 'app' package
from app.models.task import ScanRun, TaskLock # Modified

logger = logging.getLogger(__name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function





def sqlite_task_lock(key_template=None, expire=300): # expire is kept for API consistency but not strictly used by SQLite lock yet
    """
    Decorator to ensure a task does not run concurrently using an SQLite-based lock.
    :param key_template: str, template for the lock key. Can use {task_name} and argument names.
    :param expire: int, lock expiration in seconds (currently informational, not enforced by DB).
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            task_name = func.__name__

            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            all_args_dict = bound_args.arguments

            if 'self' in all_args_dict: # Compatibility with potential bound methods
                del all_args_dict['self']

            if not key_template:
                # Simplified fallback if no template (consider if this is needed or should raise error)
                args_repr = repr(tuple(bound_args.args)) + repr(all_args_dict)
                args_hash = str(abs(hash(args_repr)))
                lock_key_val = f"sqlite_lock:{task_name}:{args_hash}"
            else:
                try:
                    lock_key_val = key_template.format(task_name=task_name, **all_args_dict)
                except KeyError as e:
                    logger.error(
                        "KeyError in key_template for task %s: %s. Ensure key_template variables match function arguments. Available args: %s",
                        task_name, e, list(all_args_dict.keys())
                    )
                    raise ValueError(f"Invalid key_template for task {task_name}. Missing argument: {e}") from e
            
            lock_acquired = False
            # Ensure we are within an application context for database operations
            # Use current_app if available (e.g. in a Flask request context), else create a new app context.
            # This is crucial for background tasks that might run outside a request.
            app_for_context = current_app._get_current_object() if current_app else None
            if not app_for_context:
                temp_app = create_app()
                app_context_manager = temp_app.app_context()
            else:
                app_context_manager = app_for_context.app_context()

            with app_context_manager:
                try:
                    # Attempt to acquire the lock
                    new_lock = TaskLock(lock_key=lock_key_val)
                    db.session.add(new_lock)
                    db.session.commit()
                    lock_acquired = True
                    logger.info("Acquired SQLite lock %s for task %s", lock_key_val, task_name)
                    
                    # Execute the decorated function
                    result = func(*args, **kwargs)
                    return result
                
                except IntegrityError:
                    # Lock is already held
                    db.session.rollback() # Rollback the failed commit
                    logger.warning("Could not acquire SQLite lock %s for task %s, skipping execution.", lock_key_val, task_name)
                    return None # Task did not run
                
                finally:
                    if lock_acquired:
                        # Release the lock
                        try:
                            # Query within the same session that created/committed the lock
                            lock_to_delete = db.session.query(TaskLock).get(lock_key_val)
                            if lock_to_delete:
                                db.session.delete(lock_to_delete)
                                db.session.commit()
                                logger.info("Released SQLite lock %s for task %s", lock_key_val, task_name)
                            else:
                                logger.warning("Attempted to release SQLite lock %s but it was not found post-commit.", lock_key_val)
                        except Exception as e_release:
                            logger.error("Error releasing SQLite lock %s: %s", lock_key_val, e_release)
                            db.session.rollback() # Rollback on error during release
        return wrapper
    return decorator