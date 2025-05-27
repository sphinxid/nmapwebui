from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user
import functools
import logging
import os
import redis
import inspect

logger = logging.getLogger(__name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function



def redis_task_lock(key_template=None, expire=300, blocking=False, blocking_timeout=None):
    """
    Decorator to ensure a Celery task does not run concurrently.
    :param key_template: str, template for redis key. Can use {task_name} and argument names from the decorated function.
    :param expire: int, lock expiration in seconds.
    :param blocking: bool, if True, wait for lock; else, fail fast.
    :param blocking_timeout: float, max seconds to wait for lock if blocking.
    """
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    redis_client = redis.from_url(CELERY_BROKER_URL)
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            task_name = func.__name__

            # Prepare context for key formatting
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            all_args_dict = bound_args.arguments

            # If 'self' is in args (bound method from Celery task), remove it from dict for key formatting
            # as it's not typically part of a user-defined key template for uniqueness.
            if 'self' in all_args_dict:
                del all_args_dict['self']

            if not key_template:
                # Fallback to old behavior if no template (based on hash of all args)
                # This path is not expected for the nmap_task use case but kept for general compatibility.
                temp_args = {k: v for k, v in all_args_dict.items()}
                args_repr = repr(tuple(bound_args.args)) + repr(temp_args) # Use bound_args.args for positional, and cleaned all_args_dict for kwargs
                args_hash = str(abs(hash(args_repr)))
                lock_key_val = f"celery_lock:{task_name}:{args_hash}"
            else:
                try:
                    lock_key_val = key_template.format(task_name=task_name, **all_args_dict)
                except KeyError as e:
                    logger.error(f"KeyError in key_template for task {task_name}: {e}. "
                                 f"Ensure key_template variables match function arguments. "
                                 f"Available args for template: {list(all_args_dict.keys())}")
                    raise ValueError(f"Invalid key_template for task {task_name}. Missing argument in template: {e}") from e

            lock = redis_client.lock(lock_key_val, timeout=expire)
            got_lock = False
            try:
                got_lock = lock.acquire(blocking=blocking, blocking_timeout=blocking_timeout)
                if got_lock:
                    logger.info(f"Acquired lock {lock_key_val} for task {task_name}")
                    return func(*args, **kwargs)
                else:
                    logger.warning(f"Could not acquire lock {lock_key_val} for task {task_name}, skipping execution.")
                    return None # Task did not run
            finally:
                if got_lock:
                    lock.release()
                    logger.info(f"Released lock {lock_key_val} for task {task_name}")
        return wrapper
    return decorator
