import os
from app import create_app, celery
from app.tasks.nmap_tasks import run_nmap_scan  # Import the task explicitly
from app.tasks.task_processor import process_queued_tasks

# Create a Flask application context
flask_app = create_app()
app = flask_app.app_context()
app.push()

# Configure Celery
celery.conf.broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
celery.conf.result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

# Print configuration for debugging
print(f"Broker URL: {celery.conf.broker_url}")
print(f"Result Backend: {celery.conf.result_backend}")
print(f"Registered tasks: {list(celery.tasks.keys())}")

if __name__ == '__main__':
    celery.worker_main(['worker', '--loglevel=info'])
