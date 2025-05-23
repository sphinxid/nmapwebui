from celery import Celery
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def make_celery(app_name=__name__):
    # Create Celery instance
    celery = Celery(
        app_name,
        broker=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
        backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
        include=['app.tasks.nmap_tasks', 'app.tasks.task_processor']
    )
    
    # Configure Celery
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        beat_schedule={
            'process-queued-tasks': {
                'task': 'app.tasks.task_processor.process_queued_tasks',
                'schedule': 10.0,  # Run every 10 seconds to be more responsive
            },
        }
    )
    
    return celery

# Create the Celery instance
celery = make_celery()
