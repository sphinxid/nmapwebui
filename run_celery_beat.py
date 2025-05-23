#!/usr/bin/env python3
"""
NmapWebUI Celery Beat Scheduler
-------------------------------
This script runs the Celery beat scheduler for periodic tasks in NmapWebUI.
It handles checking for queued tasks and scheduling them to run.
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import Celery configuration
from celery_config import celery

# Print configuration for debugging
print("NmapWebUI Celery Beat Scheduler")
print("-" * 35)
print(f"Broker URL: {celery.conf.broker_url}")
print(f"Result Backend: {celery.conf.result_backend}")
print(f"Beat Schedule: {celery.conf.beat_schedule}")
print("-" * 35)

if __name__ == '__main__':
    try:
        # Start the Celery beat scheduler
        celery.start(argv=['beat', '--loglevel=info'])
    except KeyboardInterrupt:
        print("\nCelery beat scheduler stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError starting Celery beat scheduler: {str(e)}")
        sys.exit(1)
