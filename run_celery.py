#!/usr/bin/env python3
"""
NmapWebUI Celery Worker Runner
------------------------------
This script runs the Celery worker for processing background tasks in NmapWebUI.
It handles Nmap scans and other asynchronous operations.
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import Celery configuration and tasks
from celery_config import celery
from app.tasks.nmap_tasks import run_nmap_scan  # Import the task explicitly
from app.tasks.task_processor import process_queued_tasks  # Import the task processor

# Print configuration for debugging
print("NmapWebUI Celery Worker")
print("-" * 30)
print(f"Broker URL: {celery.conf.broker_url}")
print(f"Result Backend: {celery.conf.result_backend}")
print(f"Registered tasks: {list(celery.tasks.keys())}")
print("-" * 30)

if __name__ == '__main__':
    try:
        # Start the Celery worker
        celery.worker_main(['worker', '--loglevel=info'])
    except KeyboardInterrupt:
        print("\nCelery worker stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError starting Celery worker: {str(e)}")
        sys.exit(1)
