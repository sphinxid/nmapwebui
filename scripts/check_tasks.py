#!/usr/bin/env python3
"""
Script to check if Celery tasks are properly registered and can be called.
"""
import os
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import Celery configuration
from celery_config import celery

# Try to import the tasks directly
try:
    from app.tasks.nmap_tasks import run_nmap_scan
    print("✅ Successfully imported run_nmap_scan")
except ImportError as e:
    print(f"❌ Failed to import run_nmap_scan: {e}")

try:
    from app.tasks.masscan_tasks import run_masscan_scan
    print("✅ Successfully imported run_masscan_scan")
except ImportError as e:
    print(f"❌ Failed to import run_masscan_scan: {e}")

# Print all registered tasks
print("\nRegistered tasks in Celery:")
for task_name in sorted(celery.tasks.keys()):
    print(f"- {task_name}")

# Check if our specific tasks are registered
print("\nChecking for specific tasks:")
if 'app.tasks.nmap_tasks.run_nmap_scan' in celery.tasks:
    print("✅ run_nmap_scan is registered")
else:
    print("❌ run_nmap_scan is NOT registered")

if 'app.tasks.masscan_tasks.run_masscan_scan' in celery.tasks:
    print("✅ run_masscan_scan is registered")
else:
    print("❌ run_masscan_scan is NOT registered")

# Try to call the tasks (without actually executing them)
print("\nTrying to inspect tasks:")
try:
    task_signature = run_nmap_scan.signature((0,), immutable=True)
    print(f"✅ run_nmap_scan signature: {task_signature}")
except Exception as e:
    print(f"❌ Error creating run_nmap_scan signature: {e}")

try:
    task_signature = run_masscan_scan.signature((0,), immutable=True)
    print(f"✅ run_masscan_scan signature: {task_signature}")
except Exception as e:
    print(f"❌ Error creating run_masscan_scan signature: {e}")

print("\nDone!")
