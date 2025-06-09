#!/usr/bin/env python3
"""
Script to clean up stuck scan tasks in the nmapwebui application.
This script identifies tasks that are stuck in 'running' or 'queued' state
and marks them as 'failed'.

Usage:
    python cleanup_stuck_tasks.py [--hours HOURS] [--dry-run]

Options:
    --hours HOURS    Consider tasks older than HOURS hours as stuck (default: 2)
    --dry-run        Show what would be done without making changes
"""

import os
import sys
import argparse
from datetime import datetime, timedelta
import json

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def parse_args():
    parser = argparse.ArgumentParser(description='Clean up stuck scan tasks')
    parser.add_argument('--hours', type=int, default=2,
                        help='Consider tasks older than HOURS hours as stuck (default: 2)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without making changes')
    return parser.parse_args()

def cleanup_stuck_tasks(hours=2, dry_run=False):
    # Import app and models here to avoid circular imports
    from app import create_app, db
    from app.models.task import ScanRun
    
    app = create_app()
    
    with app.app_context():
        # Calculate the cutoff time
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Find stuck tasks
        stuck_tasks = ScanRun.query.filter(
            ScanRun.status.in_(['starting', 'running', 'queued']),
            ScanRun.started_at < cutoff_time
        ).all()
        
        if not stuck_tasks:
            print(f"No stuck tasks found older than {hours} hours.")
            return
        
        print(f"Found {len(stuck_tasks)} stuck tasks:")
        
        for task in stuck_tasks:
            task_info = {
                'id': task.id,
                'task_id': task.task_id,
                'status': task.status,
                'started_at': task.started_at.isoformat() if task.started_at else None,
                'nmap_pid': task.nmap_pid
            }
            
            print(f"Task {task.id}: {json.dumps(task_info, indent=2)}")
            
            if not dry_run:
                # Update the task status
                task.status = 'failed'
                task.completed_at = datetime.utcnow()
                task.notes = f"Marked as failed by cleanup script at {datetime.utcnow().isoformat()}"
                
                # If the task has an Nmap PID, attempt to kill the process
                if task.nmap_pid:
                    try:
                        import signal
                        os.kill(task.nmap_pid, signal.SIGKILL)
                        print(f"  Killed process with PID {task.nmap_pid}")
                    except ProcessLookupError:
                        print(f"  Process with PID {task.nmap_pid} not found")
                    except Exception as e:
                        print(f"  Error killing process: {str(e)}")
                
                print(f"  Updated task {task.id} status to 'failed'")
        
        if not dry_run:
            # Commit the changes
            db.session.commit()
            print(f"Successfully updated {len(stuck_tasks)} tasks.")
        else:
            print(f"Dry run: would have updated {len(stuck_tasks)} tasks.")

if __name__ == '__main__':
    args = parse_args()
    cleanup_stuck_tasks(hours=args.hours, dry_run=args.dry_run)
