#!/usr/bin/env python3
"""
NmapWebUI Zombie Task Cleanup
-----------------------------
This script checks for 'running' scan tasks whose nmap or masscan processes are no longer active
and marks them as 'failed'. This helps clean up zombie tasks that might be stuck.
"""
import os
import sys
import subprocess
import psutil
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.task import ScanRun, TaskLock # Import TaskLock
import pytz

def get_status_color(status):
    """Return ANSI color code based on status"""
    colors = {
        'queued': '\033[33m',  # Yellow
        'starting': '\033[35m',  # Magenta
        'running': '\033[36m',  # Cyan
        'completed': '\033[32m',  # Green
        'failed': '\033[31m'    # Red
    }
    return colors.get(status, '\033[0m')

def reset_color():
    """Reset ANSI color"""
    return '\033[0m'

def is_scan_process_running(pid, scan_engine='nmap'):
    """Check if a process with the given PID is running and is a scan process (nmap or masscan)"""
    if pid is None:
        return False
        
    try:
        # Check if process exists
        process = psutil.Process(pid)
        process_cmdline = ' '.join(process.cmdline()).lower()
        process_name = process.name().lower()
        
        # Check if it's the specified scan engine process
        if scan_engine == 'masscan':
            return 'masscan' in process_name or 'masscan' in process_cmdline
        else:  # Default to nmap
            return 'nmap' in process_name or 'nmap' in process_cmdline
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False

def extract_scan_pids(scan_engine='both'):
    """Find running scan processes (nmap, masscan, or both) and return their PIDs"""
    try:
        scan_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.name().lower()
                proc_cmdline = ' '.join(proc.cmdline()).lower() if proc.cmdline() else ''
                
                # Check for nmap processes
                if (scan_engine == 'nmap' or scan_engine == 'both') and \
                   ('nmap' in proc_name or 'nmap' in proc_cmdline):
                    scan_processes.append({'pid': proc.pid, 'engine': 'nmap'})
                
                # Check for masscan processes
                if (scan_engine == 'masscan' or scan_engine == 'both') and \
                   ('masscan' in proc_name or 'masscan' in proc_cmdline):
                    scan_processes.append({'pid': proc.pid, 'engine': 'masscan'})
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return scan_processes
    except Exception as e:
        print(f"Error checking for scan processes: {str(e)}")
        return []

def main():
    app = create_app()
    
    with app.app_context():
        # Get current time in UTC
        now_utc = datetime.now(pytz.UTC)
        print(f"Current UTC time: {now_utc.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Get all running and starting scan runs
        running_scans = ScanRun.query.filter(ScanRun.status.in_(['starting', 'running'])).all()
        
        print("\n" + "=" * 80)
        print(f"NmapWebUI Zombie Task Cleanup - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        if not running_scans:
            print("\nNo running scan tasks found in the database.")
            return
        
        print(f"\nFound {len(running_scans)} running scan task(s) in the database.")
        
        # Get all running scan processes (both nmap and masscan)
        running_scan_processes = extract_scan_pids('both')
        
        # Group processes by scan engine
        nmap_processes = [p for p in running_scan_processes if p['engine'] == 'nmap']
        masscan_processes = [p for p in running_scan_processes if p['engine'] == 'masscan']
        
        print(f"Found {len(nmap_processes)} running nmap processes and {len(masscan_processes)} running masscan processes.")
        
        if nmap_processes:
            print(f"Running nmap PIDs: {', '.join(map(lambda p: str(p['pid']), nmap_processes))}")
        if masscan_processes:
            print(f"Running masscan PIDs: {', '.join(map(lambda p: str(p['pid']), masscan_processes))}")
        
        # Check each running scan
        zombie_count = 0
        for scan in running_scans:
            print("\n" + "-" * 80)
            print(f"Scan Run ID: {scan.id} | Task ID: {scan.task_id}")
            print(f"Status: {get_status_color(scan.status)}{scan.status}{reset_color()}")
            print(f"Started At: {scan.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Check how long the scan has been running
            run_time = now_utc - scan.started_at.replace(tzinfo=pytz.UTC)
            print(f"Running for: {run_time}")
            
            # Determine scan engine from task
            scan_engine = 'nmap'  # Default to nmap
            try:
                # Get the task to determine scan engine
                task = scan.task
                if hasattr(task, 'scan_engine') and task.scan_engine:
                    scan_engine = task.scan_engine
                    print(f"Scan engine: {scan_engine}")
                else:
                    print(f"No scan engine specified, assuming nmap")
            except Exception as e:
                print(f"Error determining scan engine: {str(e)}")
            
            # Check if this is a zombie task
            is_zombie = False
            final_status_message = f"Scan run {scan.id} appears to be running normally or is not in a state to be checked for zombie Nmap process."

            if scan.nmap_pid is not None:
                print(f"Stored scan PID: {scan.nmap_pid}")
                if not is_scan_process_running(scan.nmap_pid, scan_engine):
                    print(f"ZOMBIE DETECTED: Stored {scan_engine} PID {scan.nmap_pid} is no longer running")
                    is_zombie = True
                else:
                    # PID stored and process is running
                    final_status_message = f"{scan_engine.capitalize()} process with PID {scan.nmap_pid} is still running for ScanRun {scan.id}."
            else: # No PID stored for this scan
                print(f"No {scan_engine} PID stored for this scan (ScanRun ID: {scan.id}).")
                grace_period_no_pid = timedelta(minutes=2) # Shorter grace period for PID-less runs
                if scan.status in ['starting', 'running']:
                    if run_time > grace_period_no_pid:
                        print(f"ZOMBIE DETECTED: Scan (ID: {scan.id}) is '{scan.status}' for {run_time} without a PID (threshold: {grace_period_no_pid}).")
                        is_zombie = True
                    else:
                        # Status is 'starting' or 'running', no PID, but within grace period
                        final_status_message = f"Scan run {scan.id} is '{scan.status}' without a PID but within grace period ({run_time} < {grace_period_no_pid}). Monitoring."
                # If status is 'queued' or other, it's not a zombie Nmap process yet.

            # Mark as failed if it's a zombie
            if is_zombie:
                zombie_count += 1
                print(f"Marking scan run {scan.id} as FAILED (zombie task)")
                scan.status = 'failed'
                scan.completed_at = datetime.utcnow()
                # Commit the status change for the scan run first
                db.session.commit()
                print(f"Scan run {scan.id} has been marked as failed.")

                # Now, attempt to remove the associated task lock
                lock_key_to_delete = f"lock:run_nmap_scan:task_id_{scan.task_id}"
                try:
                    task_lock_entry = TaskLock.query.get(lock_key_to_delete)
                    if task_lock_entry:
                        db.session.delete(task_lock_entry)
                        db.session.commit()
                        print(f"Successfully deleted task lock: {lock_key_to_delete}")
                    else:
                        print(f"No task lock found with key: {lock_key_to_delete} (already released or never existed for this zombie)")
                except Exception as e_lock_delete:
                    db.session.rollback()
                    print(f"Error deleting task lock {lock_key_to_delete}: {str(e_lock_delete)}")
            else:
                print(final_status_message)
        
        print("\n" + "=" * 80)
        print(f"Cleanup complete. Found and fixed {zombie_count} zombie task(s).")
        print("=" * 80)

if __name__ == "__main__":
    main()
