"""
Task processor module for handling queued tasks
"""
from app import db, create_app, scheduler
from app.models.task import ScanRun, ScanTask
from app.models.settings import SystemSettings
from celery import shared_task
from celery_config import celery
import logging
from datetime import datetime
import pytz
from sqlalchemy import case, and_

logger = logging.getLogger(__name__)

@shared_task
def process_queued_tasks():
    """
    Process queued tasks based on the maximum concurrent tasks setting
    This function is meant to be called periodically by Celery
    """
    app = create_app()
    
    with app.app_context():
        try:
            # Get the maximum concurrent tasks setting
            max_concurrent_tasks = SystemSettings.get_int('max_concurrent_tasks', 4)
            
            # Count currently running tasks
            running_tasks_count = ScanRun.query.filter(
                ScanRun.status == 'running'
            ).count()
            
            # If we're already at or over the limit, don't start any new tasks
            if running_tasks_count >= max_concurrent_tasks:
                logger.info(f"Already running {running_tasks_count} tasks (limit: {max_concurrent_tasks}). No new tasks will be started.")
                return
            
            # Calculate how many new tasks we can start
            available_slots = max_concurrent_tasks - running_tasks_count
            
            # Get all queued tasks
            queued_tasks_query = ScanRun.query.filter(ScanRun.status == 'queued')
            
            # Get the queued tasks directly - we'll prioritize based on started_at
            # which is now set to the scheduled run time for scheduled tasks
            queued_tasks_all = queued_tasks_query.order_by(ScanRun.started_at.asc()).all()
            
            # Log all queued tasks and their priority times
            if queued_tasks_all:
                logger.info(f"All queued tasks and their priority times:")
                for i, task in enumerate(queued_tasks_all):
                    scan_task = ScanTask.query.get(task.task_id)
                    is_scheduled = scan_task.is_scheduled if scan_task else False
                    task_type = "Scheduled" if is_scheduled else "Regular"
                    logger.info(f"  {i+1}. {task_type} Task - ScanRun ID: {task.id}, Task ID: {task.task_id}, Priority Time: {task.started_at}")
            
            # We don't need to join with ScanTask anymore since we're using started_at for prioritization
            # which is already set correctly for scheduled tasks
            
            # Current time in UTC
            now_utc = datetime.now(pytz.UTC)
            logger.info(f"Current UTC time: {now_utc.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Log all scheduled tasks and their next run times
            scheduled_tasks = ScanTask.query.filter_by(is_scheduled=True).all()
            if scheduled_tasks:
                logger.info(f"All scheduled tasks and their next run times:")
                for task in scheduled_tasks:
                    job_id = f"scan_task_{task.id}"
                    job = scheduler.get_job(job_id)
                    next_run = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job and job.next_run_time else 'Not scheduled'
                    logger.info(f"  Task ID: {task.id}, Name: {task.name}, Next run: {next_run}")
            else:
                logger.info("No scheduled tasks found in the database")
            
            # Tasks are already sorted by started_at which contains the priority time
            # Limit to available slots
            queued_tasks = queued_tasks_all[:available_slots]
            
            # Log final task selection
            if queued_tasks:
                logger.info(f"Final task selection (limited to {available_slots} slots):")
                for i, task in enumerate(queued_tasks):
                    scan_task = ScanTask.query.get(task.task_id)
                    is_scheduled = scan_task.is_scheduled if scan_task else False
                    task_type = "Scheduled" if is_scheduled else "Regular"
                    logger.info(f"  {i+1}. {task_type} Task - ScanRun ID: {task.id}, Task ID: {task.task_id}, Priority Time: {task.started_at}")
            else:
                logger.info("No tasks selected for execution")
            
            # Start each task
            for task in queued_tasks:
                logger.info(f"Starting queued task: ScanRun ID {task.id} for Task ID {task.task_id}")
                
                # Update the task status to 'running' in the database
                task.status = 'running'
                task.started_at = datetime.utcnow()
                db.session.commit()
                
                # Send the task to Celery
                celery.send_task('app.tasks.nmap_tasks.run_nmap_scan', args=[task.id, task.task_id])
                
            if queued_tasks:
                logger.info(f"Started {len(queued_tasks)} queued tasks. {running_tasks_count + len(queued_tasks)}/{max_concurrent_tasks} concurrent tasks now running.")
            
        except Exception as e:
            logger.error(f"Error processing queued tasks: {str(e)}")
