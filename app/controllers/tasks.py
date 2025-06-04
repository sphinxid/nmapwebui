from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import login_required, current_user
from app import db, celery
from app.models.task import ScanTask, ScanRun
from app.models.target import TargetGroup
from app.models.settings import SystemSettings
from app.models.report import ScanReport, HostFinding, PortFinding
from app.utils.forms import ScanTaskForm, ScheduleForm
from app.tasks.nmap_tasks import run_nmap_scan
from app.tasks.scheduler_tasks import schedule_task, unschedule_task
from app.utils.timezone_utils import convert_utc_to_local, convert_local_to_utc, get_user_timezone, format_datetime, get_timezone_display_name
from app.utils.sanitize import sanitize_form_data, sanitize_nmap_command
from app.utils.validators import validate_nmap_args
from datetime import datetime, timedelta
import json
import pytz
import sqlalchemy
from sqlalchemy import func

tasks_bp = Blueprint('tasks', __name__, url_prefix='/tasks')

@tasks_bp.route('/')
@tasks_bp.route('/page/<int:page>')
@login_required
def index(page=1):
    # Get pagination settings from system settings
    per_page = SystemSettings.get_int('pagination_rows', 20)

    # Get search query from request
    search = request.args.get('search', '', type=str).strip()

    # Build base query
    query = ScanTask.query.filter_by(user_id=current_user.id)
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(ScanTask.name.ilike(search_pattern))
    all_scan_tasks = query.all()

    for task in all_scan_tasks:
        latest_run = ScanRun.query.filter_by(task_id=task.id).order_by(ScanRun.id.desc()).first()
        task.latest_run = latest_run
        task.open_ports_count = 0
        if latest_run and latest_run.status == 'completed':
            report = ScanReport.query.filter_by(scan_run_id=latest_run.id).first()
            if report:
                open_ports_count = db.session.query(func.count(PortFinding.id)).\
                    join(HostFinding, HostFinding.id == PortFinding.host_id).\
                    filter(HostFinding.report_id == report.id).\
                    filter(PortFinding.state == 'open').scalar()
                task.open_ports_count = open_ports_count or 0

    all_scan_tasks.sort(key=lambda x: x.latest_run.id if x.latest_run else 0, reverse=True)
    total_tasks = len(all_scan_tasks)
    total_pages = (total_tasks + per_page - 1) // per_page

    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages

    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    scan_tasks = all_scan_tasks[start_idx:end_idx]

    return render_template('tasks/index.html',
                          title='Scan Tasks',
                          scan_tasks=scan_tasks,
                          ScanRun=ScanRun,
                          pagination={
                              'page': page,
                              'per_page': per_page,
                              'total_pages': total_pages,
                              'total_items': total_tasks
                          },
                          search=search)


@tasks_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = ScanTaskForm()

    # Get target groups for the current user
    target_groups = TargetGroup.query.filter_by(user_id=current_user.id).all()
    form.target_groups.choices = [(tg.id, tg.name) for tg in target_groups]

    if form.validate_on_submit():
        # Sanitize form data
        form_data = sanitize_form_data({
            'name': form.name.data,
            'description': form.description.data,
            'scan_profile': form.scan_profile.data,
            'custom_args': form.custom_args.data,
            'max_reports': form.max_reports.data if not form.use_global_max_reports.data else None
        })

        # Validate Nmap arguments again as an extra security measure
        if form_data['scan_profile'] == 'custom' and form_data['custom_args']:
            is_valid, message = validate_nmap_args(form_data['custom_args'])
            if not is_valid:
                flash(f'Invalid Nmap arguments: {message}', 'danger')
                return render_template('tasks/create.html', title='Create Scan Task', form=form)

        # Create new scan task
        scan_task = ScanTask(
            name=form_data['name'],
            description=form_data['description'],
            scan_profile=form_data['scan_profile'],
            custom_args=form_data['custom_args'],
            user_id=current_user.id,
            use_global_max_reports=form.use_global_max_reports.data,
            max_reports=form_data['max_reports']
        )

        # Add target groups
        for tg_id in form.target_groups.data:
            target_group = TargetGroup.query.get(tg_id)
            if target_group and target_group.user_id == current_user.id:
                scan_task.target_groups.append(target_group)

        db.session.add(scan_task)
        db.session.commit()

        flash('Scan task created successfully!', 'success')

        # Run the scan immediately if requested
        if form.run_now.data:
            return redirect(url_for('tasks.run', id=scan_task.id))

        return redirect(url_for('tasks.index'))

    return render_template('tasks/create.html', title='Create Scan Task', form=form)

@tasks_bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    scan_task = ScanTask.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    form = ScanTaskForm(obj=scan_task)

    # Get target groups for the current user
    target_groups = TargetGroup.query.filter_by(user_id=current_user.id).all()
    form.target_groups.choices = [(tg.id, tg.name) for tg in target_groups]

    # Pre-select current target groups and settings
    if request.method == 'GET':
        form.target_groups.data = [tg.id for tg in scan_task.target_groups]
        form.use_global_max_reports.data = scan_task.use_global_max_reports
        if not scan_task.use_global_max_reports and scan_task.max_reports is not None:
            form.max_reports.data = scan_task.max_reports
        else:
            form.max_reports.data = SystemSettings.get_int('max_reports_per_task', 15)

    if form.validate_on_submit():
        # Sanitize form data
        form_data = sanitize_form_data({
            'name': form.name.data,
            'description': form.description.data,
            'scan_profile': form.scan_profile.data,
            'custom_args': form.custom_args.data,
            'max_reports': form.max_reports.data if not form.use_global_max_reports.data else None
        })

        # Validate Nmap arguments again as an extra security measure
        if form_data['scan_profile'] == 'custom' and form_data['custom_args']:
            is_valid, message = validate_nmap_args(form_data['custom_args'])
            if not is_valid:
                flash(f'Invalid Nmap arguments: {message}', 'danger')
                return render_template('tasks/edit.html', title='Edit Scan Task', form=form, scan_task=scan_task)

        scan_task.name = form_data['name']
        scan_task.description = form_data['description']
        scan_task.scan_profile = form_data['scan_profile']
        scan_task.custom_args = form_data['custom_args']
        scan_task.use_global_max_reports = form.use_global_max_reports.data
        scan_task.max_reports = form_data['max_reports']

        # Update target groups
        scan_task.target_groups = []
        for tg_id in form.target_groups.data:
            target_group = TargetGroup.query.get(tg_id)
            if target_group and target_group.user_id == current_user.id:
                scan_task.target_groups.append(target_group)

        db.session.commit()

        flash('Scan task updated successfully!', 'success')

        # Run the scan immediately if requested
        if form.run_now.data:
            return redirect(url_for('tasks.run', id=scan_task.id))

        return redirect(url_for('tasks.index'))

    return render_template('tasks/edit.html', title='Edit Scan Task', form=form, scan_task=scan_task)

@tasks_bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    scan_task = ScanTask.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    # Unschedule the task if it's scheduled
    if scan_task.is_scheduled:
        unschedule_task(scan_task.id)

    db.session.delete(scan_task)
    db.session.commit()

    flash('Scan task deleted successfully!', 'success')
    return redirect(url_for('tasks.index'))

@tasks_bp.route('/<int:id>/run')
@login_required
def run(id):
    scan_task = ScanTask.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    # Sanitize the custom arguments if present
    if scan_task.scan_profile == 'custom' and scan_task.custom_args:
        # Validate and sanitize Nmap arguments
        is_valid, message = validate_nmap_args(scan_task.custom_args)
        if not is_valid:
            flash(f'Cannot run scan: {message}', 'danger')
            return redirect(url_for('tasks.view', id=scan_task.id))

        # Update with sanitized version
        sanitized_args = sanitize_nmap_command(scan_task.custom_args)
        if sanitized_args != scan_task.custom_args:
            scan_task.custom_args = sanitized_args
            db.session.commit()

    # Check if there are any active runs for this task
    active_run = ScanRun.query.filter(
        ScanRun.task_id == scan_task.id,
        ScanRun.status.in_(['queued', 'running'])
    ).first()

    if active_run:
        flash('This task is already running!', 'warning')
        return redirect(url_for('tasks.view', id=scan_task.id))

    # Check the maximum concurrent tasks setting
    max_concurrent_tasks = SystemSettings.get_int('max_concurrent_tasks', 4)

    # Count currently running tasks
    active_tasks_count = ScanRun.query.filter(
        ScanRun.status.in_(['running'])
    ).count()

    # Determine if we should start the task immediately or queue it
    should_start_immediately = active_tasks_count < max_concurrent_tasks

    # Create a new scan run
    scan_run = ScanRun(
        task_id=scan_task.id,
        status='queued'
    )

    try:
        db.session.add(scan_run)
        db.session.commit()

        # Start the Nmap scan immediately only if under the limit
        if should_start_immediately:
            from celery_config import celery
            # Pass the scan_task.id as the second argument (scan_task_id_for_lock)
            celery.send_task('app.tasks.nmap_tasks.run_nmap_scan', args=[scan_run.id, scan_task.id])
            flash('Scan started successfully!', 'success')
        else:
            flash(f'Scan queued successfully. It will start automatically when resources are available. Current limit: {max_concurrent_tasks} concurrent tasks.', 'info')
    except sqlalchemy.exc.SQLAlchemyError as e:
        db.session.rollback()
        flash(f'Error starting scan: {str(e)}', 'danger')

    return redirect(url_for('tasks.view', id=scan_task.id))

@tasks_bp.route('/<int:id>/view')
@login_required
def view(id):
    scan_task = ScanTask.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    # Get the maximum number of reports/history items to keep for this task
    max_history = scan_task.get_max_reports()

    # Get scan runs for this task and order by ID in descending order
    # Since IDs are auto-incremented, this will show the most recent runs first
    # Limit the number of scan runs to the max_history setting
    scan_runs = ScanRun.query.filter_by(task_id=scan_task.id).order_by(ScanRun.id.desc()).limit(max_history).all()

    # Get open port counts for each completed scan run
    for run in scan_runs:
        run.open_ports_count = 0
        if run.status == 'completed' and run.report:
            # Count all open ports across all hosts for this report
            open_ports_count = db.session.query(func.count(PortFinding.id)).\
                join(HostFinding, HostFinding.id == PortFinding.host_id).\
                filter(HostFinding.report_id == run.report.id).\
                filter(PortFinding.state == 'open').scalar()
            run.open_ports_count = open_ports_count or 0

    return render_template(
        'tasks/view.html',
        title=f'Scan Task: {scan_task.name}',
        scan_task=scan_task,
        scan_runs=scan_runs
    )

@tasks_bp.route('/<int:id>/schedule', methods=['GET', 'POST'])
@login_required
def schedule(id):
    scan_task = ScanTask.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    form = ScheduleForm()

    # Set the current timezone field
    user_timezone = get_user_timezone()
    form.current_timezone.data = f"{user_timezone} (UTC{datetime.now(pytz.timezone(user_timezone)).strftime('%z')})"

    # Pre-populate form with existing schedule data
    if request.method == 'GET' and scan_task.is_scheduled:
        form.schedule_type.data = scan_task.schedule_type
        schedule_data = scan_task.get_schedule_data()

        if scan_task.schedule_type == 'daily':
            form.hour.data = schedule_data.get('hour', 0)
            form.minute.data = schedule_data.get('minute', 0)
        elif scan_task.schedule_type == 'weekly':
            form.day_of_week.data = schedule_data.get('day_of_week', 0)
            form.hour.data = schedule_data.get('hour', 0)
            form.minute.data = schedule_data.get('minute', 0)
        elif scan_task.schedule_type == 'monthly':
            form.day.data = schedule_data.get('day', 1)
            form.hour.data = schedule_data.get('hour', 0)
            form.minute.data = schedule_data.get('minute', 0)
        elif scan_task.schedule_type == 'interval':
            form.hours.data = schedule_data.get('hours', 24)

    if form.validate_on_submit():
        schedule_type = form.schedule_type.data

        # Build schedule data based on schedule type
        schedule_data = {}

        if schedule_type == 'daily':
            schedule_data = {
                'hour': form.hour.data,
                'minute': form.minute.data
            }
        elif schedule_type == 'weekly':
            schedule_data = {
                'day_of_week': form.day_of_week.data,
                'hour': form.hour.data,
                'minute': form.minute.data
            }
        elif schedule_type == 'monthly':
            schedule_data = {
                'day': form.day.data,
                'hour': form.hour.data,
                'minute': form.minute.data
            }
        elif schedule_type == 'interval':
            schedule_data = {
                'hours': form.hours.data
            }

        # Update task with schedule information
        scan_task.is_scheduled = True
        scan_task.schedule_type = schedule_type
        scan_task.set_schedule_data(schedule_data)
        db.session.commit()

        # Schedule the task
        schedule_task(scan_task)

        flash('Task scheduled successfully!', 'success')
        return redirect(url_for('tasks.view', id=scan_task.id))

    return render_template(
        'tasks/schedule.html',
        title=f'Schedule Task: {scan_task.name}',
        form=form,
        scan_task=scan_task
    )

@tasks_bp.route('/<int:id>/unschedule', methods=['POST'])
@login_required
def unschedule(id):
    scan_task = ScanTask.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    if not scan_task.is_scheduled:
        flash('This task is not scheduled.', 'warning')
        return redirect(url_for('tasks.view', id=scan_task.id))

    # Unschedule the task
    unschedule_task(scan_task.id)

    # Update task
    scan_task.is_scheduled = False
    scan_task.schedule_type = None
    scan_task.schedule_data = None
    db.session.commit()

    flash('Task unscheduled successfully!', 'success')
    return redirect(url_for('tasks.view', id=scan_task.id))

@tasks_bp.route('/api/status/<int:run_id>')
@login_required
def api_status(run_id):
    scan_run = ScanRun.query.join(ScanTask).filter(
        ScanRun.id == run_id,
        ScanTask.user_id == current_user.id
    ).first_or_404()

    return jsonify({
        'id': scan_run.id,
        'status': scan_run.status,
        'progress': scan_run.progress,
        'started_at': scan_run.started_at.isoformat() if scan_run.started_at else None,
        'completed_at': scan_run.completed_at.isoformat() if scan_run.completed_at else None
    })

@tasks_bp.route('/<int:run_id>/kill', methods=['POST'])
@login_required
def kill_task(run_id):
    # Get the scan run and verify ownership
    scan_run = ScanRun.query.join(ScanTask).filter(
        ScanRun.id == run_id,
        ScanTask.user_id == current_user.id
    ).first_or_404()

    # Check if the task is actually running
    if scan_run.status not in ['queued', 'running']:
        flash('This task is not running.', 'warning')
        return redirect(url_for('tasks.view', id=scan_run.task_id))

    # If the task has a Celery task ID, revoke it
    if scan_run.celery_task_id:
        try:
            celery.control.revoke(scan_run.celery_task_id, terminate=True, signal='SIGKILL')
        except Exception as e:
            print(f"Error revoking Celery task: {str(e)}")

    # If the task has an Nmap PID, kill the process
    if scan_run.nmap_pid:
        try:
            # Try to kill the process
            import os
            import signal
            os.kill(scan_run.nmap_pid, signal.SIGKILL)
            print(f"Killed Nmap process with PID {scan_run.nmap_pid}")
        except ProcessLookupError:
            print(f"Process with PID {scan_run.nmap_pid} not found")
        except Exception as e:
            print(f"Error killing process: {str(e)}")

    # Update the scan run status
    scan_run.status = 'failed'
    scan_run.completed_at = datetime.utcnow()
    db.session.commit()

    flash('Task stopped successfully.', 'success')
    return redirect(url_for('tasks.view', id=scan_run.task_id))
    