from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from config import Config # Import Config
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.target import TargetGroup
from app.models.task import ScanTask, ScanRun
from app.models.settings import SystemSettings
from app.utils.forms import UserForm, SystemSettingsForm
from app.utils.decorators import admin_required
import psutil
import platform
from datetime import datetime
import os

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
@login_required
@admin_required
def index():
    # Gather user statistics
    stats = {
        'total_users': User.query.count()
    }
    
    # Get system settings
    settings = {
        'max_concurrent_tasks': SystemSettings.get_int('max_concurrent_tasks', 4),
        'max_reports_per_task': SystemSettings.get_int('max_reports_per_task', 15),
        'pagination_rows': SystemSettings.get_int('pagination_rows', 20)
    }
    
    # Get system information
    system_info = {
        # System uptime
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
        'uptime_seconds': int(datetime.now().timestamp() - psutil.boot_time()),
        
        # CPU information
        'cpu_count': psutil.cpu_count(logical=False),
        'cpu_threads': psutil.cpu_count(logical=True),
        'cpu_percent': psutil.cpu_percent(interval=1),
        'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else 'Unknown',
        
        # Memory information
        'total_memory': round(psutil.virtual_memory().total / (1024 * 1024 * 1024), 2),  # GB
        'available_memory': round(psutil.virtual_memory().available / (1024 * 1024 * 1024), 2),  # GB
        'memory_percent': psutil.virtual_memory().percent,
        
        # Disk information
        'disk_usage': psutil.disk_usage('/'),
        
        # Platform information
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'flask_version': getattr(current_app, 'version', 'Unknown')
    }
    
    # Format uptime as days, hours, minutes
    uptime_seconds = system_info['uptime_seconds']
    days, remainder = divmod(uptime_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    system_info['uptime_formatted'] = f"{days}d {hours}h {minutes}m {seconds}s"
    
    return render_template('admin/index.html', 
                          title='Admin Dashboard',
                          stats=stats,
                          settings=settings,
                          system_info=system_info)

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('admin/users.html', title='User Management', users=users)

@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    form = UserForm()
    
    if form.validate_on_submit():
        # Check if username or email already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'danger')
            return render_template('admin/create_user.html', title='Create User', form=form)
        
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists.', 'danger')
            return render_template('admin/create_user.html', title='Create User', form=form)
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            role=form.role.data,
            timezone=form.timezone.data
        )
        db.session.add(user)
        db.session.commit()
        
        flash('User created successfully!', 'success')
        return redirect(url_for('admin.users'))
    
    return render_template('admin/create_user.html', title='Create User', form=form)

@admin_bp.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    
    # Don't allow editing your own user through this interface
    if user.id == current_user.id:
        flash('You cannot edit your own user through this interface.', 'danger')
        return redirect(url_for('admin.users'))
    
    form = UserForm(obj=user)
    
    # Don't require password for editing
    form.password.validators = []
    
    if form.validate_on_submit():
        # Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user and existing_user.id != user.id:
            flash('Username already exists.', 'danger')
            return render_template('admin/edit_user.html', title='Edit User', form=form, user=user)
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user and existing_user.id != user.id:
            flash('Email already exists.', 'danger')
            return render_template('admin/edit_user.html', title='Edit User', form=form, user=user)
        
        # Update user
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.role.data
        user.active = form.active.data
        
        # Update password if provided
        if form.password.data:
            user.set_password(form.password.data)
        
        db.session.commit()
        
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin.users'))
    
    return render_template('admin/edit_user.html', title='Edit User', form=form, user=user)

@admin_bp.route('/users/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)
    
    # Don't allow deleting your own user
    if user.id == current_user.id:
        flash('You cannot delete your own user.', 'danger')
        return redirect(url_for('admin.users'))
    
    # Don't allow deleting the last admin
    if user.role == 'admin' and User.query.filter_by(role='admin').count() <= 1:
        flash('Cannot delete the last admin user.', 'danger')
        return redirect(url_for('admin.users'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def system_settings():
    """System settings page"""
    form = SystemSettingsForm()
    
    # Set initial values from database
    if request.method == 'GET':
        form.max_concurrent_tasks.data = SystemSettings.get_int('max_concurrent_tasks', 4)
        form.max_reports_per_task.data = SystemSettings.get_int('max_reports_per_task', 15)
        form.pagination_rows.data = SystemSettings.get_int('pagination_rows', 20)
    
    if form.validate_on_submit():
        # Save settings to database
        SystemSettings.set_setting('max_concurrent_tasks', form.max_concurrent_tasks.data, 
                                 'Maximum number of scan tasks that can run in parallel')
        SystemSettings.set_setting('max_reports_per_task', form.max_reports_per_task.data, 
                                 'Default maximum number of reports to keep for each task')
        SystemSettings.set_setting('pagination_rows', form.pagination_rows.data,
                                 'Default number of items to display per page in listings')
        
        flash('System settings updated successfully!', 'success')
        return redirect(url_for('admin.system_settings'))
    
    nmap_worker_pool_size = Config.NMAP_WORKER_POOL_SIZE
    return render_template('admin/settings.html', 
                          title='System Settings',
                          form=form,
                          nmap_worker_pool_size=nmap_worker_pool_size)
