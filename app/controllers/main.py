from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app.models.task import ScanTask, ScanRun
from app.models.target import TargetGroup
from app.models.report import ScanReport
from sqlalchemy import func
from datetime import datetime, timedelta

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def index():
    # Dashboard statistics
    stats = {
        'total_targets': TargetGroup.query.filter_by(user_id=current_user.id).count(),
        'total_tasks': ScanTask.query.filter_by(user_id=current_user.id).count(),
        'total_scans': ScanRun.query.join(ScanTask).filter(ScanTask.user_id == current_user.id).count(),
        'active_scans': ScanRun.query.join(ScanTask).filter(
            ScanTask.user_id == current_user.id,
            ScanRun.status.in_(['queued', 'running'])
        ).count()
    }
    
    # Recent scan runs - ordered by ID in descending order
    recent_runs = ScanRun.query.join(ScanTask).filter(
        ScanTask.user_id == current_user.id
    ).order_by(ScanRun.id.desc()).limit(5).all()
    
    # Upcoming scheduled scans
    scheduled_tasks = ScanTask.query.filter_by(
        user_id=current_user.id,
        is_scheduled=True
    ).all()
    
    # Get scan statistics for the last 7 days
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    # For SQLite, we need a different approach - get all runs and process in Python
    all_runs = ScanRun.query.join(ScanTask).filter(
        ScanTask.user_id == current_user.id
    ).all()
    
    # Process the data in Python to count by date
    date_counts = {}
    for run in all_runs:
        # Use created_at as our timestamp
        if run.created_at:
            # Extract just the date part as a string
            date_str = run.created_at.strftime('%Y-%m-%d')
            if date_str in date_counts:
                date_counts[date_str] += 1
            else:
                date_counts[date_str] = 1
    
    # Convert to the format expected by the chart
    daily_scans = [(date_str, count) for date_str, count in date_counts.items()]
    
    daily_scan_data = {
        'labels': [],
        'data': []
    }
    
    # Generate labels and data for the last 7 days
    for day in range(7):
        date_obj = (datetime.utcnow() - timedelta(days=6-day)).date()
        date_str = date_obj.strftime('%Y-%m-%d')
        daily_scan_data['labels'].append(date_str)
        
        # Find if we have data for this date
        count = 0
        for scan_date_str, scan_count in daily_scans:
            if scan_date_str == date_str:
                count = scan_count
                break
                
        daily_scan_data['data'].append(count)
        
    print(f"Chart data: {daily_scan_data}")
    print(f"All scan dates: {[date for date, _ in daily_scans]}")
    print(f"All scan counts: {[count for _, count in daily_scans]}")
    
    return render_template(
        'main/index.html',
        title='Dashboard',
        stats=stats,
        recent_runs=recent_runs,
        scheduled_tasks=scheduled_tasks,
        daily_scan_data=daily_scan_data
    )

@main_bp.route('/profile')
@login_required
def profile():
    return render_template('main/profile.html', title='User Profile')
