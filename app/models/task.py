from app import db
from datetime import datetime
import json
from app.models.settings import SystemSettings

class ScanTask(db.Model):
    __tablename__ = 'scan_tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=True)
    scan_profile = db.Column(db.String(64), nullable=True)  # Predefined profile name
    custom_args = db.Column(db.Text, nullable=True)  # Custom Nmap arguments
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Schedule information
    is_scheduled = db.Column(db.Boolean, default=False)
    schedule_type = db.Column(db.String(20), nullable=True)  # 'daily', 'weekly', 'monthly'
    schedule_data = db.Column(db.Text, nullable=True)  # JSON data with schedule details
    
    # Report settings
    use_global_max_reports = db.Column(db.Boolean, default=True)  # Whether to use global setting or task-specific
    max_reports = db.Column(db.Integer, nullable=True)  # Max reports to keep, null means use global setting
    
    # Relationships
    target_groups = db.relationship('TargetGroup', secondary='task_target_groups', backref=db.backref('scan_tasks', lazy='dynamic'))
    scan_runs = db.relationship('ScanRun', backref='task', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<ScanTask {self.name}>'
    
    def get_schedule_data(self):
        if self.schedule_data:
            return json.loads(self.schedule_data)
        return {}
    
    def set_schedule_data(self, data):
        self.schedule_data = json.dumps(data)
    
    def get_schedule_display(self, timezone=None):
        """Format the schedule in a human-readable way
        
        Args:
            timezone: The timezone to use for displaying times (optional)
            
        Returns:
            A string describing the schedule in a human-readable format
        """
        if not self.is_scheduled or not self.schedule_type:
            return "Not scheduled"
            
        schedule_data = self.get_schedule_data()
        
        if self.schedule_type == 'daily':
            hour = schedule_data.get('hour', 0)
            minute = schedule_data.get('minute', 0)
            time_str = f"{int(hour):02d}:{int(minute):02d}"
            return f"Daily at {time_str}"
            
        elif self.schedule_type == 'weekly':
            hour = schedule_data.get('hour', 0)
            minute = schedule_data.get('minute', 0)
            time_str = f"{int(hour):02d}:{int(minute):02d}"
            day_of_week = schedule_data.get('day_of_week', 0)  # 0 = Monday in most systems
            days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            day_name = days[int(day_of_week) % 7]  # Ensure it's within range
            return f"Weekly on {day_name} at {time_str}"
            
        elif self.schedule_type == 'monthly':
            hour = schedule_data.get('hour', 0)
            minute = schedule_data.get('minute', 0)
            time_str = f"{int(hour):02d}:{int(minute):02d}"
            day_of_month = schedule_data.get('day_of_month', 1)
            day_of_month = int(day_of_month) # Ensure it's an integer for comparison
            # Handle special cases like 1st, 2nd, 3rd, etc.
            if day_of_month in [1, 21, 31]:
                suffix = 'st'
            elif day_of_month in [2, 22]:
                suffix = 'nd'
            elif day_of_month in [3, 23]:
                suffix = 'rd'
            else:
                suffix = 'th'
            return f"Monthly on the {day_of_month}{suffix} at {time_str}"
            
        else:
            # For any custom or unknown schedule types
            return f"{self.schedule_type.capitalize()} schedule"
        
    def get_max_reports(self):
        """Get the maximum number of reports to keep for this task"""
        if self.use_global_max_reports or self.max_reports is None:
            return SystemSettings.get_int('max_reports_per_task', 15)
        return self.max_reports
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'scan_profile': self.scan_profile,
            'custom_args': self.custom_args,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'is_scheduled': self.is_scheduled,
            'schedule_type': self.schedule_type,
            'schedule_data': self.get_schedule_data(),
            'use_global_max_reports': self.use_global_max_reports,
            'max_reports': self.get_max_reports(),
            'target_groups': [tg.id for tg in self.target_groups]
        }

class ScanRun(db.Model):
    __tablename__ = 'scan_runs'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.id'), nullable=False)
    status = db.Column(db.String(20), default='queued')  # 'queued', 'running', 'completed', 'failed'
    progress = db.Column(db.Integer, default=0)  # 0-100 percentage
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # When the scan run was created
    started_at = db.Column(db.DateTime, default=datetime.utcnow)  # When the scan run started or is scheduled to start
    completed_at = db.Column(db.DateTime, nullable=True)  # When the scan run completed
    nmap_pid = db.Column(db.Integer, nullable=True)  # PID of the nmap process
    error_message = db.Column(db.Text, nullable=True) # To store detailed error messages
    
    # Relationships
    report = db.relationship('ScanReport', backref='scan_run', uselist=False, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<ScanRun {self.id} for Task {self.task_id}>'
    
    def duration_human_readable(self):
        """Return a human-readable string representing the scan duration"""
        if not self.started_at or not self.completed_at:
            return "N/A"
            
        # Calculate duration in seconds
        duration_seconds = (self.completed_at - self.started_at).total_seconds()
        
        # Format duration
        hours, remainder = divmod(int(duration_seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def get_report_id(self):
        """Return the ID of the associated report, if any"""
        if self.report:
            return self.report.id
        return None
        
    def to_dict(self):
        report_id = self.get_report_id()
        return {
            'id': self.id,
            'task_id': self.task_id,
            'status': self.status,
            'progress': self.progress,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'nmap_pid': self.nmap_pid,
            'error_message': self.error_message,
            'report_id': report_id
        }


class TaskLock(db.Model):
    __tablename__ = 'task_locks'

    lock_key = db.Column(db.String(255), primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<TaskLock {self.lock_key}>'

