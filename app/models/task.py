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
    celery_task_id = db.Column(db.String(64), nullable=True)
    nmap_pid = db.Column(db.Integer, nullable=True)  # PID of the nmap process
    
    # Relationships
    report = db.relationship('ScanReport', backref='scan_run', uselist=False, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<ScanRun {self.id} for Task {self.task_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'status': self.status,
            'progress': self.progress,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'celery_task_id': self.celery_task_id,
            'nmap_pid': self.nmap_pid
        }
