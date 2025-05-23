from app import db
from datetime import datetime

class TargetGroup(db.Model):
    __tablename__ = 'target_groups'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    targets = db.relationship('Target', backref='group', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<TargetGroup {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'targets': [target.to_dict() for target in self.targets]
        }

class Target(db.Model):
    __tablename__ = 'targets'
    
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)  # 'ip', 'cidr', 'hostname'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    target_group_id = db.Column(db.Integer, db.ForeignKey('target_groups.id'), nullable=False)
    
    def __repr__(self):
        return f'<Target {self.value}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'value': self.value,
            'target_type': self.target_type,
            'created_at': self.created_at
        }

# Association table for many-to-many relationship between ScanTask and TargetGroup
task_target_groups = db.Table('task_target_groups',
    db.Column('task_id', db.Integer, db.ForeignKey('scan_tasks.id'), primary_key=True),
    db.Column('target_group_id', db.Integer, db.ForeignKey('target_groups.id'), primary_key=True)
)
