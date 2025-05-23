from app import db
from datetime import datetime

class ScanReport(db.Model):
    __tablename__ = 'scan_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_run_id = db.Column(db.Integer, db.ForeignKey('scan_runs.id'), nullable=False)
    summary = db.Column(db.Text, nullable=True)  # JSON summary data
    xml_report_path = db.Column(db.String(255), nullable=True)  # Path to XML report file
    normal_report_path = db.Column(db.String(255), nullable=True)  # Path to normal output report file
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Host findings
    hosts = db.relationship('HostFinding', backref='report', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<ScanReport {self.id} for ScanRun {self.scan_run_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_run_id': self.scan_run_id,
            'summary': self.summary,
            'xml_report_path': self.xml_report_path,
            'normal_report_path': self.normal_report_path,
            'created_at': self.created_at,
            'hosts': [host.to_dict() for host in self.hosts]
        }

class HostFinding(db.Model):
    __tablename__ = 'host_findings'
    
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('scan_reports.id'), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    hostname = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # 'up' or 'down'
    os_info = db.Column(db.Text, nullable=True)  # OS detection info (JSON)
    
    # Port findings
    ports = db.relationship('PortFinding', backref='host', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<HostFinding {self.ip_address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'report_id': self.report_id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'status': self.status,
            'os_info': self.os_info,
            'ports': [port.to_dict() for port in self.ports]
        }

class PortFinding(db.Model):
    __tablename__ = 'port_findings'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host_findings.id'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # 'tcp', 'udp'
    state = db.Column(db.String(20), nullable=False)  # 'open', 'closed', 'filtered'
    service = db.Column(db.String(64), nullable=True)
    version = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f'<PortFinding {self.port_number}/{self.protocol}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'port_number': self.port_number,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service,
            'version': self.version
        }
