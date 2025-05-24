#!/usr/bin/env python3
"""
Script to update all Masscan hosts with open ports to have a status of 'up'
"""
import os
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.report import ScanReport, HostFinding, PortFinding
from sqlalchemy import func

app = create_app()

with app.app_context():
    # Find all hosts in Masscan reports that have open ports but status is not 'up'
    hosts_to_update = db.session.query(HostFinding).join(
        ScanReport, HostFinding.report_id == ScanReport.id
    ).join(
        PortFinding, HostFinding.id == PortFinding.host_id
    ).filter(
        ScanReport.report_type == 'masscan',
        PortFinding.state == 'open',
        HostFinding.status != 'up'
    ).distinct().all()
    
    count = len(hosts_to_update)
    print(f"Found {count} Masscan hosts with open ports that need to be updated to 'up' status")
    
    # Update all hosts to 'up'
    for host in hosts_to_update:
        print(f"Updating host {host.ip_address} (ID: {host.id}) from status '{host.status}' to 'up'")
        host.status = 'up'
    
    # Commit the changes
    db.session.commit()
    print(f"Successfully updated {count} hosts to 'up' status")
