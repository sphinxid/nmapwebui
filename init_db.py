#!/usr/bin/env python3
"""
Database Initialization Script
------------------------------
This script initializes the database for the NmapWebUI application.
It creates the necessary tables and sets up the initial structure.
"""
import os
from dotenv import load_dotenv
from app import create_app, db
from app.models.user import User
from app.models.target import TargetGroup, Target
from app.models.task import ScanTask, ScanRun
from app.models.report import ScanReport, HostFinding, PortFinding
from app.models.settings import SystemSettings

def init_db():
    """Initialize the database with the required tables."""
    print("Initializing database...")

    # Load environment variables from .env file
    load_dotenv()

    # Create the Flask application context
    app = create_app()
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Initialize system settings with default values if they don't exist
        if SystemSettings.get_setting('max_concurrent_tasks') is None:
            SystemSettings.set_setting('max_concurrent_tasks', 4, 
                                     'Maximum number of scan tasks that can run in parallel')
        
        if SystemSettings.get_setting('max_reports_per_task') is None:
            SystemSettings.set_setting('max_reports_per_task', 15, 
                                     'Default maximum number of reports to keep for each task')
        
        if SystemSettings.get_setting('pagination_rows') is None:
            SystemSettings.set_setting('pagination_rows', 20,
                                     'Default number of items to display per page in listings')
        
        print("Database initialization complete!")
        
        # Print database location
        db_path = app.config['SQLALCHEMY_DATABASE_URI']
        print(f"Database created at: {db_path}")

if __name__ == '__main__':
    init_db()
