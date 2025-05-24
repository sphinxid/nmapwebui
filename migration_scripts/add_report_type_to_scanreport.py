#!/usr/bin/env python3
"""
Migration script to add the 'report_type' column to the ScanReport model.
This script should be run after updating the model in report.py.
"""
import os
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def migrate():
    """Add the report_type column to the scan_reports table."""
    from app import create_app, db
    from sqlalchemy import Column, String
    from sqlalchemy.sql import text
    
    app = create_app()
    
    with app.app_context():
        # Check if the column already exists
        conn = db.engine.connect()
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('scan_reports')]
        
        if 'report_type' not in columns:
            print("Adding 'report_type' column to scan_reports table...")
            
            # Add the column
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN report_type VARCHAR(20) DEFAULT 'nmap';"))
            
            # Commit the changes
            db.session.commit()
            
            print("Migration completed successfully!")
        else:
            print("The 'report_type' column already exists in the scan_reports table.")

if __name__ == '__main__':
    migrate()
