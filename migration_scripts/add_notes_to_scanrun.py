#!/usr/bin/env python3
"""
Migration script to add the 'notes' column to the ScanRun model.
This script should be run after updating the model in task.py.
"""
import os
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def migrate():
    """Add the notes column to the scan_runs table."""
    from app import create_app, db
    from sqlalchemy import Column, Text
    from sqlalchemy.sql import text
    
    app = create_app()
    
    with app.app_context():
        # Check if the column already exists
        conn = db.engine.connect()
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('scan_runs')]
        
        if 'notes' not in columns:
            print("Adding 'notes' column to scan_runs table...")
            
            # Add the column
            conn.execute(text("ALTER TABLE scan_runs ADD COLUMN notes TEXT;"))
            
            # Commit the changes
            db.session.commit()
            
            print("Migration completed successfully!")
        else:
            print("The 'notes' column already exists in the scan_runs table.")

if __name__ == '__main__':
    migrate()
