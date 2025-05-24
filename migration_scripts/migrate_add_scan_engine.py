#!/usr/bin/env python3
"""
Migration script to add the scan_engine column to the scan_tasks table
"""
import sys
import os
import sqlite3

# Add the parent directory to the path so we can import from app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.task import ScanTask
from sqlalchemy import text

def migrate_scan_engine():
    """
    Add the scan_engine column to the scan_tasks table and populate it based on existing data
    """
    app = create_app()
    
    with app.app_context():
        print("Starting migration to add scan_engine column to scan_tasks table...")
        
        # Check if the column already exists
        try:
            # Try to query the column to see if it exists
            db.session.query(ScanTask.scan_engine).first()
            print("Column scan_engine already exists. Migration not needed.")
            return
        except Exception as e:
            if "no such column" not in str(e).lower():
                print(f"Unexpected error checking column: {e}")
                return
            print("Column scan_engine does not exist. Proceeding with migration...")
        
        # Get the database URI from the app config
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        
        if 'sqlite' in db_uri:
            # For SQLite, we need to use ALTER TABLE directly
            try:
                # Extract the database path from the URI
                db_path = db_uri.replace('sqlite:///', '')
                
                # Connect to the database
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Add the column
                cursor.execute("ALTER TABLE scan_tasks ADD COLUMN scan_engine VARCHAR(20) DEFAULT 'nmap'")
                conn.commit()
                
                # Update existing records based on scan_profile
                cursor.execute("""
                    UPDATE scan_tasks 
                    SET scan_engine = 'masscan' 
                    WHERE scan_profile IS NULL
                """)
                conn.commit()
                
                # Close the connection
                conn.close()
                
                print("Migration completed successfully for SQLite database.")
            except Exception as e:
                print(f"Error during SQLite migration: {e}")
                return
        else:
            # For other databases, we can use SQLAlchemy
            try:
                # Add the column with a default value
                db.engine.execute(text("ALTER TABLE scan_tasks ADD COLUMN scan_engine VARCHAR(20) DEFAULT 'nmap'"))
                
                # Update existing records based on scan_profile
                db.engine.execute(text("""
                    UPDATE scan_tasks 
                    SET scan_engine = 'masscan' 
                    WHERE scan_profile IS NULL
                """))
                
                print("Migration completed successfully for database.")
            except Exception as e:
                print(f"Error during database migration: {e}")
                return
        
        print("Migration completed. All scan tasks now have a scan_engine value.")

if __name__ == "__main__":
    migrate_scan_engine()
