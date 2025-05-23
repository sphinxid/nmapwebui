#!/usr/bin/env python3
"""
Admin User Creation Script
-------------------------
This script creates an admin user for the NmapWebUI application.
"""
import os
import sys
import getpass
from dotenv import load_dotenv
from app import create_app, db
from app.models.user import User

# Load environment variables from .env file
load_dotenv()

def create_admin():
    """Create an admin user with the provided credentials."""
    print("NmapWebUI Admin User Creation")
    print("-" * 30)
    
    # Create the Flask application context
    app = create_app()
    
    with app.app_context():
        # Check if any admin user already exists
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            print(f"An admin user already exists: {existing_admin.username}")
            create_another = input("Do you want to create another admin user? (y/n): ")
            if create_another.lower() != 'y':
                print("Admin user creation cancelled.")
                return
        
        # Get admin user details
        username = input("Enter admin username: ")
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            print(f"Error: Username '{username}' already exists.")
            return
        
        email = input("Enter admin email: ")
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            print(f"Error: Email '{email}' already exists.")
            return
        
        # Get password securely (won't be displayed while typing)
        password = getpass.getpass("Enter admin password (min 8 characters): ")
        if len(password) < 8:
            print("Error: Password must be at least 8 characters long.")
            return
        
        confirm_password = getpass.getpass("Confirm admin password: ")
        if password != confirm_password:
            print("Error: Passwords do not match.")
            return
        
        # Create the admin user
        admin_user = User(
            username=username,
            email=email,
            password=password,
            role='admin'
        )
        
        # Add to database
        db.session.add(admin_user)
        db.session.commit()
        
        print(f"\nAdmin user '{username}' created successfully!")
        print("You can now log in to the application with these credentials.")

if __name__ == '__main__':
    create_admin()
