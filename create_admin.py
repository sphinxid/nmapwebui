#!/usr/bin/env python3
"""
Admin User Creation Script
-------------------------
This script creates an admin user for the NmapWebUI application.
It can run interactively or non-interactively via environment variables.
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
        admin_user_env = os.environ.get('ADMIN_USER')
        admin_email_env = os.environ.get('ADMIN_EMAIL')
        admin_password_env = os.environ.get('ADMIN_PASSWORD')

        if admin_user_env and admin_email_env and admin_password_env:
            # Non-interactive path
            print("Attempting non-interactive admin creation from environment variables...")

            username = admin_user_env
            email = admin_email_env
            password = admin_password_env

            if len(password) < 8:
                print("Error: ADMIN_PASSWORD must be at least 8 characters long.")
                return

            existing_user_by_username = User.query.filter_by(username=username).first()
            if existing_user_by_username:
                print(f"Admin user '{username}' already exists (from ADMIN_USER).")
                return

            existing_user_by_email = User.query.filter_by(email=email).first()
            if existing_user_by_email:
                # It's okay if the email belongs to the same user we are trying to create (though this check is redundant then)
                # The critical part is if the email is used by a *different* user.
                # However, since we check for username first and exit, if we reach here and existing_user_by_email exists,
                # it must be a different user.
                print(f"Email '{email}' (from ADMIN_EMAIL) is already in use by another user.")
                return
            
            # Create the admin user
            admin_user = User(
                username=username,
                email=email,
                password=password,  # Password will be hashed by the model's setter
                role='admin'
            )

            # Add to database
            db.session.add(admin_user)
            db.session.commit()

            print(f"Admin user '{username}' created successfully from environment variables!")
            print("You can now log in to the application with these credentials.")

        else:
            # Interactive path
            print("Environment variables for non-interactive admin creation not fully set. Proceeding with interactive mode.")

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
            existing_user_by_email = User.query.filter_by(email=email).first()
            if existing_user_by_email:
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
                password=password, # Password will be hashed by the model's setter
                role='admin'
            )
            
            # Add to database
            db.session.add(admin_user)
            db.session.commit()
            
            print(f"Admin user '{username}' created successfully!")
            print("You can now log in to the application with these credentials.")

if __name__ == '__main__':
    create_admin()
