#!/usr/bin/env python3
"""
Flask CLI Commands
-----------------
This module defines custom Flask CLI commands for the NmapWebUI application.
"""
import click
import getpass
from flask.cli import with_appcontext
from app import db
from app.models.user import User
from app.models.settings import SystemSettings

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Initialize the database with the required tables."""
    click.echo("Initializing database...")
    
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
    
    click.echo("Database initialization complete!")

@click.command('create-admin')
@with_appcontext
def create_admin_command():
    """Create an admin user with the provided credentials."""
    click.echo("NmapWebUI Admin User Creation")
    click.echo("-" * 30)
    
    # Check if any admin user already exists
    existing_admin = User.query.filter_by(role='admin').first()
    if existing_admin:
        click.echo(f"An admin user already exists: {existing_admin.username}")
        create_another = click.confirm("Do you want to create another admin user?")
        if not create_another:
            click.echo("Admin user creation cancelled.")
            return
    
    # Get admin user details
    username = click.prompt("Enter admin username")
    
    # Check if username already exists
    if User.query.filter_by(username=username).first():
        click.echo(f"Error: Username '{username}' already exists.")
        return
    
    email = click.prompt("Enter admin email")
    
    # Check if email already exists
    if User.query.filter_by(email=email).first():
        click.echo(f"Error: Email '{email}' already exists.")
        return
    
    # Get password securely (won't be displayed while typing)
    password = getpass.getpass("Enter admin password (min 8 characters): ")
    if len(password) < 8:
        click.echo("Error: Password must be at least 8 characters long.")
        return
    
    confirm_password = getpass.getpass("Confirm admin password: ")
    if password != confirm_password:
        click.echo("Error: Passwords do not match.")
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
    
    click.echo(f"\nAdmin user '{username}' created successfully!")
    click.echo("You can now log in to the application with these credentials.")

def register_commands(app):
    """Register CLI commands with the Flask application."""
    app.cli.add_command(init_db_command)
    app.cli.add_command(create_admin_command)
