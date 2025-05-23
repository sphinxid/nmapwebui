import click
from flask.cli import with_appcontext
from app import db
from app.models.user import User
from app.models.target import TargetGroup, Target
from app.models.task import ScanTask
from app.tasks.scheduler_tasks import initialize_scheduled_tasks

def register_commands(app):
    """Register custom Flask CLI commands"""
    
    @app.cli.command('init-db')
    @with_appcontext
    def init_db():
        """Initialize the database."""
        # Ensure the instance directory exists
        import os
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance')
        os.makedirs(db_path, exist_ok=True)
        
        # Create all tables
        db.create_all()
        click.echo('Initialized the database.')
        click.echo(f'Database path: {app.config["SQLALCHEMY_DATABASE_URI"]}')
        
        # Check if any users exist
        if User.query.count() == 0:
            click.echo('No users found. You can create an admin user with the create-admin command.')
            click.echo('Example: flask create-admin --username admin --email admin@example.com')
    
    @app.cli.command('create-admin')
    @click.option('--username', default='admin', help='Admin username')
    @click.option('--email', default='admin@example.com', help='Admin email')
    @click.option('--password', help='Admin password')
    @with_appcontext
    def create_admin(username, email, password):
        """Create an admin user."""
        if not password:
            password = click.prompt('Enter admin password', hide_input=True, confirmation_prompt=True)
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            click.echo(f'User {username} already exists.')
            return
        
        user = User(username=username, email=email, password=password, role='admin')
        db.session.add(user)
        db.session.commit()
        click.echo(f'Admin user {username} created successfully.')
    
    @app.cli.command('init-scheduler')
    @with_appcontext
    def init_scheduler():
        """Initialize the task scheduler."""
        initialize_scheduled_tasks()
        click.echo('Task scheduler initialized.')
    
    @app.cli.command('create-demo-data')
    @with_appcontext
    def create_demo_data():
        """Create demo data for testing."""
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@example.com', password='password', role='admin')
            db.session.add(admin)
            db.session.commit()
            click.echo('Created admin user.')
        
        # Create a regular user
        user = User.query.filter_by(username='user').first()
        if not user:
            user = User(username='user', email='user@example.com', password='password', role='user')
            db.session.add(user)
            db.session.commit()
            click.echo('Created regular user.')
        
        # Create target groups
        if TargetGroup.query.count() == 0:
            # Create target groups for admin
            local_network = TargetGroup(name='Local Network', description='Local network targets', user_id=admin.id)
            db.session.add(local_network)
            
            # Add targets to local network group
            targets = [
                ('127.0.0.1', 'ip'),
                ('localhost', 'hostname'),
                ('192.168.1.0/24', 'cidr')
            ]
            
            for value, target_type in targets:
                target = Target(value=value, target_type=target_type, target_group_id=local_network.id)
                db.session.add(target)
            
            # Create target groups for regular user
            web_servers = TargetGroup(name='Web Servers', description='Web server targets', user_id=user.id)
            db.session.add(web_servers)
            
            # Add targets to web servers group
            targets = [
                ('example.com', 'hostname'),
                ('google.com', 'hostname')
            ]
            
            for value, target_type in targets:
                target = Target(value=value, target_type=target_type, target_group_id=web_servers.id)
                db.session.add(target)
            
            db.session.commit()
            click.echo('Created target groups with targets.')
        
        # Create scan tasks
        if ScanTask.query.count() == 0:
            # Create scan task for admin
            local_network = TargetGroup.query.filter_by(name='Local Network').first()
            if local_network:
                quick_scan = ScanTask(
                    name='Quick Local Scan',
                    description='Quick scan of local network',
                    scan_profile='quick_scan',
                    user_id=admin.id
                )
                quick_scan.target_groups.append(local_network)
                db.session.add(quick_scan)
            
            # Create scan task for regular user
            web_servers = TargetGroup.query.filter_by(name='Web Servers').first()
            if web_servers:
                port_scan = ScanTask(
                    name='Web Server Port Scan',
                    description='Port scan of web servers',
                    scan_profile='port_scan',
                    user_id=user.id
                )
                port_scan.target_groups.append(web_servers)
                db.session.add(port_scan)
            
            db.session.commit()
            click.echo('Created scan tasks.')
        
        click.echo('Demo data creation completed.')
