# NmapWebUI

A web-based application that serves as a user-friendly wrapper for the Nmap network scanner. This application allows authenticated users to manage targets, define and execute Nmap scans, view scan reports, and schedule recurring scans.

## Features

- User Authentication & Authorization
- User Management (Admin only)
- Target Group Management
- Scan Task Creation & Configuration
- Asynchronous Background Scanning
- Task Listing & Management
- Scan Report Display
- Multiple Scan Runs & Report History
- Scheduled Scanning

## Prerequisites

- Python 3.8+
- Nmap installed on the system
- Redis server (for Celery task queue)
- (optional) Gunicorn or uWSGI for production deployment
- (optional) user running the celery worker have sudo without password for nmap command that require root privilege

## Installation

1. Clone the repository:
```
git clone <repository-url>
cd cekin
```

2. Create a virtual environment and activate it:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```
pip install -r requirements.txt
```

4. Set up environment variables:
```
cp .env.example .env
```
Edit the `.env` file and set your configuration values.

5. Initialize the database:
```
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

6. Create an admin user:
```
python create_admin.py
```

## Running the Application

1. Start the Redis server:
```
redis-server
```

2. Start the Celery worker:
```
python run_celery.py
```

3. Start the Celery beat scheduler (for scheduled scans):
```
python run_celery_beat.py
```

4. Run the Flask application:
```
python run_app.py
```

5. Access the application at the URL shown in the console (default: http://127.0.0.1:5000)

## Configuration

The application uses environment variables for configuration. You can set these in the `.env` file:

```
# Flask configuration
FLASK_APP=run_app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key

# Database configuration
DATABASE_URL=/path/to/your/database.db

# Celery configuration
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Nmap configuration
NMAP_REPORTS_DIR=instance/reports

# Server configuration
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
```

## License

[MIT License](LICENSE)
