#!/usr/bin/env python3
"""
NmapWebUI Flask Application - Production WSGI Entry Point
--------------------------------------------------------
This script serves as the WSGI entry point for running the NmapWebUI application
in a production environment with Gunicorn or uWSGI.

Usage with Gunicorn:
$ gunicorn -w 4 -b 0.0.0.0:5000 run_app_production:app

Usage with uWSGI:
$ uwsgi --http 0.0.0.0:5000 --module run_app_production:app --processes 4 --threads 2

For systemd service:
ExecStart=/path/to/gunicorn -w 4 -b 0.0.0.0:5000 run_app_production:app
"""
import os
from dotenv import load_dotenv
from app import create_app

# Load environment variables from .env file
load_dotenv()

# Create the Flask application - this is the WSGI entry point
app = create_app()

# This block only runs when the script is executed directly (not imported)
if __name__ == '__main__':
    # Get host and port from environment variables or use defaults
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    print(f"Starting NmapWebUI in production mode on {host}:{port}...")
    # In production, we should never run with debug=True
    app.run(host=host, port=port, debug=False)
