#!/usr/bin/env python3
"""
NmapWebUI Flask Application Runner
-----------------------------------
This script runs the Flask web application for NmapWebUI.
"""
import os
from dotenv import load_dotenv
from app import create_app

# Load environment variables from .env file
load_dotenv()

if __name__ == '__main__':
    app = create_app()

    # Get the absolute path to the project directory
    base_dir = os.path.abspath(os.path.dirname(__file__))
    instance_dir = os.path.join(base_dir, 'instance')

    #print(os.environ.get('DATABASE_URL'))
    #exit()

    # Database URL should already be set in the .env file
    # Just print it for debugging
    print(os.environ.get('DATABASE_URL'))
    #exit()

    # Get host and port from environment variables or use defaults
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    print(f"Starting NmapWebUI on {host}:{port}...")
    app.run(host=host, port=port, debug=True)
