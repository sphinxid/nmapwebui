#!/bin/sh
set -e

# Change to the /app directory (this is already the WORKDIR, but good for explicitness)
cd /app

# Run database migrations (as appuser, which this script will be)
echo "Running database migrations..."
flask db upgrade

# Create admin user (as appuser)
echo "Creating admin user..."
python create_admin.py

# Execute the command passed as arguments to the script (e.g., supervisord)
echo "Executing CMD: $@"
exec "$@"
